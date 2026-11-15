/*
 * WireGuard implementation for ESP32 Arduino by Kenta Ida (fuga@fugafuga.org)
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "arduino-wireguard-pico-w.h"

#include <WiFi.h>
#include <lwip_wrap.h>  // LWIPMutex: arduino-pico's lwIP lock (see WireGuard::end())

#include <lwip/udp.h>
#include <lwip/netif.h>
#include <lwip/ip4_addr.h>
#include <lwip/inet.h>
#include <lwip/ip_addr.h>
#include <lwip/ip4_addr.h>

#include "wireguardif.h"
#include "wireguard-platform.h"
#include "wg_port_pico.h"

// wireguard.h has no extern "C" guard (unlike wireguardif.h), so its
// declarations get C++ name-mangled unless wrapped here -- wireguard.c
// itself is compiled as plain C, so the linker would otherwise look for a
// mangled symbol that only ever exists unmangled.
extern "C" {
#include "wireguard.h"  // wireguard_base64_decode(), WIREGUARD_SESSION_KEY_LEN
#include "crypto.h"     // crypto_zero(); no extern "C" guard either
}

// ---- Globals kept for backward-compat with the original library API ----
static struct netif wg_netif_instance;
static struct netif *wg_netif = &wg_netif_instance;
static struct netif *previous_default_netif = nullptr;
static uint8_t peer_index = WIREGUARDIF_INVALID_INDEX;

const struct netif* WireGuard::tunnelNetif() { return &wg_netif_instance; }

// Undoes netif_add(wg_netif): wireguardif_init() (run by netif_add()) starts
// wireguardif_tmr and allocates a UDP PCB and the device, none of which
// netif_remove() frees -- only wireguardif_shutdown() does, finding the
// device through wg_netif->state and then clearing it. Shutdown runs first,
// the order end() has always used. (The order would matter only for TCP over
// the tunnel: netif_remove() aborts TCP PCBs bound to the tunnel address, and
// the RST goes out through wireguardif_output(), which needs state. Nothing
// here uses TCP.) Caller holds the lwIP lock (see WireGuard::end()).
static void release_wg_netif() {
    wireguardif_shutdown(wg_netif);
    netif_remove(wg_netif);
}

static bool resolve_ipv4(const char *host_or_ip, ip4_addr_t *out) {
    if (host_or_ip == nullptr || out == nullptr) {
        return false;
    }

    // Fast path: literal IPv4.
    if (ip4addr_aton(host_or_ip, out)) {
        return true;
    }

    // Fallback: use Arduino WiFi resolver.
    IPAddress resolved;
    // WiFi.hostByName returns 1 on success (Arduino convention).
    if (WiFi.hostByName(host_or_ip, resolved) != 1) {
        return false;
    }

    IP4_ADDR(out, resolved[0], resolved[1], resolved[2], resolved[3]);
    return true;
}

bool WireGuard::begin(const IPAddress &localIP,
                     const char *privateKey,
                     const char *remotePeerAddress,
                     const char *remotePeerPublicKey,
                     uint16_t remotePeerPort,
                     const char *presharedKey) {
    // Historical behavior: route everything via WireGuard.
    const IPAddress allowedIP(0, 0, 0, 0);
    const IPAddress allowedMask(0, 0, 0, 0);
    return beginAdvanced(localIP, privateKey, remotePeerAddress, remotePeerPublicKey,
                         remotePeerPort, allowedIP, allowedMask, presharedKey);
}

bool WireGuard::beginAdvanced(const IPAddress &localIP,
                             const char *privateKey,
                             const char *remotePeerAddress,
                             const char *remotePeerPublicKey,
                             uint16_t remotePeerPort,
                             const IPAddress &allowedIP,
                             const IPAddress &allowedMask,
                             const char *presharedKey) {
    if (_is_initialized) {
        return true;
    }
    if (privateKey == nullptr || remotePeerAddress == nullptr || remotePeerPublicKey == nullptr) {
        return false;
    }

    log_d(TAG "initial parameters OK");

    // Initialize platform glue (timers, RNG, etc.).
    wireguard_platform_init();

    log_d(TAG "wireguard_platform_init OK");

    // Resolve endpoint.
    ip4_addr_t endpoint4;
    if (!resolve_ipv4(remotePeerAddress, &endpoint4)) {
        log_e(TAG "Failed to resolve endpoint '%s'", remotePeerAddress);
        return false;
    }
    // wireguardif_connect() (below) refuses an endpoint of 0.0.0.0 or a port
    // of 0 with ERR_ARG and leaves the peer inactive: no handshake is ever
    // sent, yet begin() used to report success. Refuse here instead, before
    // anything is allocated, so the caller sees a failure it can log.
    if (ip4_addr_isany_val(endpoint4) || remotePeerPort == 0) {
        log_e(TAG "Endpoint %u.%u.%u.%u:%u can't be connected to (address 0.0.0.0 or port 0)",
              ip4_addr1(&endpoint4), ip4_addr2(&endpoint4), ip4_addr3(&endpoint4),
              ip4_addr4(&endpoint4), (unsigned)remotePeerPort);
        return false;
    }

    // Prepare interface addresses.
    ip4_addr_t ipaddr;
    ip4_addr_t netmask;
    ip4_addr_t gateway;

    IP4_ADDR(&ipaddr, localIP[0], localIP[1], localIP[2], localIP[3]);

    const bool route_all = (allowedIP == IPAddress(0, 0, 0, 0)) && (allowedMask == IPAddress(0, 0, 0, 0));
    if (route_all) {
        // /32 - only the interface address is treated as local. Default route will be switched to WG.
        IP4_ADDR(&netmask, 255, 255, 255, 255);
    } else {
        // Use the allowed IP mask as the interface netmask to get proper routing without changing default netif.
        IP4_ADDR(&netmask, allowedMask[0], allowedMask[1], allowedMask[2], allowedMask[3]);
    }

    IP4_ADDR(&gateway, 0, 0, 0, 0);

    // Capture the current default netif (Wi-Fi) so we can bind UDP traffic there.
    previous_default_netif = netif_default;

    // Initialize lwIP netif.
    wg_netif->name[0] = 'w';
    wg_netif->name[1] = 'g';

    log_d(TAG "netif start");

    struct wireguardif_init_data wg_init;
    wg_init.private_key = privateKey;
    wg_init.listen_port = 0;

    log_i(TAG "Previous default netif: %p", previous_default_netif);
    log_i(TAG "WiFi STA netif: %p", tcpip_adapter_get_netif(TCPIP_ADAPTER_IF_STA));

    // Jeśli underlying_netif jest NULL, użyj poprzedniego:
    if (previous_default_netif == NULL) {
        log_e(TAG "No default netif!");
        return false;
    }
    wg_init.bind_netif = previous_default_netif;

    // Important: netif_add expects ip4_addr_t* in this Arduino-Pico (LWIP_IPV6=0) build.
    if (netif_add(wg_netif,
                  &ipaddr,
                  &netmask,
                  &gateway,
                  &wg_init,
                  &wireguardif_init,
                  &ip_input) == nullptr) {
        log_e(TAG "netif_add() failed");
        return false;
    }

    log_d(TAG "peer start");

    struct wireguardif_peer peer;
    memset(&peer, 0, sizeof(peer));

    // preshared_key (unlike public_key) is a pointer to already-decoded raw
    // bytes, not a base64 string -- wireguard_peer_init() memcpy()s it
    // synchronously inside wireguardif_add_peer() below, so this stack
    // buffer's lifetime only needs to outlive that one call.
    uint8_t presharedKeyBytes[WIREGUARD_SESSION_KEY_LEN];
    const uint8_t *presharedKeyPtr = nullptr;
    if (presharedKey != nullptr && presharedKey[0] != '\0') {
        size_t presharedKeyLen = sizeof(presharedKeyBytes);
        if (wireguard_base64_decode(presharedKey, presharedKeyBytes, &presharedKeyLen)
                && presharedKeyLen == sizeof(presharedKeyBytes)) {
            presharedKeyPtr = presharedKeyBytes;
        } else {
            log_e(TAG "Failed to decode preshared key (bad base64 or wrong length) -- "
                      "proceeding without one");
        }
    }

    peer.public_key = remotePeerPublicKey;
    peer.preshared_key = presharedKeyPtr;
    peer.allowed_ip = allowedIP;
    peer.allowed_mask = allowedMask;
    peer.endpoint_ip = endpoint4;
    peer.endport_port = remotePeerPort;
    // wireguardif_add_peer() (wireguardif.c) special-cases
    // WIREGUARDIF_KEEPALIVE_DEFAULT (0xFFFF) to mean "use the library's own
    // KEEPALIVE_TIMEOUT (10s)" -- any other value, including 0, is taken
    // literally as the interval, and should_send_keepalive() only fires when
    // that interval is > 0. The memset() above left this field at 0, which
    // is indistinguishable from a caller *explicitly* disabling keepalives --
    // nothing in this project ever decided that, it was just an unset field.
    // Net effect: once a session reached Connected, this device sent zero
    // outbound traffic until WireGuardModule's own 10s status poll (a local
    // peerUp() check, not real traffic) noticed the peer had gone down --
    // long enough for most home-router NAT UDP mappings to expire first.
    // Confirmed 2026-08-11: an overnight soak run against a real cloud
    // server saw 1% tunnel uptime with the one successful session lasting
    // ~133s total; explicitly opting into the library's own default here
    // is the fix.
    peer.keep_alive = WIREGUARDIF_KEEPALIVE_DEFAULT;

    err_t perr = wireguardif_add_peer(wg_netif, &peer, &peer_index);
    // add_peer copied the PSK (wireguard_peer_init's memcpy) or failed; either
    // way the decoded copy on this stack is done with.
    crypto_zero(presharedKeyBytes, sizeof(presharedKeyBytes));
    if (perr != ERR_OK) {
        log_e(TAG "wireguardif_add_peer() failed err=%d", (int)perr);
        // netif_add() above already listed wg_netif and started its timer.
        // _is_initialized stays false, so end() would skip it, and the next
        // begin() would netif_add() the still-listed netif again: lwIP's
        // LWIP_ASSERT("netif already added") -> panic("lwip"), a watchdog
        // reboot on every retry. add_peer fails with ERR_ARG for a server
        // public key that isn't 32 bytes of base64, which wgServerKey saves
        // with only a warning. The netif isn't up or default yet, so
        // releasing it is all there is to undo.
        LWIPMutex lock;
        release_wg_netif();
        peer_index = WIREGUARDIF_INVALID_INDEX;
        return false;
    }

    log_d(TAG "connecting...");

    // Bring up WireGuard.
    netif_set_up(wg_netif);
    // Its only other failure, an unknown peer_index, can't follow a
    // successful add_peer; logged in case that ever changes.
    err_t cerr = wireguardif_connect(wg_netif, peer_index);
    if (cerr != ERR_OK) {
        log_e(TAG "wireguardif_connect() failed err=%d -- no handshake will be sent", (int)cerr);
    }

    log_d(TAG "connected!...");

    // Route configuration.
    if (route_all) {
        netif_set_default(wg_netif);
    }

    _is_initialized = true;

    log_i(TAG "WireGuard initialized. local=%u.%u.%u.%u endpoint=%u.%u.%u.%u:%u allowed=%u.%u.%u.%u/%u.%u.%u.%u listen=%u",
          localIP[0], localIP[1], localIP[2], localIP[3],
          ip4_addr1(&endpoint4), ip4_addr2(&endpoint4), ip4_addr3(&endpoint4), ip4_addr4(&endpoint4), (unsigned)remotePeerPort,
          allowedIP[0], allowedIP[1], allowedIP[2], allowedIP[3],
          allowedMask[0], allowedMask[1], allowedMask[2], allowedMask[3],
          (unsigned)wg_init.listen_port);

    return true;
}

void WireGuard::end() {
    if (!_is_initialized) {
        return;
    }

    {
        // The whole teardown runs under the lwIP lock. wireguardif_tmr() and
        // wireguardif_network_rx() run in lwIP's own context, which on this
        // port is an IRQ that can interrupt this thread, and they read the
        // peer and device freed here. arduino-pico wraps netif_remove(),
        // udp_remove() and udp_disconnect() in this lock, but not
        // sys_untimeout() (which unlinks from the list sys_check_timeouts()
        // walks), mem_free() (lwIP's heap, which IRQ-side pbuf allocations
        // share; NO_SYS makes lwIP's own heap protection a no-op),
        // netif_set_default(), or the peer zeroing in remove_peer. Nothing
        // here does crypto, so the IRQ waits only briefly; the lock is
        // recursive, so the wrapped calls inside nest.
        LWIPMutex lock;
        wireguardif_remove_peer(wg_netif, peer_index);
        // wireguardif_init() (called from netif_add() in beginAdvanced())
        // allocates a UDP PCB and a wireguard_device via
        // udp_new()/mem_calloc(). Neither netif_remove() nor
        // wireguardif_remove_peer() frees them -- only wireguardif_shutdown()
        // does. Without it, every begin()/end() cycle leaked one UDP PCB; once
        // lwIP's pool was exhausted, every later udp_new() inside
        // wireguardif_init() returned NULL and begin() failed for the rest of
        // the uptime.
        release_wg_netif();

        if (previous_default_netif != nullptr) {
            netif_set_default(previous_default_netif);
        }
    }

    _is_initialized = false;
    peer_index = WIREGUARDIF_INVALID_INDEX;
}

bool WireGuard::peerUp(IPAddress* currentEndpointIp, uint16_t* currentEndpointPort) const {
    if (!_is_initialized) return false;
    if (wg_netif == nullptr || peer_index == WIREGUARDIF_INVALID_INDEX) return false;

    ip_addr_t ep_ip;
    u16_t ep_port = 0;

    err_t rc = wireguardif_peer_is_up(
        wg_netif,
        peer_index,
        (currentEndpointIp ? &ep_ip : nullptr),
        (currentEndpointPort ? &ep_port : nullptr)
    );
    if (rc != ERR_OK) return false;

    if (currentEndpointIp) {
        if (IP_IS_V4(&ep_ip)) {
            const ip4_addr_t* a = ip_2_ip4(&ep_ip);
            *currentEndpointIp = IPAddress(ip4_addr1(a), ip4_addr2(a), ip4_addr3(a), ip4_addr4(a));
        } else {
            *currentEndpointIp = IPAddress(0, 0, 0, 0);
        }
    }
    if (currentEndpointPort) *currentEndpointPort = (uint16_t)ep_port;

    return true;
}

bool WireGuard::kickHandshake(const IPAddress& probeIp, uint16_t probePort, uint32_t minIntervalMs) {
    if (!_is_initialized) return false;

    const uint32_t now = millis();
    if ((uint32_t)(now - _lastKickMs) < minIntervalMs) {
        return true; // rate-limited: already kicked recently
    }
    _lastKickMs = now;

    // Non-blocking trigger: one small UDP datagram to an AllowedIPs address.
    WiFiUDP udp;
    udp.begin(0); // ephemeral local port
    udp.beginPacket(probeIp, probePort);
    udp.write((uint8_t)0x00);
    udp.endPacket();
    udp.stop();

    return true;
}