/*
 * Based on WireGuard implementation for ESP32 Arduino by Kenta Ida (fuga@fugafuga.org)
 * SPDX-License-Identifier: BSD-3-Clause
 * Arduino / Pico W port: Marcin Kielesiński
 */
#pragma once

#include <Arduino.h>
#include <IPAddress.h>

struct netif;

class WireGuard {
private:
    bool _is_initialized = false;
    uint32_t _lastKickMs = 0;

public:
    /*
     * Backward-compatible API:
     * - Allowed IPs: 0.0.0.0/0 (route everything through the tunnel)
     * - Listen port: remotePeerPort
     * - presharedKey: optional, base64-encoded 32-byte PSK. nullptr/empty
     *   means no PSK (matches every prior caller's behavior unchanged).
     */
    bool begin(const IPAddress& localIP,
               const char* privateKey,
               const char* remotePeerAddress,
               const char* remotePeerPublicKey,
               uint16_t remotePeerPort,
               const char* presharedKey = nullptr);

    /*
     * Configurable API:
     * - allowedIp/allowedMask: what should be routed via WireGuard (e.g. 10.8.0.0/24)
     * - presharedKey: see begin() above.
     */
    bool beginAdvanced(const IPAddress& localIP,
                       const char* privateKey,
                       const char* remotePeerAddress,
                       const char* remotePeerPublicKey,
                       uint16_t remotePeerPort,
                       const IPAddress& allowedIp,
                       const IPAddress& allowedMask,
                       const char* presharedKey = nullptr);

    void end();

    bool is_initialized() const { return this->_is_initialized; }

    /*
     * Returns true while the peer holds a usable session keypair: one from a
     * handshake completed within the last REJECT_AFTER_TIME (180 s). It goes
     * false during an outage once the newest keypair is that old, so a caller
     * polling it notices a dead tunnel within about 180 s of the last
     * completed handshake.
     */
    bool peerUp(IPAddress* currentEndpointIp = nullptr, uint16_t* currentEndpointPort = nullptr) const;

    /*
     * Sends a 1-byte UDP datagram to probeIp:probePort. Despite the name it
     * can't start a handshake: before one completes the wg netif's link is
     * down, so the datagram never enters the tunnel, and
     * wireguardif_output_to_peer() with no keypair doesn't initiate anyway.
     * The library's own timer (wireguardif_tmr) drives handshakes. Kept for
     * API compatibility; MezMirage no longer calls it. Rate-limited.
     */
    bool kickHandshake(const IPAddress& probeIp, uint16_t probePort, uint32_t minIntervalMs = 250);

    /*
     * The tunnel's lwIP netif. Its address never changes (one static
     * instance, re-added by every begin()), so a UDP receive callback can
     * compare ip_current_input_netif() against it, without a lock, to accept
     * only packets that came out of the tunnel: decrypted packets enter lwIP
     * through ip_input() on this netif, while a packet that merely carries a
     * tunnel source address arrives on the WiFi netif.
     */
    static const struct netif* tunnelNetif();
};
