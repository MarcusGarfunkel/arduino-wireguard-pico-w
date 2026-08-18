/*
 * based on WireGuard implementation for ESP32 Arduino by Kenta Ida (fuga@fugafuga.org)
 * SPDX-License-Identifier: BSD-3-Clause
 * RP2040 port by Marcin Kielesinski (jaszczurtd@tlen.pl)
 */

#include <Arduino.h>
#include "wireguard-platform.h"

#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "crypto.h"          // for U64TO8_BIG / U32TO8_BIG
#include <sys/time.h>        // gettimeofday()

#include "pico/rand.h"
#include "wg_port_pico.h"    // log_d(), routed through this project's LogModule

static bool is_platform_initialized = false;

static void __attribute__((unused)) secure_bzero(void *p, size_t n) {
  volatile uint8_t *vp = (volatile uint8_t *)p;
  while (n--) *vp++ = 0;
}

void wireguard_platform_init() {
  if (is_platform_initialized) return;

  is_platform_initialized = true;
}

// Key-generation entropy. Previously read the RP2040 ring oscillator's
// "random bit" register directly, 32 times, with no whitening/debiasing --
// the Pico SDK's own documentation flags raw ROSC-bit sampling as having
// high auto-correlation when sampled this way (exactly this pattern).
// pico_rand's get_rand_32()/get_rand_64() (pico/rand.h) mix ROSC with the
// microsecond timer and a bus performance counter through a seeded 128-bit
// PRNG state, and are already part of the pico-sdk this build already links
// against -- no new dependency. Safe to call from any core/IRQ context per
// its own documented contract (may block a few microseconds on entropy).
void wireguard_random_bytes(void *bytes, size_t size) {
    uint8_t *p = (uint8_t *)bytes;

    while (size >= 8) {
        uint64_t r = get_rand_64();
        memcpy(p, &r, 8);
        p += 8;
        size -= 8;
    }

    if (size >= 4) {
        uint32_t r = get_rand_32();
        memcpy(p, &r, 4);
        p += 4;
        size -= 4;
    }

    if (size > 0) {
        uint32_t r = get_rand_32();
        memcpy(p, &r, size);
    }
}

uint32_t wireguard_sys_now() {
  // we use lwIP sys_now() instead of millis() for better synchro with lwIP
  extern uint32_t sys_now(void);
  return sys_now();
}

void wireguard_tai64n_now(uint8_t *output) {
  // TAI64N for Pico W: NTP time (time()) + monotonic nano
  struct timeval tv;
  gettimeofday(&tv, NULL);
  
  uint64_t seconds = 0x400000000000000aULL + (uint64_t)tv.tv_sec;
  uint32_t nanos = (uint32_t)tv.tv_usec * 1000U;
  
  // crypto.h
  U64TO8_BIG(output + 0, seconds);
  U32TO8_BIG(output + 8, nanos);
}

// ── DoS load heuristic ───────────────────────────────────────────────────
// Tracks handshake-initiation/response attempts (mac1-shaped packets,
// counted by wireguardif.c at the point the message type is recognized --
// before any expensive DH/AEAD work runs) in a sliding window. This
// activates the library's own mac2/cookie challenge once the rate exceeds
// WIREGUARD_LOAD_THRESHOLD attempts per WIREGUARD_LOAD_WINDOW_MS --
// previously wireguard_is_under_load() unconditionally returned false, so
// that mechanism was permanently dead code regardless of real traffic.
// Threshold picked well above normal operation (this port's own periodic
// re-handshake cadence is minutes, not seconds) but well below what would
// let a flood keep this platform's ~280-300ms-per-handshake compute cost
// saturated indefinitely.
#define WIREGUARD_LOAD_WINDOW_MS 1000u
#define WIREGUARD_LOAD_THRESHOLD 4u

static uint32_t load_window_start_ms = 0;
static uint32_t load_window_count = 0;
static bool     load_state_was_under_load = false;  // edge-detect only, for the log_d below

void wireguard_platform_note_handshake_attempt() {
  uint32_t now = wireguard_sys_now();
  if ((uint32_t)(now - load_window_start_ms) >= WIREGUARD_LOAD_WINDOW_MS) {
    load_window_start_ms = now;
    load_window_count = 0;
  }
  load_window_count++;
}

bool wireguard_is_under_load() {
  uint32_t now = wireguard_sys_now();
  bool under_load;
  if ((uint32_t)(now - load_window_start_ms) >= WIREGUARD_LOAD_WINDOW_MS) {
    // Window has aged out with no attempt recorded since -- not under load.
    under_load = false;
  } else {
    under_load = load_window_count > WIREGUARD_LOAD_THRESHOLD;
  }
  // Edge-triggered, not per-call, so this can't itself become a per-packet
  // log flood under real load -- exactly the failure mode this project has
  // hit before with this library's own logging (see the log_i->log_d commit
  // this fork already carries).
  if (under_load != load_state_was_under_load) {
    log_d(TAG "load state -> %s (count=%lu in window)", under_load ? "UNDER LOAD" : "normal",
          (unsigned long)load_window_count);
    load_state_was_under_load = under_load;
  }
  return under_load;
}
