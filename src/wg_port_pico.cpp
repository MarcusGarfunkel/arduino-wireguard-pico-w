#include "wg_port_pico.h"
#include "LogModule.h"

NOINIT static char deb_buffer[PRINTABLE_BUFFER_SIZE];

// Format using va_list
static void vdeb(const char *fmt, va_list ap) {
  // NOTE: This is not thread-safe / not multi-core safe.
  vsnprintf(deb_buffer, sizeof(deb_buffer), fmt, ap);
  Serial.print(deb_buffer);
}

// Convenience wrapper (printf-like)
void dbg(const char *format, ...) {
  va_list ap;
  va_start(ap, format);
  vdeb(format, ap);
  va_end(ap);
}

// lvl is always one of "V"/"D"/"I"/"W"/"E" -- the single char the log_v/
// log_d/log_i/log_w/log_e macros in wg_port_pico.h pass in.
static LogLevel wgLevelFromChar(const char *lvl) {
  switch (lvl[0]) {
    case 'V': return LogLevel::TRACE;
    case 'D': return LogLevel::DEBUG;
    case 'W': return LogLevel::WARN;
    case 'E': return LogLevel::ERROR;
    default:  return LogLevel::INFO; // 'I' and anything unexpected
  }
}

// Log function used by macros. Routed through this project's LogModule
// (COM4 + level-gated) instead of raw Serial (native USB-CDC, unconditional,
// no level gating) -- see project_wireguard_stage1_verification memory for
// why: this was the only reason the two reconnect-loop leak bugs found
// earlier this session were ever visible at all, via a live debugger, since
// nothing in this project's normal workflow has native USB-CDC attached.
void wg_logf_(const char *lvl, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(deb_buffer, sizeof(deb_buffer), fmt, ap);
  va_end(ap);

  LogModule::instance().log(wgLevelFromChar(lvl), "WireGuard", deb_buffer);
}