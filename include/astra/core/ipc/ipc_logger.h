#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// ipc_logger.h — M-03 logger declaration
// Include this in any M-03 file that needs to log.
// ─────────────────────────────────────────────────────────────────────────────
#include <astra/core/logger.h>

// Global logger for M-03 IPC Engine — writes to logs/ipc.log
ASTRA_DECLARE_LOGGER(g_logIpc);

// Convenience shorthand macros — saves typing g_logIpc every time
#define IPC_TRACE(msg) LOG_TRACE(g_logIpc, msg)
#define IPC_DEBUG(msg) LOG_DEBUG(g_logIpc, msg)
#define IPC_INFO(msg)  LOG_INFO(g_logIpc,  msg)
#define IPC_WARN(msg)  LOG_WARN(g_logIpc,  msg)
#define IPC_ERROR(msg) LOG_ERROR(g_logIpc, msg)
#define IPC_FATAL(msg) LOG_FATAL(g_logIpc, msg)
