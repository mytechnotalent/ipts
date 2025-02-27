/////////////////////////////////////////////////////////////////////
// Project: Raspberry Pi Pico TLS Client Common Library (Header)
// Author: Kevin Thomas
// E-Mail: ket189@pitt.edu
// Version: 1.0
// Date: 02/26/25
// Target Device: Raspberry Pi Pico W (RP2040)
// Clock Frequency: (Depends on your board, e.g., 125 MHz)
// Toolchain: CMake, pico-sdk, ARM-none-eabi-gcc
// License: Apache License 2.0
// Description: This header file declares the public API for the TLS 
//              client common library. It provides the data structure 
//              and function prototypes needed to establish a TLS 
//              connection using lwIP and altcp_tls.
/////////////////////////////////////////////////////////////////////

#ifndef TLS_COMMON_H
#define TLS_COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "lwip/altcp_tls.h"
#include "lwip/pbuf.h"
#include "lwip/dns.h"

/**
 * @brief Runs the TLS client test.
 *
 * This function creates the TLS configuration, performs DNS resolution,
 * opens a TLS connection to the server, sends an HTTP request, and waits until
 * the process is complete.
 *
 * @param cert Pointer to the certificate data (or NULL if not used).
 * @param cert_len Length of the certificate data.
 * @param server Server hostname.
 * @param request HTTP request string.
 * @param timeout Connection timeout in seconds.
 * @return true if the test passed, false otherwise.
 */
bool run_tls_client_test(const uint8_t *cert, size_t cert_len, const char *server, const char *request, int timeout);

#ifdef __cplusplus
}
#endif

#endif // TLS_COMMON_H