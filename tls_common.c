/////////////////////////////////////////////////////////////////////
// Project: Raspberry Pi Pico TLS Client Common Library
// Author: Kevin Thomas
// E-Mail: ket189@pitt.edu
// Version: 1.0
// Date: 02/26/25
// Target Device: Raspberry Pi Pico W (RP2040)
// Clock Frequency: (Depends on your board, e.g., 125 MHz)
// Toolchain: CMake, pico-sdk, ARM-none-eabi-gcc
// License: Apache License 2.0
// Description: This source file implements the TLS client common 
//              library functions. It provides functionality for TLS 
//              connection establishment, DNS resolution, data 
//              reception, error handling, and cleanup using lwIP and 
//              altcp_tls. All code is unmodified from the original
//              working implementation.
/////////////////////////////////////////////////////////////////////

 #include <string.h>
 #include <time.h>
 #include <assert.h>
 #include "pico/stdlib.h"
 #include "pico/cyw43_arch.h"
 #include "lwip/pbuf.h"
 #include "lwip/altcp_tcp.h"
 #include "lwip/altcp_tls.h"
 #include "lwip/dns.h"
 
 /**
  * @brief Internal TLS client state structure.
  */
 typedef struct TLS_CLIENT_T_ {
     struct altcp_pcb *pcb;
     bool complete;
     int error;
     const char *http_request;
     int timeout;
 } TLS_CLIENT_T;
 
 /** Global TLS configuration pointer */
 static struct altcp_tls_config *tls_config = NULL;
 
 /**
  * @brief Closes the TLS client connection and frees resources.
  *
  * This function resets callbacks, closes the TLS connection, and 
  * marks the state as complete.
  *
  * @param arg Pointer to the TLS client state.
  * @return LWIP error code.
  */
 static err_t tls_client_close(void *arg) {
     TLS_CLIENT_T *state = (TLS_CLIENT_T*)arg;
     err_t err = ERR_OK;
 
     state->complete = true;
     if (state->pcb != NULL) {
         altcp_arg(state->pcb, NULL);
         altcp_poll(state->pcb, NULL, 0);
         altcp_recv(state->pcb, NULL);
         altcp_err(state->pcb, NULL);
         err = altcp_close(state->pcb);
         if (err != ERR_OK) {
             printf("close failed %d, calling abort\n", err);
             altcp_abort(state->pcb);
             err = ERR_ABRT;
         }
         state->pcb = NULL;
     }
     return err;
 }
 
 /**
  * @brief Callback invoked when the TLS connection is established.
  *
  * Upon a successful connection, this function sends the HTTP 
  * request.
  *
  * @param arg Pointer to the TLS client state.
  * @param pcb Pointer to the LWIP connection control block.
  * @param err Connection error code.
  * @return LWIP error code.
  */
 static err_t tls_client_connected(void *arg, struct altcp_pcb *pcb, err_t err) {
     TLS_CLIENT_T *state = (TLS_CLIENT_T*)arg;
     if (err != ERR_OK) {
         printf("connect failed %d\n", err);
         return tls_client_close(state);
     }
 
     printf("connected to server, sending request\n");
     err = altcp_write(state->pcb, state->http_request, strlen(state->http_request), TCP_WRITE_FLAG_COPY);
     if (err != ERR_OK) {
         printf("error writing data, err=%d", err);
         return tls_client_close(state);
     }
 
     return ERR_OK;
 }
 
 /**
  * @brief Polling callback for handling connection timeouts.
  *
  * @param arg Pointer to the TLS client state.
  * @param pcb Pointer to the LWIP connection control block.
  * @return LWIP error code.
  */
 static err_t tls_client_poll(void *arg, struct altcp_pcb *pcb) {
     TLS_CLIENT_T *state = (TLS_CLIENT_T*)arg;
     printf("timed out\n");
     state->error = PICO_ERROR_TIMEOUT;
     return tls_client_close(arg);
 }
 
 /**
  * @brief Error handler callback for TLS connection errors.
  *
  * This function is called when a TLS error occurs.
  *
  * @param arg Pointer to the TLS client state.
  * @param err TLS error code.
  */
 static void tls_client_err(void *arg, err_t err) {
     TLS_CLIENT_T *state = (TLS_CLIENT_T*)arg;
     printf("tls_client_err %d\n", err);
     tls_client_close(state);
     state->error = PICO_ERROR_GENERIC;
 }
 
 /**
  * @brief Data reception callback for the TLS connection.
  *
  * Received data is copied to a temporary buffer and printed.
  *
  * @param arg Pointer to the TLS client state.
  * @param pcb Pointer to the LWIP connection control block.
  * @param p Packet buffer with the received data.
  * @param err LWIP error code.
  * @return LWIP error code.
  */
 static err_t tls_client_recv(void *arg, struct altcp_pcb *pcb, struct pbuf *p, err_t err) {
     TLS_CLIENT_T *state = (TLS_CLIENT_T*)arg;
     if (!p) {
         printf("connection closed\n");
         return tls_client_close(state);
     }
 
     if (p->tot_len > 0) {
         /* For simplicity, a buffer on stack is allocated to hold the received data.
            Note: TLS records can be large (up to 16 KB) so in production code you may need to handle this differently. */
         char buf[p->tot_len + 1];
 
         pbuf_copy_partial(p, buf, p->tot_len, 0);
         buf[p->tot_len] = 0;
 
         printf("***\nnew data received from server:\n***\n\n%s\n", buf);
 
         altcp_recved(pcb, p->tot_len);
     }
     pbuf_free(p);
 
     return ERR_OK;
 }
 
 /**
  * @brief Initializes the TLS client state.
  *
  * Allocates memory for a TLS_CLIENT_T structure.
  *
  * @return Pointer to the allocated TLS_CLIENT_T or NULL on failure.
  */
 static TLS_CLIENT_T* tls_client_init(void) {
     TLS_CLIENT_T *state = calloc(1, sizeof(TLS_CLIENT_T));
     if (!state) {
         printf("failed to allocate state\n");
         return NULL;
     }
 
     return state;
 }
 
 /**
  * @brief Connects the TLS client to the server using a resolved IP address.
  *
  * Initiates a connection to the server on port 443.
  *
  * @param ipaddr Pointer to the server's IP address.
  * @param state Pointer to the TLS client state.
  */
 static void tls_client_connect_to_server_ip(const ip_addr_t *ipaddr, TLS_CLIENT_T *state)
 {
     err_t err;
     u16_t port = 443;
 
     printf("connecting to server IP %s port %d\n", ipaddr_ntoa(ipaddr), port);
     err = altcp_connect(state->pcb, ipaddr, port, tls_client_connected);
     if (err != ERR_OK)
     {
         fprintf(stderr, "error initiating connect, err=%d\n", err);
         tls_client_close(state);
     }
 }
 
 /**
  * @brief DNS resolution callback.
  *
  * Called when DNS resolution completes. On success, it connects to the server.
  *
  * @param hostname Resolved hostname.
  * @param ipaddr Pointer to the resolved IP address.
  * @param arg Pointer to the TLS client state.
  */
 static void tls_client_dns_found(const char* hostname, const ip_addr_t *ipaddr, void *arg)
 {
     if (ipaddr)
     {
         printf("DNS resolving complete\n");
         tls_client_connect_to_server_ip(ipaddr, (TLS_CLIENT_T *) arg);
     }
     else
     {
         printf("error resolving hostname %s\n", hostname);
         tls_client_close(arg);
     }
 }
 
 /**
  * @brief Opens a TLS connection to the server.
  *
  * Creates a TLS PCB, sets callbacks, configures SNI, and starts DNS resolution.
  *
  * @param hostname Server hostname.
  * @param arg Pointer to the TLS client state.
  * @return true if connection initiation was successful, false otherwise.
  */
 static bool tls_client_open(const char *hostname, void *arg) {
     err_t err;
     ip_addr_t server_ip;
     TLS_CLIENT_T *state = (TLS_CLIENT_T*)arg;
 
     state->pcb = altcp_tls_new(tls_config, IPADDR_TYPE_ANY);
     if (!state->pcb) {
         printf("failed to create pcb\n");
         return false;
     }
 
     altcp_arg(state->pcb, state);
     altcp_poll(state->pcb, tls_client_poll, state->timeout * 2);
     altcp_recv(state->pcb, tls_client_recv);
     altcp_err(state->pcb, tls_client_err);
 
     /* Set SNI */
     mbedtls_ssl_set_hostname(altcp_tls_context(state->pcb), hostname);
 
     printf("resolving %s\n", hostname);
 
     cyw43_arch_lwip_begin();
 
     err = dns_gethostbyname(hostname, &server_ip, tls_client_dns_found, state);
     if (err == ERR_OK)
     {
         /* host is in DNS cache */
         tls_client_connect_to_server_ip(&server_ip, state);
     }
     else if (err != ERR_INPROGRESS)
     {
         printf("error initiating DNS resolving, err=%d\n", err);
         tls_client_close(state->pcb);
     }
 
     cyw43_arch_lwip_end();
 
     return err == ERR_OK || err == ERR_INPROGRESS;
 }
 
 bool run_tls_client_test(const uint8_t *cert, size_t cert_len, const char *server, const char *request, int timeout) {
     /* No CA certificate checking */
     tls_config = altcp_tls_create_config_client(cert, cert_len);
     assert(tls_config);
 
     //mbedtls_ssl_conf_authmode(&tls_config->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
 
     TLS_CLIENT_T *state = tls_client_init();
     if (!state) {
         return false;
     }
     state->http_request = request;
     state->timeout = timeout;
     if (!tls_client_open(server, state)) {
         return false;
     }
     while(!state->complete) {
 #if PICO_CYW43_ARCH_POLL
         cyw43_arch_poll();
         cyw43_arch_wait_for_work_until(make_timeout_time_ms(1000));
 #else
         sleep_ms(1000);
 #endif
     }
     int err = state->error;
     free(state);
     altcp_tls_free_config(tls_config);
     return err == 0;
 }