![image](https://github.com/mytechnotalent/ipts/blob/main/ipts.png?raw=true)

## FREE Reverse Engineering Self-Study Course [HERE](https://github.com/mytechnotalent/Reverse-Engineering-Tutorial)

<br><br>

# IoT Pico W TLS Server
IoT Pico W TLS Server that obtains the Pico W temperature and serves it to a TLS client where this project is designed for a MAC M series client and is based on the Raspberry Pi Foundation’s pico_examples TLS client example.

<br><br>

### STEP 1: rename `wifi_creds.template` to `wifi_creds.h` and fill in your SSID and password
### STEP 2: `./build.sh`
### STEP 3: `./tls_client <IP>`

### SOURCE `tls_server.c`
```c
/////////////////////////////////////////////////////////////////////
// Project: Raspberry Pi Pico TLS Server Application
// Author: Kevin Thomas
// E-Mail: ket189@pitt.edu
// Version: 1.0
// Date: 02/26/25
// Target Device: Raspberry Pi Pico W (RP2040)
// Clock Frequency: (Depends on your board, e.g., 125 MHz)
// Toolchain: CMake, pico-sdk, ARM-none-eabi-gcc
// License: Apache License 2.0
// Description: This application sets up a TLS server on port 443 
//              using altcp_tls from lwIP, parsing an embedded 
//              self-signed certificate and private key. It sends 
//              RP2040 temperature readings once per second to 
//              connected clients and provides console logs for 
//              debugging, including connection status, sent data, 
//              and errors.
/////////////////////////////////////////////////////////////////////

 #include "pico/stdlib.h"
 #include "pico/cyw43_arch.h"
 #include "hardware/adc.h"
 #include "wifi_creds.h" 
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 
 #include "lwip/altcp_tls.h"
 #include "lwip/altcp_tcp.h"
 #include "lwip/ip_addr.h"
 #include "lwip/netif.h"
 #include "lwip/pbuf.h"
 
 #include "mbedtls/x509_crt.h"
 #include "mbedtls/pk.h"
 #include "mbedtls/error.h"
 
 #include "cert_string.h" 
 #include "key_string.h"
 
 #define SERVER_PORT             443
 #define TEMP_SEND_INTERVAL_MS   1000
 
  /**
  * @struct TLS_SERVER_T
  * @brief Structure that holds server state and TLS connection data.
  * 
  * This structure is used to track the TLS server connection details and its status.
  */
 typedef struct {
     struct altcp_pcb *pcb;      ///< lwIP control block for the connection
     bool connected;
     int error;
 } TLS_SERVER_T;
 
 // TLS configuration structure; holds the TLS server state
 static struct altcp_tls_config *tls_config = NULL;
 static TLS_SERVER_T *server_state = NULL;

 // Forward declarations
 static err_t dummy_recv(void *arg, struct altcp_pcb *pcb, struct pbuf *p, err_t err);
 static void tls_server_err(void *arg, err_t err);
 static void print_server_ip(void);
 static float read_temperature(void);
 static err_t tls_server_accept(void *arg, struct altcp_pcb *newpcb, err_t err);
 static int configure_tls_cert(void);
 
 int main(void) {
     // Initialize standard I/O for logging/debugging
     stdio_init_all();

    // Initialize CYW43 (Wi-Fi module)
     if (cyw43_arch_init()) {
         printf("❌ Failed to initialize CYW43\n");
         return 1;
     }
     cyw43_arch_enable_sta_mode();
 
     // Attempt to connect to the specified Wi-Fi network
     printf("🔄 Connecting to Wi-Fi...\n");
     if (cyw43_arch_wifi_connect_timeout_ms(
             WIFI_SSID, WIFI_PASSWORD, CYW43_AUTH_WPA2_AES_PSK, 30000
         )) {
         printf("❌ Failed to connect to Wi-Fi\n");
         return 1;
     }
     printf("✅ Connected to Wi-Fi!\n");
     print_server_ip();
 
    // Configure TLS server
     printf("🔄 Configuring TLS server...\n");
     tls_config = altcp_tls_create_config_server(1);  // 1 => one cert
     if (!tls_config) {
         printf("❌ Failed to create TLS config\n");
         return 1;
     }
 
     // Attempt to parse and add cert/key to config
     if (configure_tls_cert() != 0) {
         return 1; // We printed error details already
     }
 
     // Create altcp TLS PCB
     struct altcp_pcb *pcb = altcp_tls_new(tls_config, IPADDR_TYPE_ANY);
     if (!pcb) {
         printf("❌ Failed to create TLS PCB\n");
         return 1;
     }
 
     // Bind on port 443
     err_t err = altcp_bind(pcb, IP_ADDR_ANY, SERVER_PORT);
     if (err != ERR_OK) {
         printf("❌ Failed to bind PCB, err=%d\n", err);
         return 1;
     }
 
     // Listen for incoming TLS connections
     pcb = altcp_listen(pcb);
 
     // Allocate global server state
     server_state = malloc(sizeof(TLS_SERVER_T));
     if (!server_state) {
         printf("❌ Failed to allocate server state\n");
         return 1;
     }
     memset(server_state, 0, sizeof(TLS_SERVER_T));
 
     // Register accept callback
     altcp_accept(pcb, tls_server_accept);
     altcp_arg(pcb, server_state); // Make sure the top-level listening pcb also has the arg
     printf("✅ TLS server listening on port %d\n", SERVER_PORT);
 
     // After a client connects, wait 500 ms, then send every second
     const uint32_t post_connect_delay_ms = 500;
 
     // Main loop - continuously checking for connections and sending temperature updates
     while (1) {
 #if PICO_CYW43_ARCH_POLL
         cyw43_arch_poll();
 #endif
         if (server_state->connected && server_state->pcb) {
             static bool sent_first = false;
             if (!sent_first) {
                 sleep_ms(post_connect_delay_ms);
                 sent_first = true;
             }
 
             float temp = read_temperature();
             char msg[64];
             snprintf(msg, sizeof(msg), "RP2040 Temperature: %.2f C\n", temp);
 
             err_t werr = altcp_write(server_state->pcb, msg, strlen(msg), TCP_WRITE_FLAG_COPY);
             if (werr == ERR_OK) {
                 altcp_output(server_state->pcb);
                 printf("📡 Sent: %s", msg);
             } else if (werr == ERR_MEM) {
                 altcp_output(server_state->pcb);
                 printf("⚠️ altcp_write returned ERR_MEM, will retry\n");
             } else {
                 printf("❌ altcp_write returned err=%d\n", werr);
                 // Mark connection as closed
                 server_state->connected = false;
                 server_state->pcb       = NULL;
             }
         } else {
             // No valid connection
             printf("⚠️ No client connected.\n");
         }
         sleep_ms(TEMP_SEND_INTERVAL_MS);
     }
 
     return 0; // Unreachable but good practice
 }

  /**
  * @brief Dummy receive callback that drains inbound data.
  * 
  * @param arg Unused.
  * @param pcb Pointer to lwIP TLS connection control block.
  * @param p Pointer to received data buffer.
  * @param err lwIP error code.
  * @return ERR_OK if processed successfully.
  */
 static err_t dummy_recv(void *arg, struct altcp_pcb *pcb, struct pbuf *p, err_t err) {
    if (!p) {
        // Client closed the connection
        printf("Client closed connection (dummy_recv)\n");
        return altcp_close(pcb);
    }
    altcp_recved(pcb, p->tot_len);
    pbuf_free(p);
    return ERR_OK;
}

/**
 * @brief Error callback for the TLS server.
 * 
 * @param arg Pointer to the server state.
 * @param err lwIP error code.
 */
static void tls_server_err(void *arg, err_t err) {
    TLS_SERVER_T *state = (TLS_SERVER_T *)arg;
    printf("❌ TLS server error: %d\n", err);
    if (state) {
        state->pcb = NULL;
        state->connected = false;
    }
}

/**
 * @brief Displays the assigned IP address of the server.
 */
static void print_server_ip(void) {
    if (netif_default && netif_is_up(netif_default)) {
        char ip_str[16];
        ip4addr_ntoa_r(netif_ip4_addr(netif_default), ip_str, sizeof(ip_str));
        printf("✅ Server IP: %s\n", ip_str);
    } else {
        printf("❌ Failed to obtain IP address\n");
    }
}

/**
 * @brief Reads the RP2040 internal temperature sensor.
 * 
 * @return Temperature in Celsius.
 */
static float read_temperature(void) {
   static bool adc_initialized = false;
   if (!adc_initialized) {
       adc_init();
       adc_set_temp_sensor_enabled(true);
       adc_initialized = true;
   }
   
   adc_select_input(4);
   uint16_t raw = adc_read();
   
   // Corrected conversion formula
   const float conversion_factor = 3.3f / (1 << 12); // ADC 12-bit scale
   float voltage = raw * conversion_factor;
   
   float temperature = 27.0f - (voltage - 0.706f) / 0.001721f; // Correct formula
   return temperature;
}

/**
 * @brief Callback when a client connects to the TLS server.
 * 
 * @param arg Pointer to server state.
 * @param newpcb Pointer to the new lwIP TLS control block.
 * @param err lwIP error code.
 * @return ERR_OK on success.
 */
static err_t tls_server_accept(void *arg, struct altcp_pcb *newpcb, err_t err) {
    TLS_SERVER_T *state = (TLS_SERVER_T *)arg;
    if ((err != ERR_OK) || !newpcb) {
        return ERR_VAL;
    }
    printf("✅ Client connected to TLS server\n");
    state->pcb       = newpcb;
    state->connected = true;
    altcp_arg(newpcb, state);
    altcp_recv(newpcb, dummy_recv);
    altcp_err(newpcb, tls_server_err);
    return ERR_OK;
}

/**
 * @brief Loads the TLS certificate and private key.
 * 
 * @return 0 on success, nonzero on failure.
 */
static int configure_tls_cert(void) {
    int ret;
    char err_buf[128];

    // 1. Test parse the certificate (for debug)
    {
        mbedtls_x509_crt manual_cert;
        mbedtls_x509_crt_init(&manual_cert);
        ret = mbedtls_x509_crt_parse(
            &manual_cert,
            (const unsigned char *)server_cert_pem,
            strlen(server_cert_pem) + 1
        );
        if (ret != 0) {
            mbedtls_strerror(ret, err_buf, sizeof(err_buf));
            printf("❌ [Manual parse] mbedtls_x509_crt_parse failed: %d (%s)\n", ret, err_buf);
            return ret;
        }
        printf("✅ [Manual parse] Certificate OK!\n");
        mbedtls_x509_crt_free(&manual_cert);
    }

    // 2. Parse again for altcp_tls, along with the private key
    mbedtls_x509_crt server_cert;
    mbedtls_pk_context server_key;
    mbedtls_x509_crt_init(&server_cert);
    mbedtls_pk_init(&server_key);

    printf("🔍 Server Cert:\n%s\n", server_cert_pem);
    printf("🔍 Server Key:\n%s\n", server_key_pem);

    // Certificate
    ret = mbedtls_x509_crt_parse(&server_cert,
                                 (const unsigned char *)server_cert_pem,
                                 strlen(server_cert_pem) + 1);
    if (ret != 0) {
        mbedtls_strerror(ret, err_buf, sizeof(err_buf));
        printf("❌ mbedtls_x509_crt_parse failed: %d (%s)\n", ret, err_buf);
        return ret;
    }

    // Key
    ret = mbedtls_pk_parse_key(&server_key,
                               (const unsigned char *)server_key_pem,
                               strlen(server_key_pem) + 1,
                               NULL, 0);
    if (ret != 0) {
        mbedtls_strerror(ret, err_buf, sizeof(err_buf));
        printf("❌ mbedtls_pk_parse_key failed: %d (%s)\n", ret, err_buf);
        return ret;
    }

    // 3. Add certificate and key to altcp_tls config
    ret = altcp_tls_config_server_add_privkey_cert(
              tls_config,
              (const u8_t *)server_key_pem,  strlen(server_key_pem)  + 1,
              (const u8_t *)server_cert_pem, strlen(server_cert_pem) + 1,
              (const u8_t *)server_cert_pem, strlen(server_cert_pem) + 1
          );
    if (ret != ERR_OK) {
        printf("❌ Failed to set server certificate, err=%d\n", ret);
        return ret;
    }
    printf("✅ Server certificate successfully loaded!\n");

    mbedtls_x509_crt_free(&server_cert);
    mbedtls_pk_free(&server_key);

    return 0;
}
```

### SOURCE `tls_client.c`
```c
/////////////////////////////////////////////////////////////////////
// Project: Raspberry Pi Pico TLS Client Application
// Author: Kevin Thomas
// E-Mail: ket189@pitt.edu
// Version: 1.0
// Date: 02/27/25
// Target Device: Any Linux/macOS system (including Raspberry Pi)
// Toolchain: GCC, OpenSSL
// License: Apache License 2.0
// Description: This program implements a TLS client using OpenSSL. 
//              It establishes a secure connection to a TLS server, 
//              reads incoming data, and handles connection errors. 
//              The client continuously reads messages from the server 
//              until the connection is closed. 
/////////////////////////////////////////////////////////////////////

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SERVER_PORT 443

int main(int argc, char *argv[]) {
    // Ensure the correct number of command-line arguments are provided
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <server_ip>\n", argv[0]);
        return 1;
    }

    const char *server_ip = argv[1];

    // Initialize OpenSSL library
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // Create a new SSL context using TLS_client_method
    const SSL_METHOD *method = TLS_client_method();
    if (!method) {
        fprintf(stderr, "Unable to create TLS method\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    // Optionally ignore self-signed certificate errors:
    // SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    // Create a new SSL connection state object
    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return 1;
    }

    // Create a TCP socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return 1;
    }

    // Setup server address
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        perror("inet_pton");
        close(sockfd);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return 1;
    }

    // Connect to the server
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(sockfd);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return 1;
    }

    // Attach the socket to the SSL object
    SSL_set_fd(ssl, sockfd);

    // Perform the TLS handshake
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        close(sockfd);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        return 1;
    }

    printf("Connected to %s via TLS %s\n", server_ip, SSL_get_version(ssl));

    // Read lines from the server until it closes
    char buf[1024];
    while (1) {
        int bytes = SSL_read(ssl, buf, sizeof(buf) - 1);
        if (bytes > 0) {
            buf[bytes] = '\0';
            printf("%s", buf);
            fflush(stdout);
        } else if (bytes == 0) {
            // Server closed connection gracefully
            printf("\nServer closed connection.\n");
            break;
        } else {
            // Error or shutdown
            ERR_print_errors_fp(stderr);
            break;
        }
    }

    // Clean up
    SSL_shutdown(ssl);
    close(sockfd);
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    return 0;
}
```

<br>

## License
[Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
