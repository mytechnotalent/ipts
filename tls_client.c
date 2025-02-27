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