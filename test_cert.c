#include <stdio.h>
#include <stdlib.h>
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
#include "mbedtls/error.h"

int main(int argc, char *argv[]) {
    // Ensure correct usage
    if (argc != 2) {
        printf("Usage: %s <server_cert.pem>\n", argv[0]);
        return 1;
    }

    // Load the certificate file into memory
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        printf("❌ Failed to open %s\n", argv[1]);
        return 1;
    }

    // Determine file size and allocate memory
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    rewind(f);

    unsigned char *buf = (unsigned char*)malloc(len + 1);
    if (!buf) {
        printf("❌ malloc() failed\n");
        fclose(f);
        return 1;
    }

    // Read the certificate file into memory and null-terminate it
    fread(buf, 1, len, f);
    buf[len] = '\0'; 
    fclose(f);

    // Initialize mbedTLS X.509 certificate structure
    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);

    // Attempt to parse the certificate
    int ret = mbedtls_x509_crt_parse(&crt, buf, len + 1);
    if (ret != 0) {
        char err_buf[128];
        mbedtls_strerror(ret, err_buf, sizeof(err_buf));
        printf("❌ mbedtls_x509_crt_parse failed: -0x%04X (%s)\n", -ret, err_buf);
    } else {
        printf("✅ Certificate OK!\n");
    }

    // Clean up allocated resources
    free(buf);
    mbedtls_x509_crt_free(&crt);
    return 0;
}