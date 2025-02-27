#include <stdio.h>
#include <stdlib.h>
#include "mbedtls/pk.h"
#include "mbedtls/error.h"

int main(int argc, char *argv[]) {
    // Ensure correct usage
    if (argc != 2) {
        printf("Usage: %s <private_key.pem>\n", argv[0]);
        return 1;
    }

    // Load the private key file into memory
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        printf("❌ Failed to open %s\n", argv[1]);
        return 1;
    }

    // Determine file size and allocate memory
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    rewind(f);

    unsigned char *buf = (unsigned char *)malloc(len + 1);
    if (!buf) {
        printf("❌ malloc() failed\n");
        fclose(f);
        return 1;
    }

    // Read the private key file into memory and null-terminate it
    fread(buf, 1, len, f);
    buf[len] = '\0'; 
    fclose(f);

    // Initialize the mbedTLS private key structure
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    // Attempt to parse the private key (7 arguments for newer mbedTLS versions)
    int ret = mbedtls_pk_parse_key(&pk,
                                   buf,
                                   len + 1,
                                   NULL, // No password
                                   0,    // Password length
                                   NULL, // No RNG callback
                                   NULL  // No RNG context
                                  );
    if (ret != 0) {
        char err_buf[128];
        mbedtls_strerror(ret, err_buf, sizeof(err_buf));
        printf("❌ mbedtls_pk_parse_key failed: -0x%04X (%s)\n", -ret, err_buf);
    } else {
        printf("✅ Private key OK!\n");
    }

    // Clean up allocated resources
    mbedtls_pk_free(&pk);
    free(buf);
    return 0;
}