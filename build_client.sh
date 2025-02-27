#!/bin/bash

# Define variables
SOURCE_FILE="tls_client.c"
OUTPUT_FILE="tls_client"
OPENSSL_PATH="/opt/homebrew/opt/openssl@3"

# Compile the TLS client
gcc "$SOURCE_FILE" -o "$OUTPUT_FILE" \
    -arch arm64 \
    -I"$OPENSSL_PATH/include" \
    -L"$OPENSSL_PATH/lib" \
    -lssl -lcrypto

# Check if compilation was successful
if [ $? -eq 0 ]; then
    echo "✅ Compilation successful: $OUTPUT_FILE created."
else
    echo "❌ Compilation failed."
    exit 1
fi