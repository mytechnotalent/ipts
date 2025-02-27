#!/bin/bash

# Compiler settings
CC=gcc  # Define the compiler
CFLAGS="-Wall -Wextra -O2 -I/opt/homebrew/include"  # Compiler flags: warnings, optimizations, and include paths
LDFLAGS="-L/opt/homebrew/lib -lmbedtls -lmbedx509 -lmbedcrypto"  # Linker flags: link against mbedTLS libraries

# Output executable name
OUTPUT="test_key"

# Source file to compile
SOURCE="test_key.c"

# Print a message indicating the start of compilation
echo "Compiling $SOURCE..."

# Compile the C source file
$CC $CFLAGS $SOURCE -o $OUTPUT $LDFLAGS

# Check if compilation was successful
if [ $? -eq 0 ]; then
    echo "✅ Compilation successful. Run ./$OUTPUT <server_key.pem>"
else
    echo "❌ Compilation failed."
fi