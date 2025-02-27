#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

echo "🔄 Generating TLS certificate..."
./generate_tls_cert.sh

echo "🔄 Converting PEM certificate to C string..."
./pem_to_cert_string.sh "server_cert.pem"

echo "🔄 Converting PEM private key to C string..."
./pem_to_key_string.sh "server_key.pem"

echo "🔄 Building client..."
./build_client.sh

echo "✅ All scripts executed successfully!"