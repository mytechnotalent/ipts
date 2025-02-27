#!/bin/bash

# Default certificate subject details (modify as needed)
SUBJECT="/C=US/ST=California/L=San Francisco/O=Example Company/OU=IT/CN=localhost"

# Certificate validity in days (default: 365 days)
DAYS=365

# RSA key size in bits (default: 2048)
KEY_SIZE=2048

# Display information about the certificate being generated
echo "🔒 Generating a ${KEY_SIZE}-bit private key and self-signed certificate..."
echo "📌 Subject: ${SUBJECT}"
echo "📅 Certificate validity: ${DAYS} days"

# Generate private key and self-signed certificate using OpenSSL
openssl req -x509 -newkey rsa:${KEY_SIZE} -nodes \
  -keyout server_key.pem -out server_cert.pem \
  -days ${DAYS} -subj "${SUBJECT}"

# Check if the command was successful
if [ $? -eq 0 ]; then
    echo "✅ Certificate and key generated successfully:"
    echo "   📜 Certificate: server_cert.pem"
    echo "   🔑 Private Key: server_key.pem"
else
    echo "❌ Error generating certificate and key."
fi