#!/bin/bash

# Check if a file argument was provided
if [ $# -lt 1 ]; then
  echo "Usage: $0 <server_cert.pem>"
  exit 1
fi

# Set input PEM file and the variable name to use in the header
PEM_FILE="$1"
VAR_NAME="server_cert_pem"

# Begin the header guard for the C header file
echo "#ifndef CERT_STRING_H"
echo "#define CERT_STRING_H"
echo

# Declare the static constant string to hold the certificate content
echo "static const char $VAR_NAME[] ="

# Read the PEM file line by line, escaping necessary characters
while IFS= read -r line; do
  # Escape backslashes and double quotes to ensure proper string formatting in C
  ESCAPED=$(echo "$line" | sed 's/\\/\\\\/g; s/"/\\"/g')
  # Print the escaped line as a properly formatted C string
  echo "\"$ESCAPED\\n\""
done < "$PEM_FILE"

# End the C string declaration
echo ";"
echo

# Close the header guard
echo "#endif // CERT_STRING_H"