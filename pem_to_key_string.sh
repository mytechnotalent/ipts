#!/bin/bash

# Check if the user provided an input key file
if [ $# -lt 1 ]; then
  echo "Usage: $0 <server_key.pem>"
  exit 1
fi

# Define the input PEM file and the variable name for the C header
PEM_FILE="$1"
VAR_NAME="server_key_pem"

# Start the header guard to prevent multiple inclusions
echo "#ifndef KEY_STRING_H"
echo "#define KEY_STRING_H"
echo

# Declare the static constant string to hold the private key content
echo "static const char $VAR_NAME[] ="

# Read the PEM file line by line and process each line
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
echo "#endif // KEY_STRING_H"