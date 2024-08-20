import binascii

# Read the content from out.txt
with open('out.txt', 'r') as file:
    hex_data = file.read().replace('\n', '')

# Convert hex data to binary
binary_data = binascii.unhexlify(hex_data)

# Decode the binary data to a string
# try:
#     decoded_string = binary_data.decode('utf-8', errors='replace')
# except UnicodeDecodeError:
decoded_string = binary_data.decode('latin1', errors='replace')

print("Decoded Data:\n")
print(decoded_string)

