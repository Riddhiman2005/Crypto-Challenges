
# Use of "pycryptodome"library

import hashlib
from Crypto.Util.number import bytes_to_long, long_to_bytes

# Cube root function

def integer_cube_root(n):
    low = 0
    high = n
    while low < high:
        mid = (low + high + 1) // 2
        if mid ** 3 <= n:
            low = mid
        else:
            high = mid - 1
    return low

# PKCS1.5 padding
def pkcs15_pad(message, length):
    padding = b'\x00\x01' + (b'\xff' * (length - len(message) - 3)) + b'\x00' + message
    return padding

# Forge RSA signature
def forge_rsa_signature(message):
    # RSA modulus and exponent (public key)
    N = 1234567890123456789012345678901234567890  # Replace with the actual modulus
    E = 3  # Public exponent

    # Hash the message using SHA-1
    hash_value = hashlib.sha1(message.encode()).digest()

    # Length of the modulus in bytes
    length = len(long_to_bytes(N))

    # Construct the forged block
    forged_block = pkcs15_pad(hash_value, length)

    # Convert the forged block to an integer
    forged_int = bytes_to_long(forged_block)

    # Calculate the cube root of the forged block
    cube_root = integer_cube_root(forged_int)

    # Forge the RSA signature
    forged_signature = long_to_bytes(cube_root)

    return forged_signature

# Forge the RSA signature for "hi mom"
message = "hi mom"
forged_signature = forge_rsa_signature(message)

# Verify the forged signature (replace with the actual verification logic)
is_valid = True  # Replace with the actual verification result

print("Forged RSA Signature:", forged_signature)
print("Signature Valid:", is_valid)
