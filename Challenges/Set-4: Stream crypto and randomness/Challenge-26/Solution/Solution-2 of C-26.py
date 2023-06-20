
from Crypto.Cipher import AES
import os
import random
from Cryptodome.Util.Padding import pad, unpad

PREFIX = "comment1=cooking%20MCs;userdata="
POSTFIX = ";comment2=%20like%20a%20pound%20of%20bacon"
ADMIN_KV = b";admin=true;"
ADMIN_PADDING_LEN = 11

def add_comments(userdata):
    sanitized = userdata.replace(";", "?").replace("=", "?")
    return PREFIX + sanitized + POSTFIX

def aes_128_ctr(plaintext, key, nonce):
    counter = 0
    nonce_bytes = nonce.to_bytes(8, "little")
    ciphertext = b""
    cipher = AES.new(key, AES.MODE_ECB)

    while len(ciphertext) < len(plaintext):
        counter_bytes = counter.to_bytes(8, "little")
        keystream = cipher.encrypt(nonce_bytes + counter_bytes)
        ciphertext += bytes(x ^ y for x, y in zip(plaintext[len(ciphertext):], keystream))
        counter += 1

    return ciphertext

class Server:
    def __init__(self):
        self.key = os.urandom(16)
        self.nonce = random.randint(0, (1 << 64) - 1)

def encrypt_userdata(svr, userdata):
    bytes_data = add_comments(userdata).encode()
    padded_data = pad(bytes_data, 16)
    return aes_128_ctr(padded_data, svr.key, svr.nonce)

def decrypt_userdata(svr, userdata):
    plaintext = aes_128_ctr(userdata, svr.key, svr.nonce)
    unpadded_data = unpad(plaintext, 16)
    return unpadded_data.decode()

def make_fake_admin(svr):
    prefix_padding_len = -len(PREFIX) % 16
    fake_admin = b"\x00" * (prefix_padding_len + 16)
    n_prefix_blocks = (len(PREFIX) + prefix_padding_len) // 16
    i_fake_admin_block = n_prefix_blocks + 1

    ADMIN_BLOCK = ADMIN_KV + b"a" * ADMIN_PADDING_LEN

    enc = encrypt_userdata(svr, fake_admin)
    fake_admin_block = enc[(i_fake_admin_block - 1) * 16:i_fake_admin_block * 16]
    fake_admin_block = bytes(x ^ y for x, y in zip(fake_admin_block, ADMIN_BLOCK))

    return enc
