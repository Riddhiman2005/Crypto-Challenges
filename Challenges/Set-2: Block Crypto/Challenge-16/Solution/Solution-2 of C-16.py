
from Crypto.Cipher import AES
import os
import random
import string

blockSize = 16
key = os.urandom(blockSize)
IV = os.urandom(blockSize)

def xorBytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def paddingPKCS7(plainText):
    padding = blockSize - (len(plainText) % blockSize)
    return plainText + bytes([padding] * padding)

def removePadding(plaintextPadded):
    paddingBytes = plaintextPadded[-1]
    return plaintextPadded[:-paddingBytes]

def aesCBC_encrypt(plaintextUnpadded):
    plaintext = paddingPKCS7(plaintextUnpadded)
    cipherBlock = AES.new(key, AES.MODE_ECB)
    cipherText = b""
    previousBlock = IV

    for i in range(0, len(plaintext), blockSize):
        block = plaintext[i:i+blockSize]
        xored = xorBytes(block, previousBlock)
        encrypted = cipherBlock.encrypt(xored)
        cipherText += encrypted
        previousBlock = encrypted

    return cipherText

def aesCBC_decrypt(cipherText):
    cipherBlock = AES.new(key, AES.MODE_ECB)
    plaintextPadded = b""
    previousBlock = IV

    for i in range(0, len(cipherText), blockSize):
        block = cipherText[i:i+blockSize]
        decrypted = cipherBlock.decrypt(block)
        xored = xorBytes(decrypted, previousBlock)
        plaintextPadded += xored
        previousBlock = block

    plaintext = removePadding(plaintextPadded)
    return plaintext

def prependData(plaintext):
    data = "comment1=cooking%20MCs;userdata="
    return bytes(data + plaintext.decode(), "utf-8")

def quoteOut(plaintext):
    buffer = plaintext.decode().replace(";", "?").replace("=", "?")
    return bytes(buffer, "utf-8")

def appendData(plaintext):
    data = ";comment2=%20like%20a%20pound%20of%20bacon"
    return plaintext + bytes(data, "utf-8")

def getModifiedCipherText(cipherText, plaintext):
    beforeXorPlaintext = xorBytes(plaintext[32:48], cipherText[16:32])
    cipherTextBlock = bytearray(cipherText[16:32])
    cipherTextBlock[0] = beforeXorPlaintext[0] ^ ord(';')
    cipherTextBlock[11] = beforeXorPlaintext[11] ^ ord(';')
    cipherTextBlock[6] = beforeXorPlaintext[6] ^ ord('=')
    cipherText[16:32] = bytes(cipherTextBlock)
    return cipherText

def attackSuccess(cipherText):
    cipherTextNew = getModifiedCipherText(cipherText, aesCBC_decrypt(cipherText))
    plaintextNew = aesCBC_decrypt(cipherTextNew)
    return b";admin=true;" in plaintextNew

def main():
    userData = ";admin=true;"
    plaintext = prependData(userData.encode())
    plaintext = appendData(plaintext)
    plaintext = quoteOut(plaintext)
    cipherText = aesCBC_encrypt(plaintext)
    if attackSuccess(cipherText):
        print("Attack Success")
    else:
        print("Bad Attack")

if __name__ == "__main__":
    main()
