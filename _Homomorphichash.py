from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# 生成RSA密钥对
key = RSA.generate(2048)
public_key = key.publickey()
def hash_message(message):
    cipher_Text = PKCS1_OAEP.new(public_key).encrypt(message)
    return cipher_Text

