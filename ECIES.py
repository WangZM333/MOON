import collections
import hashlib
import pickle
import random
import binascii
import sys
from Crypto.Cipher import AES
import Padding
import sys

# 设置更高的整数字符串转换位数限制
sys.set_int_max_str_digits(1000000000)  # 可以根据需要调整这个数字


def enc_long(n):
    '''Encodes arbitrarily large number n to a sequence of bytes.
    Big endian byte order is used.'''
    s = ""
    while n > 0:
        s = chr(n & 0xFF) + s
        n >>= 8
    return s

# Padding for the input string --not
# related to encryption itself.
BLOCK_SIZE = 16  # Bytes
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
                chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpad = lambda s: s[:-ord(s[len(s) - 1:])]


def encrypt(plaintext,key, mode):
	encobj = AES.new(key,mode)
	return(encobj.encrypt(plaintext))

def decrypt(ciphertext,key, mode):
	encobj = AES.new(key,mode)
	return(encobj.decrypt(ciphertext))


# Modular arithmetic ##########################################################

def inverse_mod(k, p):
    """Returns the inverse of k modulo p.
    This function returns the only integer x such that (x * k) % p == 1.
    k must be non-zero and p must be a prime.
    """
    if k == 0:
        raise ZeroDivisionError('division by zero')

    if k < 0:
        # k ** -1 = p - (-k) ** -1  (mod p)
        return p - inverse_mod(-k, p)

    # Extended Euclidean algorithm.
    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = p, k

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    gcd, x, y = old_r, old_s, old_t

    assert gcd == 1
    assert (k * x) % p == 1

    return x % p

# Functions that work on curve points #########################################

def is_on_curve(point):
    """Returns True if the given point lies on the elliptic curve."""
    if point is None:
        # None represents the point at infinity.
        return True

    x, y = point

    return (y * y - x * x * x - curve.a * x - curve.b) % curve.p == 0


def point_neg(point):
    """Returns -point."""
    assert is_on_curve(point)

    if point is None:
        # -0 = 0
        return None

    x, y = point
    result = (x, -y % curve.p)

    assert is_on_curve(result)

    return result


def point_add(point1, point2):
    """Returns the result of point1 + point2 according to the group law."""
    assert is_on_curve(point1)
    assert is_on_curve(point2)

    if point1 is None:
        # 0 + point2 = point2
        return point2
    if point2 is None:
        # point1 + 0 = point1
        return point1

    x1, y1 = point1
    x2, y2 = point2

    if x1 == x2 and y1 != y2:
        # point1 + (-point1) = 0
        return None

    if x1 == x2:
        # This is the case point1 == point2.
        m = (3 * x1 * x1 + curve.a) * inverse_mod(2 * y1, curve.p)
    else:
        # This is the case point1 != point2.
        m = (y1 - y2) * inverse_mod(x1 - x2, curve.p)

    x3 = m * m - x1 - x2
    y3 = y1 + m * (x3 - x1)
    result = (x3 % curve.p,
              -y3 % curve.p)

    assert is_on_curve(result)

    return result


def scalar_mult(k, point):
    """Returns k * point computed using the double and point_add algorithm."""
    assert is_on_curve(point)

    if k % curve.n == 0 or point is None:
        return None

    if k < 0:
        # k * point = -k * (-point)
        return scalar_mult(-k, point_neg(point))

    result = None
    addend = point

    while k:
        if k & 1:
            # Add.
            result = point_add(result, addend)

        # Double.
        addend = point_add(addend, addend)

        k >>= 1

    assert is_on_curve(result)

    return result


# Keypair generation and ECDSA ################################################

def make_keypair():
    """Generates a random private-public key pair."""
    private_key = random.randrange(1, curve.n)
    public_key = scalar_mult(private_key, curve.g)

    return private_key, public_key


def verify_signature(public_key, message, signature):
    z = hash_message(message)

    r, s = signature

    w = inverse_mod(s, curve.n)
    u1 = (z * w) % curve.n
    u2 = (r * w) % curve.n

    x, y = point_add(scalar_mult(u1, curve.g),
                     scalar_mult(u2, public_key))

    if (r % curve.n) == (x % curve.n):
        return 'signature matches'
    else:
        return 'invalid signature'

EllipticCurve = collections.namedtuple('EllipticCurve', 'name p a b g n h')

curve = EllipticCurve(
    'secp256k1',
    # Field characteristic.
    p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
    # Curve coefficients.
    a=0,
    b=7,
    # Base point.
    g=(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
       0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8),
    # Subgroup order.
    n=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
    # Subgroup cofactor.
    h=1,
)


# 封装ecies加密的密文消息
class Message:
    def __init__(self, text):
        self.R = []
        if isinstance(text, int):
            self.text = str(text)
        else:
            self.text = text

    def encrypt(self, Qa):
        '''
        多层加密:加密方在加密时根据自己私钥和解密方公钥计算出对称密钥和R，使用对称密钥进行加密，然后将R存入列表；
               解密方根据R和自己私钥计算对称密钥进行解密,然后将自己用于计算对称密钥的R从列表中删去
        '''
        r = random.randint(0, 2 ** 128)
        S = scalar_mult(r, Qa)
        key = hashlib.sha256(str(S[0]).encode()).digest()
        if isinstance(self.text, bytes):  # 第一次加密时需要将明文转换为字节形式
            self.text = encrypt(self.text, key, AES.MODE_ECB)
        else:
            message = Padding.appendPadding(self.text, blocksize=Padding.AES_blocksize, mode=0)
            self.text = encrypt(message.encode(), key, AES.MODE_ECB)

        rG = scalar_mult(r, curve.g)
        self.R.append(rG)

    def decrypt(self, dA):
        S = scalar_mult(dA, self.R[-1])
        key = hashlib.sha256(str(S[0]).encode()).digest()
        self.text = decrypt(self.text, key, AES.MODE_ECB)
        self.R.pop()

    def serialize(self):
        return pickle.dumps(self)

    @staticmethod
    def deserialize(serialized_obj):
        return pickle.loads(serialized_obj)

# 为每个客户端生成ECIES密钥对
def generate_keys(clients):
    private_keys = {}
    public_keys = {}
    for client in clients:
        dA, Qa = make_keypair()
        public_keys[client] = Qa
        private_keys[client] = dA

    return private_keys, public_keys


def generate_symmetric_keys(clients, ecc_keys):
    symmetric_keys = {}
    for client in clients:
        # 私钥r，公钥rG; 根据Qa和r生成对称密钥S
        r = random.randint(0, 2 ** 128)
        rG = scalar_mult(r, curve.g)
        S = scalar_mult(r, ecc_keys[clients[0]]['public_key'])
        symmetric_keys[client] = {
            'rG': rG,
            'S': S
        }
    return symmetric_keys


def main():

    message = "131564313843135473135464131387468465126843"
    if (len(sys.argv) > 1):
        message = str(sys.argv[1])


    dA, Qa = make_keypair()
    print("Private key:", hex(dA))
    print(("Public key: (0x{:x}, 0x{:x})".format(*Qa)))


    print("\n\n=========================")

    r = random.randint(0, 2**128)

    rG = scalar_mult(r,curve.g)
    S = scalar_mult(r,Qa)

    print("Random value: ", r)
    print("rG: ", rG)

    print("\n\n======Symmetric key========")

    print("Encryption key:",S[0],str(S[0]))
    # password='hello'

    key = hashlib.sha256(str(S[0]).encode()).digest()

    message = Padding.appendPadding(message,blocksize=Padding.AES_blocksize,mode=0)

    ciphertext = encrypt(message.encode(),key,AES.MODE_ECB)




    print("Encrypted:\t",binascii.hexlify(ciphertext))


    Snew = scalar_mult(dA,rG)
    key = hashlib.sha256(str(Snew[0]).encode()).digest()

    text = decrypt(ciphertext,key,AES.MODE_ECB)


    print("Decrypted:\t",Padding.removePadding(text.decode(),mode=0))

if __name__ == "__main__":
    main()