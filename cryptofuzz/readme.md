## `utils.py`


```python
import binascii
import os, re
import hashlib, pbkdf2, hmac
import hmac
import random
from hashlib import sha256 as SHA256, sha512 as SHA512, new as NEW
import ecdsa
from b58 import b58encode, b58encode_check, b58decode_check, b58decode
from bit import Key
from mnemonic import Mnemonic
from bit.format import bytes_to_wif
from assest import (
    MAIN_DIGEST_RMD160,
    MAIN_PREFIX,
    MAIN_SUFFIX,
    BIP39
)


def generate_entropy(entropy_bits=256):
    entropy = os.urandom(entropy_bits // 8)
    checksum = SHA256(entropy).digest()[0]
    entropy_with_checksum = entropy + bytes([checksum])
    return entropy_with_checksum


def mne_to_seed(mnemonic, password=""):
    salt = ("mnemonic" + password).encode('utf-8')
    seed = hashlib.pbkdf2_hmac('sha512', mnemonic.encode('utf-8'), salt, 2048)
    return seed[:64]


def generate_keypair(seed):
    sk = ecdsa.SigningKey.from_string(seed[:32], curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    return sk, vk


def pub_to_addr(pubkey, compressed=True):
    if compressed:
        if pubkey.to_string()[63] % 2 == 0:
            compressed_pub = b"\x02" + pubkey.to_string()[:32]
        else:
            compressed_pub = b"\x03" + pubkey.to_string()[:32]
    else:
        compressed_pub = b"\x04" + pubkey.to_string()

    ripemd160 = NEW('ripemd160')
    ripemd160.update(SHA256(compressed_pub).digest())
    raw_address = MAIN_DIGEST_RMD160 + ripemd160.digest()
    address = b58encode(raw_address + SHA256(SHA256(raw_address).digest()).digest()[:4])
    return address

def byte2Mne(byte: bytes): return Mnemonic("english").to_mnemonic(byte[:32])


def bytes2Wif(private_key, compress=True):
    PREFIX = MAIN_PREFIX
    if compress:
        EXTENDED_KEY = PREFIX + private_key + MAIN_SUFFIX
    else:
        EXTENDED_KEY = PREFIX + private_key

    FIRST_SHA256 = SHA256(EXTENDED_KEY).digest()
    DOUBLE_SHA256 = SHA256(FIRST_SHA256).digest()
    CHECKSUM = DOUBLE_SHA256[:4]

    WIF = b58encode(EXTENDED_KEY + CHECKSUM)

    return WIF.decode('utf-8')


def generate_mnemonic(size: int) -> str:
    characters = re.findall('[A-Z][a-z]+', BIP39)
    return " ".join(random.choices(characters, k=size)).lower()


word = generate_mnemonic(12)

seed = mne_to_seed(word)

private, public = generate_keypair(seed)

caddr = pub_to_addr(public, True)
uaddr = pub_to_addr(public, False)
print(word)
print(f"compress: {caddr}\nUncompress: {uaddr}\n{private.to_string()}")
```
