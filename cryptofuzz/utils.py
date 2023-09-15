import binascii
import os, re, hashlib
import hmac
import random
import ecdsa
from .bs58 import b58encode, b58encode_check, b58decode_check, b58decode, base58_check_encode, base58_encode
from mnemonic import Mnemonic
from .assest import (
    MAIN_DIGEST_RMD160,
    MAX_PRIVATE_KEY,
    MAIN_PREFIX,
    MAIN_SUFFIX,
    COMPRESSED_PREFIX,
    COMPRESSED_PREFIX2,
    UNCOMPRESSED_PREFIX,
    BIP39
)


class Generate:
    def __init__(self):
        super().__init__()

    def checkValid(self, key: int) -> bool:
        if 0 < key < MAX_PRIVATE_KEY:
            return True
        else:
            raise ValueError(f"Secret Scalar Must be greater than 0 and less than {MAX_PRIVATE_KEY}.")

    def generate_private_key(self) -> str:
        randkey = "".join(random.choice("0123456789abcdef") for _ in range(64))
        if self.checkValid(int(randkey, 16)):
            return randkey
        else:
            return self.generate_private_key()

    def generate_xprv(self) -> str:
        seed = os.urandom(32)
        return "xprv" + binascii.hexlify(seed).decode('utf-8')

    def generate_entropy(self, entropy_bits=256):
        entropy = os.urandom(entropy_bits // 8)
        checksum = hashlib.sha256(entropy).digest()[0]
        entropy_with_checksum = entropy + bytes([checksum])
        return entropy_with_checksum

    def generate_mnemonic(self, size: int) -> str:
        characters = re.findall('[A-Z][a-z]+', BIP39)
        return " ".join(random.choices(characters, k=size)).lower()


class Convert:
    def __init__(self):
        super().__init__()
        self.gen = Generate()

    def double_sha256(self, data): return hashlib.sha256(hashlib.sha256(data).digest()).digest()

    def mne_to_seed(self, mnemonic, password=""):
        salt = ("mnemonic" + password).encode('utf-8')
        seed = hashlib.pbkdf2_hmac('sha512', mnemonic.encode('utf-8'), salt, 2048)
        return seed[:64]

    def hex_to_bytes(self, hexed): return bytes.fromhex(hexed)

    def byte_to_hex(self, seed):
        privatekey_int = int.from_bytes(hashlib.sha256(seed).digest(), byteorder='big')
        self.gen.checkValid(privatekey_int)
        return privatekey_int.to_bytes(32, byteorder='big')

    def bytes_to_pub(self, seed):
        sk = ecdsa.SigningKey.from_string(seed, curve=ecdsa.SECP256k1)
        return sk.get_verifying_key()

    def byte_to_keys(self, seed_bytes: bytes):
        """
        convert bytes seed to private key bytes ans public key bytes.

        >>> private, public = byte_to_keys(seed_bytes)
        >>> privatekey = private.to_string()
        >>> publickey = public.to_string()

        :param: seed_bytes
        :return: signing_key, verifying_key.
        """
        sk = ecdsa.SigningKey.from_string(seed_bytes[:32], curve=ecdsa.SECP256k1)
        vk = sk.get_verifying_key()
        return sk, vk

    def pub_to_addr(self, pubkey, compress=True):
        if compress:
            if pubkey.to_string()[63] % 2 == 0:
                compressed_pub = b"\x02" + pubkey.to_string()[:32]
            else:
                compressed_pub = b"\x03" + pubkey.to_string()[:32]
        else:
            compressed_pub = b"\x04" + pubkey.to_string()

        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(hashlib.sha256(compressed_pub).digest())
        raw_address = MAIN_DIGEST_RMD160 + ripemd160.digest()
        address = b58encode(raw_address + self.double_sha256(raw_address)[:4])
        return address.decode('utf-8')

    def pub_to_bytes(self, pubkey, compress=True):
        if compress:
            prefix = (b'\x03' if pubkey.pubkey.point.y() & 1 else b'\x02')
            return prefix + pubkey.pubkey.point.x().to_bytes(32, 'big')
        else:
            return b'\x04' + pubkey.pubkey.point.x().to_bytes(32, 'big') + pubkey.pubkey.point.y().to_bytes(32, 'big')

    def pub_to_hex(self, pubkey, compress=True):
        return self.pub_to_bytes(pubkey, compress).hex()

    def byte_to_mne(self, byte: bytes):
        return Mnemonic("english").to_mnemonic(byte[:32])

    def byte_to_wif(self, private_key, compress=True):
        PREFIX = MAIN_PREFIX
        if compress:
            EXTENDED_KEY = PREFIX + private_key + MAIN_SUFFIX
        else:
            EXTENDED_KEY = PREFIX + private_key

        DOUBLE_SHA256 = self.double_sha256(EXTENDED_KEY)
        CHECKSUM = DOUBLE_SHA256[:4]

        WIF = b58encode(EXTENDED_KEY + CHECKSUM)

        return WIF.decode('utf-8')

    def pass_To_addr(self, passphrase, compress=False):
        priv_key_hex = hashlib.sha256(passphrase.encode()).hexdigest()
        sk = ecdsa.SigningKey.from_string(bytes.fromhex(priv_key_hex), curve=ecdsa.SECP256k1)
        vk = sk.verifying_key
        if compress:
            if vk.pubkey.point.y() & 1:
                pub_key = COMPRESSED_PREFIX + vk.to_string()[:32]
            else:
                pub_key = COMPRESSED_PREFIX2 + vk.to_string()[:32]
        else:
            pub_key = UNCOMPRESSED_PREFIX + vk.to_string()
        sha = hashlib.sha256(pub_key).digest()
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha)

        address = base58_check_encode(ripemd160.digest())
        return "1" + address

    def xprv_to_bytes(self, xprv):
        return binascii.unhexlify(xprv[4:])[:32]

    def xprv_to_addr(self, xprv, compress: bool = False):
        seed = self.xprv_to_bytes(xprv)
        pub = self.bytes_to_pub(seed)
        if compress:
            return self.pub_to_addr(pub, True)
        else:
            return self.pub_to_addr(pub, False)


