import binascii
import os, re, hashlib
import random
import struct
import ecdsa
from typing import Union
from .bs58 import b58encode, b58decode, base58_check_encode, base58encodeCheck, base58decode, base58encode
from hdwallet import HDWallet as HD_W
from hdwallet.symbols import BTC, ETH, TRX, LTC, DOGE, DGB, BTG, RVN, QTUM, DASH, ZEC, BCH, AXE
from mnemonic import Mnemonic
from .assest import (
    MAIN_DIGEST_RMD160,
    MAX_PRIVATE_KEY,
    MAIN_PREFIX,
    MAIN_SUFFIX,
    ZERO_BASE_NET,
    VERSION_NETWORK,
    BASE58_ALPHABET,
    FINGERPRINT_RMD160,
    COMPRESSED_PREFIX,
    COMPRESSED_PREFIX2,
    UNCOMPRESSED_PREFIX,
    MAIN_DIGEST,
    XPUB_PREFIX,
    ZERO_BYTES,
    BIP39
)


class Generator:
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
    
    def generate_xprv(self):
        return "xprv" + binascii.hexlify(os.urandom(32)).decode('utf-8')
    
    def generate_decimal(self) -> int: return random.randint(0, MAX_PRIVATE_KEY)
    def generate_binary(self) -> str:
        return "".join(random.choice("01") for _ in range(256))
    
    def generate_entropy(self, entropy_bits=256):
        entropy = os.urandom(entropy_bits // 8)
        checksum = hashlib.sha256(entropy).digest()[0]
        entropy_with_checksum = entropy + bytes([checksum])
        return entropy_with_checksum
    
    def generate_mnemonic(self, size: int) -> str:
        characters = re.findall('[A-Z][a-z]+', BIP39)
        return " ".join(random.choices(characters, k=size)).lower()


class Convertor:
    def __init__(self):
        super().__init__()
        self.gen = Generator()
    
    def double_sha256(self, data):
        return hashlib.sha256(hashlib.sha256(data).digest()).digest()
    
    def mne_to_seed(self, mnemonic, password=""):
        salt = ("mnemonic" + password).encode('utf-8')
        seed = hashlib.pbkdf2_hmac('sha512', mnemonic.encode('utf-8'), salt, 2048)
        return seed[:64]
    
    def unHexlify(self, h: str):
        return binascii.unhexlify(h)
    
    def hex_to_bytes(self, hexed):
        return binascii.unhexlify(hexed)
    
    def hex_to_int(self, hexed: str) -> int:
        return int(hexed, 16)
    
    def hex_to_pub(self, hexed: str, compress: bool = False) -> bytes:
        if compress:
            return self.bytes_to_public(self.hex_to_bytes(hexed), True)
        else:
            return self.bytes_to_public(self.hex_to_bytes(hexed), False)
    
    def hex_to_addr(self, hexed: str, compress: bool = False) -> str:
        pub = self.hex_to_pub(hexed)
        if compress:
            return self.pub_to_addr(pub)
        else:
            return self.pub_to_addr(pub)
    
    def bytes_to_hex(self, seed):
        privatekey_int = int.from_bytes(hashlib.sha256(seed).digest(), byteorder='big')
        self.gen.checkValid(privatekey_int)
        pvkByte = privatekey_int.to_bytes(32, byteorder='big')
        return pvkByte.hex()
    
    def bytes_to_int(self, seed) -> int:
        return int.from_bytes(seed, byteorder='big')
    
    def bytes_to_pub(self, seed_bytes: bytes) -> bytes:
        sk = ecdsa.SigningKey.from_string(seed_bytes[:32], curve=ecdsa.SECP256k1)
        vk = sk.get_verifying_key()
        pub = b'\x02' + vk.to_string()[-32:] if vk.to_string()[-1] % 2 == 0 else b'\x03' + vk.to_string()[-32:]
        return pub
    
    def bytes_to_public(self, seed: bytes, compress: bool = True) -> bytes:
        sk = ecdsa.SigningKey.from_string(seed, curve=ecdsa.SECP256k1)
        vk = sk.get_verifying_key()
        if compress:
            prefix = COMPRESSED_PREFIX2 if vk.pubkey.point.y() % 2 == 0 else COMPRESSED_PREFIX
            return prefix + vk.to_string()[:32]
        else:
            return UNCOMPRESSED_PREFIX + vk.to_string()
    
    def bytes_to_xpub(self, seed: bytes, chain_code=None) -> str:
        if chain_code is None:
            chain_code = os.urandom(32)  # .hex
        prefix = self.unHexlify(XPUB_PREFIX)
        FINGERPRINT = ZERO_BYTES + ZERO_BYTES
        pub = self.bytes_to_pub(seed)
        xpub = prefix + MAIN_DIGEST + FINGERPRINT + chain_code + pub
        Hash64 = self.double_sha256(xpub)
        xpub += Hash64[:4]
        xpubBase58 = b58encode(xpub)
        return xpubBase58.decode('utf-8')
    
    def bytes_to_mne(self, byte: bytes):
        seed = byte[:32]
        return Mnemonic("english").to_mnemonic(seed)
    
    def bytes_to_binary(self, bytes_: bytes) -> str:
        if len(bytes_) != 32:
            raise ValueError("Input bytes should have a length of 32.")
        
        # Convert each byte to its binary representation and pad with zeros
        return ''.join(format(byte, '08b') for byte in bytes_)
    
    def bytes_to_wif(self, private_key, compress=True):
        if compress:
            EXTENDED_KEY = MAIN_PREFIX + private_key + MAIN_SUFFIX
        else:
            EXTENDED_KEY = MAIN_PREFIX + private_key
        
        DOUBLE_SHA256 = self.double_sha256(EXTENDED_KEY)
        CHECKSUM = DOUBLE_SHA256[:4]
        
        WIF = b58encode(EXTENDED_KEY + CHECKSUM)
        
        return WIF.decode('utf-8')
    
    def bytes_to_xprv(self, bytes_code: bytes) -> str:
        chain_code = bytes.fromhex(ZERO_BASE_NET)
        child_number = struct.pack('>L', 0)
        key = MAIN_DIGEST_RMD160 + bytes_code  # 0x00
        
        xprv_main = VERSION_NETWORK + MAIN_DIGEST_RMD160 + FINGERPRINT_RMD160 + child_number + chain_code + key
        decode_main = base58encodeCheck(b"", xprv_main)
        return decode_main
    
    def bytes_to_addr(self, seedBytes: bytes, compress: bool = False) -> str:
        if compress:
            pub = self.bytes_to_public(seedBytes, compress=True)
            return self.pub_to_addr(public_key=pub)
        else:
            pub = self.bytes_to_public(seedBytes, compress=False)
            return self.pub_to_addr(public_key=pub)
    
    # ------------------------------------------------------------
    def pass_to_hex(self, passphrase):
        return hashlib.sha256(passphrase.encode()).hexdigest()
    
    def pass_to_bytes(self, passphrase: str) -> bytes:
        return bytes.fromhex(self.pass_to_hex(passphrase))
    
    def pass_to_addr(self, passphrase, compress=False):
        passBytes = self.pass_to_bytes(passphrase)
        sk = ecdsa.SigningKey.from_string(passBytes, curve=ecdsa.SECP256k1)
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
    
    def pass_to_wif(self, passphrase, compress=False):
        passBytes = self.pass_to_bytes(passphrase)
        return self.bytes_to_wif(passBytes, compress)
    
    def pass_to_xprv(self, passphrase):
        return self.bytes_to_xprv(self.pass_to_bytes(passphrase))
    
    # ------------------------------------------------------------
    
    def pub_to_bytes(self, pubkey, compress=True):
        if compress:
            prefix = (COMPRESSED_PREFIX if pubkey.pubkey.point.y() & 1 else COMPRESSED_PREFIX2)
            return prefix + pubkey.pubkey.point.x().to_bytes(32, 'big')
        else:
            point_x = pubkey.pubkey.point.x().to_bytes(32, 'big')
            point_y = pubkey.pubkey.point.y().to_bytes(32, 'big')
            return UNCOMPRESSED_PREFIX + point_x + point_y
    
    def pub_to_hex(self, pubkey, compress=True):
        return self.pub_to_bytes(pubkey, compress).hex()
    
    def pub_to_addr(self, public_key: bytes) -> str:
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(hashlib.sha256(public_key).digest())
        hashed = MAIN_DIGEST_RMD160 + ripemd160.digest()
        checksum = hashlib.sha256(hashlib.sha256(hashed).digest()).digest()[:4]
        address = hashed + checksum
        return b58encode(address).decode('utf-8')
    
    # ------------------------------------------------------------
    
    def wif_to_bytes(self, wif):
        wif_bytes = b58decode(wif)
        isCompress = wif_bytes[-5] == 0x01 if len(wif_bytes) == 38 else False
        return wif_bytes[1:-5] if isCompress else wif_bytes[1:-4]
    
    def wif_to_addr(self, wif: str, compress: bool = False) -> str:
        pvkBytes = self.wif_to_bytes(wif)
        public_key = self.bytes_to_public(pvkBytes, compress)
        address = self.pub_to_addr(public_key)
        return address
    
    # ------------------------------------------------------------
    
    def xprv_to_bytes(self, xprv: str):
        if not xprv.startswith("xprv") or len(xprv) <= 4:
            raise ValueError("Invalid xprv format.")
        xprv58 = xprv[4:]
        xprvBytes = base58decode(xprv58)
        return xprvBytes[:32]
    
    def xprv_to_addr(self, xprv, compress: bool = False):
        seed = self.xprv_to_bytes(xprv)
        if compress:
            pub = self.bytes_to_public(seed, True)
            return self.pub_to_addr(pub)
        else:
            pub = self.bytes_to_public(seed, False)
            return self.pub_to_addr(pub)
    
    def xprv_to_pub(self, xprv, compress: bool = False):
        seed = self.xprv_to_bytes(xprv)
        if compress:
            return self.bytes_to_public(seed, True)
        else:
            return self.bytes_to_public(seed, False)
    
    def xprv_to_wif(self, xprv, compress: bool = False):
        seed = self.xprv_to_bytes(xprv)
        if compress:
            return self.bytes_to_wif(seed, True)
        else:
            return self.bytes_to_wif(seed, False)
    
    def xprv_to_mne(self, xprv):
        seed = self.xprv_to_bytes(xprv)
        return self.bytes_to_mne(seed)
    
    # ------------------------------------------------------------
    
    def binary_to_bytes(self, bin_str: str) -> bytes:
        if len(bin_str) != 256:
            raise ValueError("The binary string must have 256 characters.")
        chunks = [bin_str[i:i + 8] for i in range(0, len(bin_str), 8)]
        return bytes([int(chunk, 2) for chunk in chunks])
    
    def int_to_bytes(self, int_dec: int) -> bytes:
        bytes_length = (int_dec.bit_length() + 7) // 8
        return int_dec.to_bytes(bytes_length, 'big')
    
    def int_to_hex(self, int_dec: int) -> str:
        return "%064x" % int_dec
