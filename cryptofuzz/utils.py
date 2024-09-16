import binascii
import unicodedata
import os, re, hashlib
import random
import struct
import sys
import ecdsa
from typing import Union, Tuple, Optional, AnyStr
from functools import lru_cache as LR_CACHE
from .bs58 import b58encode, b58decode, base58_check_encode, base58encodeCheck, base58decode, base58encode
from hdwallet import HDWallet as HD_W
from hdwallet.symbols import BTC, ETH, TRX, LTC, DOGE, DGB, BTG, RVN, QTUM, DASH, ZEC, BCH, AXE
from Crypto.Hash import keccak
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

    # --- Check Valid Private Key
    def checkValid(self, key: int) -> bool:
        if 0 < key < MAX_PRIVATE_KEY:
            return True
        else:
            raise ValueError(f"Secret Scalar Must be greater than 0 and less than {MAX_PRIVATE_KEY}.")

    # --- Generate a random Private Key
    def generate_private_key(self) -> str:
        randkey = "".join(random.choice("0123456789abcdef") for _ in range(64))
        if self.checkValid(int(randkey, 16)):
            return randkey
        else:
            return self.generate_private_key()

    # --- Generate a random XPRV
    def generate_xprv(self):
        rand = os.urandom(32)
        return "xprv" + binascii.hexlify(rand).decode('utf-8')

    # --- Generate a random Decimal
    def generate_decimal(self) -> int:
        return random.randint(0, MAX_PRIVATE_KEY)

    # --- Generate a random Binary
    def generate_binary(self) -> str:
        return "".join(random.choice("01") for _ in range(256))

    # --- Generate Entropy
    def generate_entropy(self, entropy_bits=256):
        entropy = os.urandom(entropy_bits // 8)
        checksum = hashlib.sha256(entropy).digest()[0]
        entropy_with_checksum = entropy + bytes([checksum])
        return entropy_with_checksum

    # --- Generate Mnemonic
    def generate_mnemonic(self, size: int = 12) -> str:
        characters = re.findall('[A-Z][a-z]+', BIP39)
        return " ".join(random.choices(characters, k=size)).lower()

    # --- Generate Short Key
    def generate_short_key(self):
        return ('%s%s' % ('S', ''.join(
            [BASE58_ALPHABET[random.randrange(0, len(BASE58_ALPHABET))] for i in range(29)])))


class Convertor:
    def __init__(self):
        self.gen = Generator()

    # --- SHA256 ---
    def _sha256(self, data):
        if isinstance(data, bytes):
            return hashlib.sha256(data).digest()
        elif isinstance(data, str):
            return hashlib.sha256(data.encode('utf-8')).digest()
        else:
            raise TypeError("data must be bytes or str")

    # --- Double Sha256 ---
    def double_sha256(self, data):
        return self._sha256(self._sha256(data))

    # --- Mnemonic ---
    def mne_to_seed(self, mnemonic, password=""):
        salt = ("mnemonic" + password).encode('utf-8')
        seed = hashlib.pbkdf2_hmac('sha512', mnemonic.encode('utf-8'), salt, 2048)
        return seed[:32]

    # --- Mnemonic To Bytes
    def mne_to_bytes(self, mnemonic):
        """
        Convert mnemonic words to bytes.

        - **mnemonic** (`str`): Mnemonic words.

        - **return bytes**: Mnemonic bytes.

        :param mnemonic: Mnemonic words.
        :type mnemonic: str

        :returns: bytes -- Mnemonic bytes.
        :rtype: bytes

        --------

        More Detail's Refer To Official **CryptoFuzz**  `Documentation <https://cryptofuzz.readthedocs.io/en/latest/#mnemonic>`_

        """
        return self.mne_to_seed(mnemonic)

    # --- Mnemonic To Hex
    def mne_to_hex(self, mnemonic):
        """
        Convert mnemonic words to hex.

        - **mnemonic** (`str`): Mnemonic words.

        - **return str**: Mnemonic hex.

        :param mnemonic: Mnemonic words.
        :type mnemonic: str

        :returns: str -- Mnemonic hex.
        :rtype: str

        --------

        More Detail's Refer To Official **CryptoFuzz**  `Documentation <https://cryptofuzz.readthedocs.io/en/latest/#mnemonic>`_

        """
        seed = self.mne_to_seed(mnemonic)
        return self.bytes_to_hex(seed)

    # --- Mnemonic To WIF
    def mne_to_wif(self, mnemonic, compress: bool = False):
        """
        Convert mnemonic words to wallet import format.

        - **mnemonic** (`str`): Mnemonic words.

        - **compress** (`bool`): Compress private key.

        - **return str**: Mnemonic wallet import format.

        :param mnemonic: Mnemonic words.
        :type mnemonic: str
        :param compress: Compress private key.
        :type compress: bool

        :returns: str -- Mnemonic wallet import format.
        :rtype: str

        --------

        More Detail's Refer To Official **CryptoFuzz**  `Documentation <https://cryptofuzz.readthedocs.io/en/latest/#mnemonic>`_

        """
        return self.bytes_to_wif(self.mne_to_seed(mnemonic), compress)

    # --- Mnemonic To Int
    def mne_to_int(self, mnemonic):
        """
        Convert mnemonic words to integer.

        - **mnemonic** (`str`): Mnemonic words.

        - **return int**: Mnemonic integer.

        :param mnemonic: Mnemonic words.
        :type mnemonic: str

        :returns: int -- Mnemonic integer.
        :rtype: int

        --------

        More Detail's Refer To Official **CryptoFuzz**  `Documentation <https://cryptofuzz.readthedocs.io/en/latest/#mnemonic>`_

        """
        return self.bytes_to_int(self.mne_to_seed(mnemonic))

    # --- Mnemonic To Extended Public Key
    def mne_to_xpub(self, mnemonic):
        """
        Convert mnemonic words to extended public key.

        - **mnemonic** (`str`): Mnemonic words.

        - **return str**: Extended public key.

        :param mnemonic:
        :return str: -- Mnemonic extended public key.

        --------

        More Detail's Refer To Official **CryptoFuzz**  `Documentation <https://cryptofuzz.readthedocs.io/en/latest/#mnemonic>`_

        """
        if not mnemonic:
            raise ValueError("Mnemonic is required.")
        if not isinstance(mnemonic, str):
            raise ValueError("Mnemonic must be a string.")
        return self.bytes_to_xpub(self.mne_to_seed(mnemonic))

    # --- Mnemonic To Extended Private Key
    def mne_to_xprv(self, mnemonic):
        """
        Convert mnemonic words to extended private key.

        - **mnemonic** (`str`): Mnemonic words.

        :param mnemonic: Mnemonic words.
        :type mnemonic: str

        :returns: str -- Mnemonic extended private key.
        :rtype: str

        --------

        More Detail's Refer To Official **CryptoFuzz**  `Documentation <https://cryptofuzz.readthedocs.io/en/latest/#mnemonic>`_

        """
        if not mnemonic:
            raise ValueError("Mnemonic is required.")
        if not isinstance(mnemonic, str):
            raise ValueError("Mnemonic must be a string.")
        return self.bytes_to_xprv(self.mne_to_seed(mnemonic))

    # --- Mnemonic To Address
    def mne_to_addr(self, mnemonic, compress: bool = False):
        """
        Convert mnemonic words to address.

        - **mnemonic** (`str`): Mnemonic words.
        - **compress** (`bool`): Compress address.

        :param mnemonic: Mnemonic words.
        :type mnemonic: str
        :param compress: Compress address.
        :type compress: bool

        :returns: str -- Mnemonic address.
        :rtype: str

        --------

        More Detail's Refer To Official **CryptoFuzz**  `Documentation <https://cryptofuzz.readthedocs.io/en/latest/#mnemonic>`_

        """
        if not mnemonic:
            raise ValueError("Mnemonic is required.")
        if not isinstance(mnemonic, str):
            raise ValueError("Mnemonic must be a string.")
        return self.bytes_to_addr(
            self.mne_to_seed(mnemonic), compress)

    # --- Mnemonic To Binary
    def mne_to_binary(self, mnemonic):
        """
        Convert mnemonic words to binary.

        - **mnemonic** (`str`): Mnemonic words.

        :param mnemonic: Mnemonic words.
        :type mnemonic: str

        :returns: str -- Mnemonic binary.
        :rtype: str

        --------

        More Detail's Refer To Official **CryptoFuzz**  `Documentation <https://cryptofuzz.readthedocs.io/en/latest/#mnemonic>`_

        """
        return self.bytes_to_binary(self.mne_to_seed(mnemonic))

    # --- Mnemonic Check
    @LR_CACHE(maxsize=512)
    def is_mnemonic(self, mnemonic: str, lang: str = "english") -> bool:
        """
        Check mnemonic words (Default Language: English).

        - **mnemonic** (`str`): Mnemonic words.
        - **lang** (`str` - `Language`): Language of the mnemonic words (Default: **english**).
        - **languages** (`Standard`): english, french, italian, japanese, chinese_simplified, chinese_traditional, korean, spanish.


        :param mnemonic: Mnemonic words.
        :type mnemonic: str
        :param language: Language of the mnemonic words.
        :type language: str, Optional

        :returns: bool -- Mnemonic valid/invalid.
        :rtype: bool

        --------

        More Detail's Refer To Official **CryptoFuzz**  `Documentation <https://cryptofuzz.readthedocs.io/en/latest/#mnemonic>`_


        """
        # --- Check language ---
        if not lang:
            lang = "english"
        try:
            # --- Normalize and check mnemonic ---
            mnemo = unicodedata.normalize("NFKD", mnemonic)
            # --- Check if mnemonic is valid ---
            isValid = Mnemonic(language=lang).check(mnemonic=mnemo)
            return isValid

        except Exception as e:  # pylint: disable=broad-except
            print(f"\n\n + Error Validating Mnemonic:\t{e}")
            return False

    # --- Seed ---
    # --- Bytes To Mnemonic
    def bytes_to_mne(self, seed):
        """
        Convert bytes to mnemonic words.

        - **seed** (`bytes`): seed

        :param seed:
        :type seed: bytes
        :return: Mnemonic words (`str`)
        :rtype: str

        --------

        More Detail's Refer To Official **CryptoFuzz**  `Documentation <https://cryptofuzz.readthedocs.io/en/latest/>`__

        """
        return Mnemonic().to_mnemonic(seed)

    # --- Bytes To seed (legacy)
    def bytes_to_seed(self, seed):
        return hashlib.pbkdf2_hmac('sha512', seed, b'mnemonic', 2048)

    # --- Bytes To Hex
    def bytes_to_hex(self, seed):
        return binascii.hexlify(self.bytes_to_seed(seed)).decode('utf-8')

    # --- Hex To Bytes
    def unHexlify(self, h: str):
        return binascii.unhexlify(h)

    # --- Hex To Bytes
    def hex_to_bytes(self, hexed):
        return binascii.unhexlify(hexed)

    # --- Hex To Mnemonic
    def hex_to_mne(self, hexed: str) -> str:
        seed = self.hex_to_bytes(hexed)
        return self.bytes_to_mnemonic(seed)

    # --- Hex To WIF
    def hex_to_wif(self, hexed, compress: bool = False) -> str:
        return self.bytes_to_wif(self.hex_to_bytes(hexed), compress)

    # --- Hex To Xprv
    def hex_to_xprv(self, hexed: str) -> str:
        return self.bytes_to_xprv(self.hex_to_bytes(hexed))

    # --- Hex To Xpub
    def hex_to_xpub(self, hexed: str) -> str:
        return self.bytes_to_xpub(self.hex_to_bytes(hexed))

    # --- Hex To Int
    def hex_to_int(self, hexed: str) -> int:
        return int(hexed, 16)

    # --- Hex To Pub
    def hex_to_pub(self, hexed: str, compress: bool = False) -> bytes:
        if compress:
            return self.bytes_to_public(self.hex_to_bytes(hexed), True)
        else:
            return self.bytes_to_public(self.hex_to_bytes(hexed), False)

    # --- Hex To Addr
    def hex_to_addr(self, hexed: str, compress: bool = False) -> str:
        seed = self.hex_to_bytes(hexed)
        if compress:
            return self.bytes_to_addr(seed, True)
        else:
            return self.bytes_to_addr(seed, False)

    # --- Hex To Binary
    def hex_to_binary(self, hexed: str) -> str:
        return self.bytes_to_binary(self.hex_to_bytes(hexed))

    # --- Hex To SHA256
    def bytes_hex_sha256(self, seed):
        """
        Convert bytes to Private Key (sha256).

        - **seed** (`bytes`): seed

        :param seed:
        :type seed: bytes
        :return: Private Key (sha256) (`str`)
        :rtype: str

        --------

        More Detail's Refer To Official **CryptoFuzz**  `Documentation <https://cryptofuzz.readthedocs.io/en/latest/>`__

        """
        privatekey_int = self.bytes_to_int(seed)
        self.gen.checkValid(privatekey_int)
        pvkByte = privatekey_int.to_bytes(32, byteorder='big')
        return pvkByte.hex()

    # --- Bytes To Int
    def bytes_to_int(self, seed) -> int:
        """
        Convert bytes to Int.

        - **seed** (`bytes`): seed

        :param seed:
        :type seed: bytes
        :return: Int (`int`)
        :rtype: int

        --------

        More Detail's Refer To Official **CryptoFuzz**  `Documentation <https://cryptofuzz.readthedocs.io/en/latest/>`__

        """
        seed = self.bytes_to_seed(seed)
        return int.from_bytes(seed, byteorder='big')

    # --- Bytes To Pub
    def bytes_to_pub(self, seed_bytes: bytes) -> bytes:
        """
        Convert bytes to Public Key.

        - **seed_bytes** (`bytes`): seed bytes

        :param seed_bytes:
        :type seed_bytes: bytes
        :return: Public Key (`bytes`)
        :rtype: bytes

        """
        sk = ecdsa.SigningKey.from_string(seed_bytes[:32], curve=ecdsa.SECP256k1)
        vk = sk.get_verifying_key()
        pub = COMPRESSED_PREFIX2 + vk.to_string()[-32:] if vk.to_string()[-1] % 2 == 0 else b'\x03' + vk.to_string()[
                                                                                                      -32:]
        return pub

    # --- Bytes To Public Key
    def bytes_to_public(self, seed: bytes, compress: bool = True) -> bytes:
        """
        Convert bytes to Public Key.

        - **seed** (`bytes`): seed bytes
        - **compress** (`bool`): compress or not

        :param seed:
        :param compress:
        :type seed: bytes
        :type compress: bool
        :return: Public Key (`bytes`)
        :rtype: bytes

        -------------

        More Detail's Refer To Official **CryptoFuzz**  `Documentation <https://cryptofuzz.readthedocs.io/en/latest/>`__

        """
        sk = ecdsa.SigningKey.from_string(seed, curve=ecdsa.SECP256k1)
        vk = sk.get_verifying_key()
        if compress:
            prefix = COMPRESSED_PREFIX2 if vk.pubkey.point.y() % 2 == 0 else COMPRESSED_PREFIX
            return prefix + vk.to_string()[:32]
        else:
            return UNCOMPRESSED_PREFIX + vk.to_string()

    # --- Bytes To Xpub
    def bytes_to_xpub(self, seed: bytes, chain_code=None) -> str:
        """
        Convert bytes to Extended Public Key.

        - **seed** (`bytes`): seed bytes
        - **chain_code** (`bytes`): chain code


        :param seed:
        :param chain_code:
        :type seed: bytes.
        :type chain_code: bytes,
        :return: Extended Public Key (`str`)
        :rtype: str

        -------------

        More Detail's Refer To Official **CryptoFuzz**  `Documentation <https://cryptofuzz.readthedocs.io/en/latest/>`__

        """
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

    # --- Bytes To Mnemonic
    def bytes_to_mnemonic(self, byte: bytes):
        """
        Convert bytes to Mnemonic.

        - **byte** (`bytes`): bytes

        :type byte: bytes
        :return: Mnemonic (`str`)
        :rtype: str

        -------------

        More Detail's Refer To Official **CryptoFuzz**  `Documentation <https://cryptofuzz.readthedocs.io/en/latest/>`__

        """
        if len(byte) != 32:
            raise ValueError("Input bytes should have a length of 32.")

        seed = byte[:32]
        return Mnemonic("english").to_mnemonic(seed)

    # --- Bytes To Binary
    def bytes_to_binary(self, bytes_: bytes) -> str:
        """
        Convert bytes to Binary.

        - **bytes_** (`bytes`): bytes

        :type bytes_: bytes
        :return: Binary (`str`)
        :rtype: str

        -------------

        More Detail's Refer To Official **CryptoFuzz**  `Documentation <https://cryptofuzz.readthedocs.io/en/latest/>`__

        """
        if len(bytes_) != 32:
            raise ValueError("Input bytes should have a length of 32.")

        # Convert each byte to its binary representation and pad with zeros
        return ''.join(format(byte, '08b') for byte in bytes_)

    # --- Bytes To WIF
    def bytes_to_wif(self, private_key, compress=True):
        """
        Convert bytes to Wallet Import Format.(WIF) Compressed or Uncompressed.

        - **private_key** (`bytes`): private key
        - **compress** (`bool`): compress or not

        :type private_key: bytes
        :type compress: bool
        :return: WIF (`str`)
        :rtype: str

        -------------

        More Detail's Refer To Official **CryptoFuzz**  `Documentation <https://cryptofuzz.readthedocs.io/en/latest/#wif>`__

        """
        if compress:
            EXTENDED_KEY = MAIN_PREFIX + private_key + MAIN_SUFFIX
        else:
            EXTENDED_KEY = MAIN_PREFIX + private_key

        DOUBLE_SHA256 = self.double_sha256(EXTENDED_KEY)
        CHECKSUM = DOUBLE_SHA256[:4]

        WIF = b58encode(EXTENDED_KEY + CHECKSUM)

        return WIF.decode('utf-8')

    # --- Bytes To Xprv
    def bytes_to_xprv(self, bytes_code: bytes) -> str:
        """
        Convert bytes to Extended Private Key.

        - **bytes_code** (`bytes`): bytes code

        :type bytes_code: bytes
        :return: Extended Private Key (`str`)
        :rtype: str

        -------------

        More Detail's Refer To Official **CryptoFuzz**  `Documentation <https://cryptofuzz.readthedocs.io/en/latest/>`__
        """
        chain_code = bytes.fromhex(ZERO_BASE_NET)
        child_number = struct.pack('>L', 0)
        key = MAIN_DIGEST_RMD160 + bytes_code  # 0x00

        xprv_main = VERSION_NETWORK + MAIN_DIGEST_RMD160 + FINGERPRINT_RMD160 + child_number + chain_code + key
        decode_main = base58encodeCheck(b"", xprv_main)
        return decode_main

    # --- Bytes To Address
    def bytes_to_addr(self, seedBytes: bytes, compress: bool = False) -> str:
        """
        Convert bytes to Address Compressed or Uncompressed.

        - **seedBytes** (`bytes`): bytes
        - **compress** (`bool`): compress or not

        :type seedBytes: bytes
        :type compress: bool
        :return: Address (`str`)
        :rtype: str

        -------------

        More Detail's Refer To Official **CryptoFuzz**  `Documentation <https://cryptofuzz.readthedocs.io/en/latest/>`__

        """
        if len(seedBytes) != 32:
            seedBytes = seedBytes[:32]
        elif compress:
            pub = self.bytes_to_public(seedBytes, compress=True)
            return self.pub_to_addr(public_key=pub)
        else:
            pub = self.bytes_to_public(seedBytes, compress=False)
            return self.pub_to_addr(public_key=pub)

    # --- Passphrase ---
    # --- Passphrase To Hex
    def pass_to_hex(self, passphrase):
        """
        Convert Passphrase To Hex.

        - **passphrase** (`str`): Passphrase

        :type passphrase: str
        :return: Hex
        :rtype: str

        -------------

        More Detail's Refer To Official **CryptoFuzz**  `Documentation <https://cryptofuzz.readthedocs.io/en/latest/>`__

        """
        return hashlib.sha256(passphrase.encode()).hexdigest()

    # --- Passphrase To Bytes
    def pass_to_bytes(self, passphrase: str) -> bytes:
        """
        Convert Passphrase To Bytes.

        - **passphrase** (`str`): Passphrase

        :type passphrase: str
        :return: Bytes        :rtype:

        -------------

        More Detail's Refer To Official **CryptoFuzz**  `Documentation <https://cryptofuzz.readthedocs.io/en/latest/>`__

        """
        return bytes.fromhex(self.pass_to_hex(passphrase))

    # --- Passphrase To Address
    def pass_to_addr(self, passphrase, compress=False):
        """
        Convert Passphrase To Address.

        - **passphrase** (`str`): Passphrase
        - **compress** (`bool`): compress or not

        :type passphrase: str
        :type compress: bool
        :return: Address
        :rtype: str

        -------------

        More Detail's Refer To Official **CryptoFuzz**  `Documentation <https://cryptofuzz.readthedocs.io/en/latest/>`__

        """
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

    # --- Passphrase To WIF
    def pass_to_wif(self, passphrase, compress=False):
        """
        Convert Passphrase To WIF.

        - **passphrase** (`str`): Passphrase
        - **compress** (`bool`): compress or not

        :type passphrase: str
        :type compress: bool
        :return: WIF
        :rtype: str

        -------------

        More Detail's Refer To Official **CryptoFuzz**  `Documentation <https://cryptofuzz.readthedocs.io/en/latest/>`__

        """
        passBytes = self.pass_to_bytes(passphrase)
        return self.bytes_to_wif(passBytes, compress)

    # --- Passphrase To xprv
    def pass_to_xprv(self, passphrase):
        """
        Convert Passphrase To xprv.

        - **passphrase** (`str`): Passphrase

        :type passphrase: str
        :return: xprv
        :rtype: str

        -------------

        More Detail's Refer To Official **CryptoFuzz**  `Documentation <https://cryptofuzz.readthedocs.io/en/latest/>`__

        """
        passBytes = self.pass_to_bytes(passphrase)
        return self.bytes_to_xprv(passBytes)

    # --- Public Key ---
    # --- Public Key To Bytes
    def pub_to_bytes(self, pubkey, compress=True):
        """
        Convert Public Key To Bytes.

        - **pubkey** (`str`): Public Key
        - **compress** (`bool`): compress or not

        :type pubkey: str
        :type compress: bool
        :return: Bytes
        :rtype bytes:

        -------------

        More Detail's Refer To Official **CryptoFuzz**  `Documentation <https://cryptofuzz.readthedocs.io/en/latest/>`__

        """
        if compress:
            prefix = (COMPRESSED_PREFIX if pubkey.pubkey.point.y() & 1 else COMPRESSED_PREFIX2)
            return prefix + pubkey.pubkey.point.x().to_bytes(32, 'big')
        else:
            point_x = pubkey.pubkey.point.x().to_bytes(32, 'big')
            point_y = pubkey.pubkey.point.y().to_bytes(32, 'big')
            return UNCOMPRESSED_PREFIX + point_x + point_y

    # --- Public Key To Hex
    def pub_to_hex(self, pubkey, compress=True):
        """
        Convert Public Key To Hex.

        - **pubkey** (`str`): Public Key
        - **compress** (`bool`): compress or not

        :type pubkey: str
        :type compress: bool
        :return: Hex
        :rtype: str

        -------------

        More Detail's Refer To Official **CryptoFuzz**  `Documentation <https://cryptofuzz.readthedocs.io/en/latest/>`__

        """
        return self.pub_to_bytes(pubkey, compress).hex()

    # --- Public Key To Address
    def pub_to_addr(self, public_key: bytes) -> str:
        """
        Convert Public Key To Address.

        - **public_key** (`bytes`): Public Key

        :type public_key: bytes
        :return: Address
        :rtype: str

        -------------

        More Detail's Refer To Official **CryptoFuzz**  `Documentation <https://cryptofuzz.readthedocs.io/en/latest/>`__

        """
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(hashlib.sha256(public_key).digest())
        hashed = MAIN_DIGEST_RMD160 + ripemd160.digest()
        checksum = hashlib.sha256(hashlib.sha256(hashed).digest()).digest()[:4]
        address = hashed + checksum
        return b58encode(address).decode('utf-8')

    # --- WIF ---
    # --- WIF To Bytes
    def wif_to_bytes(self, wif):
        """
        Convert WIF To Bytes.

        - **wif** (`str`): WIF

        :type wif: str
        :return: Bytes
        :rtype: bytes

        -------------

        More Detail's Refer To Official **CryptoFuzz**  `Documentation <https://cryptofuzz.readthedocs.io/en/latest/>`__

        """
        wif_bytes = b58decode(wif)
        isCompress = wif_bytes[-5] == 0x01 if len(wif_bytes) == 38 else False
        return wif_bytes[1:-5] if isCompress else wif_bytes[1:-4]

    # --- WIF To Binary
    def wif_to_binary(self, wif: str) -> str:
        """
        Convert WIF To Binary.

        - **wif** (`str`): WIF

        :type wif: str
        :return: Binary
        :rtype: str

        -------------

        More Detail's Refer To Official **CryptoFuzz**  `Documentation <https://cryptofuzz.readthedocs.io/en/latest/>`__

        """
        pvkBytes = self.wif_to_bytes(wif)
        return self.bytes_to_binary(pvkBytes)

    # --- WIF To Address
    def wif_to_addr(self, wif: str, compress: bool = False) -> str:
        """
        Convert WIF To Address Compress and Uncompress.

        - **wif** (`str`): WIF
        - **compress** (`bool`): compress or not

        :type wif: str
        :type compress: bool
        :return: Address
        :rtype: str

        -------------

        More Detail's Refer To Official **CryptoFuzz**  `Documentation <https://cryptofuzz.readthedocs.io/en/latest/#wif>`__

        """
        pvkBytes = self.wif_to_bytes(wif)
        public_key = self.bytes_to_public(pvkBytes, compress)
        address = self.pub_to_addr(public_key)
        return address

    # --- WIF To Int
    def wif_to_int(self, wif):
        """
        Convert WIF To Int.

        - **wif** (`str`): WIF

        :type wif: str
        :return: Int
        :rtype: int

        -------------

        More Detail's Refer To Official **CryptoFuzz**  `Documentation <https://cryptofuzz.readthedocs.io/en/latest/>`__

        """
        return self.bytes_to_int(self.wif_to_bytes(wif))

    # --- WIF To Hex
    def wif_to_hex(self, wif):
        """
        Convert WIF To Hex.

        - **wif** (`str`): WIF

        :type wif: str
        :return: Hex
        :rtype: str

        -------------

        More Detail's Refer To Official **CryptoFuzz**  `Documentation <https://cryptofuzz.readthedocs.io/en/latest/#wif>`__

        """
        return self.wif_to_bytes(wif).hex()

    # --- WIF To Mnemonic
    def wif_to_mne(self, wif):
        """
        Convert WIF To Mnemonic.

        - **wif** (`str`): WIF

        :type wif: str
        :return: Mnemonic
        :rtype: str

        -------------

        More Detail's Refer To Official **CryptoFuzz**  `Documentation <https://cryptofuzz.readthedocs.io/en/latest/#wif>`__

        """

        seed = self.wif_to_bytes(wif)
        return self.bytes_to_mnemonic(seed)

    # --- WIF To xPrv
    def wif_to_xprv(self, wif):
        """
        Convert WIF To xPrv.

        - **wif** (`str`): WIF

        :type wif: str
        :return: xPrv
        :rtype: str

        -------------

        More Detail's Refer To Official **CryptoFuzz**  `Documentation <https://cryptofuzz.readthedocs.io/en/latest/#wif>`__

        """
        seed = self.wif_to_bytes(wif)
        return self.bytes_to_xprv(seed)

    # --- WIF To xPub
    def wif_to_xpub(self, wif):
        """
        Convert WIF To xPub.

        - **wif** (`str`): WIF

        :type wif: str
        :return: xPub
        :rtype: str

        -------------

        More Detail's Refer To Official **CryptoFuzz**  `Documentation <https://cryptofuzz.readthedocs.io/en/latest/#wif>`__

        """
        seed = self.wif_to_bytes(wif)
        return self.bytes_to_xpub(seed)

    # --- WIF To Pub
    def wif_to_pub(self, wif):
        """
        Convert WIF To Pub.

        - **wif** (`str`): WIF

        :type wif: str
        :return: Pub
        :rtype: str

        -------------

        More Detail's Refer To Official **CryptoFuzz**  `Documentation <https://cryptofuzz.readthedocs.io/en/latest/#wif>`__

        """
        seed = self.wif_to_bytes(wif)
        return self.bytes_to_public(seed).hex()

    # --- xprv ---
    def xprv_to_bytes(self, xprv: str):
        if not xprv.startswith("xprv") or len(xprv) <= 4:
            raise ValueError("Invalid xprv format.")
        xprv58 = xprv[4:]
        xprvBytes = base58decode(xprv58)
        return xprvBytes[:32]

    # --- xprv To Address
    def xprv_to_addr(self, xprv, compress: bool = False):
        seed = self.xprv_to_bytes(xprv)
        if compress:
            pub = self.bytes_to_public(seed, True)
            return self.pub_to_addr(pub)
        else:
            pub = self.bytes_to_public(seed, False)
            return self.pub_to_addr(pub)

    # --- xprv To Pub
    def xprv_to_pub(self, xprv, compress: bool = False):
        seed = self.xprv_to_bytes(xprv)
        if compress:
            return self.bytes_to_public(seed, True)
        else:
            return self.bytes_to_public(seed, False)

    # --- xprv To WIF
    def xprv_to_wif(self, xprv, compress: bool = False):
        seed = self.xprv_to_bytes(xprv)
        if compress:
            return self.bytes_to_wif(seed, True)
        else:
            return self.bytes_to_wif(seed, False)

    # --- xprv To Mnemonic
    def xprv_to_mne(self, xprv):
        seed = self.xprv_to_bytes(xprv)
        return self.bytes_to_mnemonic(seed)

    # --- Helpers ---

    # --- Binary To Bytes
    def binary_to_bytes(self, bin_str: str) -> bytes:
        if len(bin_str) != 256:
            raise ValueError("The binary string must have 256 characters.")
        chunks = [bin_str[i:i + 8] for i in range(0, len(bin_str), 8)]
        return bytes([int(chunk, 2) for chunk in chunks])

    # --- Int To Bytes
    def int_to_bytes(self, int_dec: int) -> bytes:
        return int_dec.to_bytes(32, 'big')

    # --- Int To Hex (unkown)
    def int_to_hex(self, int_dec: int) -> str:
        return "%064x" % int_dec

    # --- Int To Mnemonic
    def int_to_mnemonic(self, int_dec: int) -> str:
        seed = self.int_to_bytes(int_dec)
        return self.bytes_to_mnemonic(seed)

    # --- Int To WIF
    def int_to_wif(self, int_dec: int, compress: bool = False) -> str:
        return self.bytes_to_wif(self.int_to_bytes(int_dec), compress)

    # --- Int To xPrv
    def int_to_xprv(self, int_dec: int) -> str:
        return self.bytes_to_xprv(self.int_to_bytes(int_dec))

    # --- Int To xPub
    def int_to_xpub(self, int_dec: int) -> str:
        return self.bytes_to_xpub(self.int_to_bytes(int_dec))

    # --- Int To Address
    def int_to_addr(self, int_dec: int, compress: bool = False) -> str:
        """
        Convert int decimal to compress & uncompress address (``str``).

        -**int_dec** (`int`): Int decimal.
        -**compress** (`bool`): Compress or not.

        :param int_dec:
        :type int_dec: int
        :param compress:
        :type compress: bool
        :return:
        :rtype: str

        --------

        More Detail's Refer To Official **CryptoFuzz**  `Documentation <https://cryptofuzz.readthedocs.io/en/latest/>`__
        """
        return self.bytes_to_addr(self.int_to_bytes(int_dec), compress)

    # --- Int To Binary
    def int_to_binary(self, int_dec: int) -> str:
        return self.bytes_to_binary(self.int_to_bytes(int_dec))

    # --- Short Key (Mini Private Key)

    # --- Short To Bytes
    def short_to_bytes(self, short_str: str) -> bytes:
        """
        Convert a short string to bytes using SHA-256 hash.

        -**short_str** (`str`): A short string to be converted.

        :param short_str:
        :type short_str: str
        :return:
        :rtype: bytes

        --------

        More Detail's Refer To Official **CryptoFuzz**  `Documentation <https://cryptofuzz.readthedocs.io/en/latest/>`__

        """
        skey = hashlib.sha256(short_str.encode('utf-8')).hexdigest()
        return binascii.unhexlify(skey)

    # --- Short To Hex
    def short_to_hex(self, short_str: str) -> str:
        """
        Convert a short key to a hexadecimal string.

        -**short_str** (`str`): A short key to be converted.

        :param short_str: A short key to be converted.
        :type short_str: str
        :return: A hexadecimal string representation of the key.
        :rtype: str

        --------

        More Detail's Refer To Official **CryptoFuzz**  `Documentation <https://cryptofuzz.readthedocs.io/en/latest/>`__

        """
        bkey = self.short_to_bytes(short_str)
        if bkey.startswith(b"\x00"):
            return hashlib.sha256(short_str.encode('utf-8')).hexdigest()
        else:
            return self.bytes_to_hex(bkey)

    # --- Short To Int
    def short_to_int(self, short_str: str) -> int:
        """
        Convert a short string to an integer using SHA-256 hash.

        -**short_str** (`str`): A short string to be converted.

        :param short_str: A short string to be converted.
        :type short_str: str
        :return: An integer representation of the short string.
        :rtype: int

        --------

        More Detail's Refer To Official **CryptoFuzz**  `Documentation <https://cryptofuzz.readthedocs.io/en/latest/>`__

        """
        skey = hashlib.sha256(short_str.encode('utf-8')).hexdigest()
        return int(skey, 16)

    # --- Short To Address
    def short_to_addr(self, short_str: str, compress: bool = False) -> str:
        """
        Convert a short string to an address using SHA-256 hash.

        -**short_str** (`str`): A short string to be converted.
        -**compress** (`bool`): Compress or not.

        :param short_str: A short string to be converted.
        :type short_str: str
        :param compress: Compress or not.
        :type compress: bool
        :return: An address representation of the short string.
        :rtype: str

        --------

        More Detail's Refer To Official **CryptoFuzz**  `Documentation <https://cryptofuzz.readthedocs.io/en/latest/>`__

        """
        hex_key = self.short_to_hex(short_str)
        dec_key = int(hex_key, 16)
        if dec_key <= MAX_PRIVATE_KEY:
            return self.hex_to_addr(hex_key, compress)
        else:
            return self.int_to_addr(dec_key, compress)

    # --- Short To WIF
    def short_to_wif(self, short_str: str, compress: bool = False) -> str:
        """
        Convert a short string to a wallet import format using SHA-256 hash.

        -**short_str** (`str`): A short string to be converted.
        -**compress** (`bool`): Compress or not.

        :param short_str: A short string to be converted.
        :type short_str: str
        :param compress: Compress or not.
        :type compress: bool
        :return: A wallet import format representation of the short string.
        :rtype: str

        --------

        More Detail's Refer To Official **CryptoFuzz**  `Documentation <https://cryptofuzz.readthedocs.io/en/latest/>`__

        """
        pHex = self.short_to_hex(short_str)
        return self.hex_to_wif(pHex, compress)
