from Crypto.Hash import keccak
from hmac import new as _new
from hashlib import (
    pbkdf2_hmac as _pbkdf2_hmac,
    sha256 as _sha256
)
from base64 import (
    urlsafe_b64encode as _urlsafe_b64encode,
    urlsafe_b64decode as _urlsafe_b64decode
)
from .bs58 import b58encode_check
from .utils import (
    re,
    HD_W,
    BTC,
    ETH,
    TRX,
    DGB,
    DOGE,
    DASH,
    BTG,
    RVN,
    ZEC,
    QTUM,
    LTC,
    AXE,
    ecdsa,
    hashlib,
    MAX_PRIVATE_KEY
)

CRC16_TAB = [
    0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50A5, 0x60C6, 0x70E7,
    0x8108, 0x9129, 0xA14A, 0xB16B, 0xC18C, 0xD1AD, 0xE1CE, 0xF1EF,
    0x1231, 0x0210, 0x3273, 0x2252, 0x52B5, 0x4294, 0x72F7, 0x62D6,
    0x9339, 0x8318, 0xB37B, 0xA35A, 0xD3BD, 0xC39C, 0xF3FF, 0xE3DE,
    0x2462, 0x3443, 0x0420, 0x1401, 0x64E6, 0x74C7, 0x44A4, 0x5485,
    0xA56A, 0xB54B, 0x8528, 0x9509, 0xE5EE, 0xF5CF, 0xC5AC, 0xD58D,
    0x3653, 0x2672, 0x1611, 0x0630, 0x76D7, 0x66F6, 0x5695, 0x46B4,
    0xB75B, 0xA77A, 0x9719, 0x8738, 0xF7DF, 0xE7FE, 0xD79D, 0xC7BC,
    0x48C4, 0x58E5, 0x6886, 0x78A7, 0x0840, 0x1861, 0x2802, 0x3823,
    0xC9CC, 0xD9ED, 0xE98E, 0xF9AF, 0x8948, 0x9969, 0xA90A, 0xB92B,
    0x5AF5, 0x4AD4, 0x7AB7, 0x6A96, 0x1A71, 0x0A50, 0x3A33, 0x2A12,
    0xDBFD, 0xCBDC, 0xFBBF, 0xEB9E, 0x9B79, 0x8B58, 0xBB3B, 0xAB1A,
    0x6CA6, 0x7C87, 0x4CE4, 0x5CC5, 0x2C22, 0x3C03, 0x0C60, 0x1C41,
    0xEDAE, 0xFD8F, 0xCDEC, 0xDDCD, 0xAD2A, 0xBD0B, 0x8D68, 0x9D49,
    0x7E97, 0x6EB6, 0x5ED5, 0x4EF4, 0x3E13, 0x2E32, 0x1E51, 0x0E70,
    0xFF9F, 0xEFBE, 0xDFDD, 0xCFFC, 0xBF1B, 0xAF3A, 0x9F59, 0x8F78,
    0x9188, 0x81A9, 0xB1CA, 0xA1EB, 0xD10C, 0xC12D, 0xF14E, 0xE16F,
    0x1080, 0x00A1, 0x30C2, 0x20E3, 0x5004, 0x4025, 0x7046, 0x6067,
    0x83B9, 0x9398, 0xA3FB, 0xB3DA, 0xC33D, 0xD31C, 0xE37F, 0xF35E,
    0x02B1, 0x1290, 0x22F3, 0x32D2, 0x4235, 0x5214, 0x6277, 0x7256,
    0xB5EA, 0xA5CB, 0x95A8, 0x8589, 0xF56E, 0xE54F, 0xD52C, 0xC50D,
    0x34E2, 0x24C3, 0x14A0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
    0xA7DB, 0xB7FA, 0x8799, 0x97B8, 0xE75F, 0xF77E, 0xC71D, 0xD73C,
    0x26D3, 0x36F2, 0x0691, 0x16B0, 0x6657, 0x7676, 0x4615, 0x5634,
    0xD94C, 0xC96D, 0xF90E, 0xE92F, 0x99C8, 0x89E9, 0xB98A, 0xA9AB,
    0x5844, 0x4865, 0x7806, 0x6827, 0x18C0, 0x08E1, 0x3882, 0x28A3,
    0xCB7D, 0xDB5C, 0xEB3F, 0xFB1E, 0x8BF9, 0x9BD8, 0xABBB, 0xBB9A,
    0x4A75, 0x5A54, 0x6A37, 0x7A16, 0x0AF1, 0x1AD0, 0x2AB3, 0x3A92,
    0xFD2E, 0xED0F, 0xDD6C, 0xCD4D, 0xBDAA, 0xAD8B, 0x9DE8, 0x8DC9,
    0x7C26, 0x6C07, 0x5C64, 0x4C45, 0x3CA2, 0x2C83, 0x1CE0, 0x0CC1,
    0xEF1F, 0xFF3E, 0xCF5D, 0xDF7C, 0xAF9B, 0xBFBA, 0x8FD9, 0x9FF8,
    0x6E17, 0x7E36, 0x4E55, 0x5E74, 0x2E93, 0x3EB2, 0x0ED1, 0x1EF0
]


def is_valid_hex(hexstring: str) -> bool:
    return re.match("^[a-fA-F0-9]*$", hexstring) is not None


class Bitcoin:
    def __int__(self):
        super().__init__()

    def hex_addr(self, hexed: str, Type: str = 'p2pkh') -> str:
        """
        Convert Private key Hex To All Bitcoin Format Type Addresses, Type: `p2pkh`, `p2sh`, `p2wpkh`, `p2wsh`, `p2wpkh_p2sh`, `p2wsh_p2sh`.
        """
        if is_valid_hex(hexed):
            hd: HD_W = HD_W(BTC)
            hd.from_private_key(hexed)
            if Type == 'p2pkh':
                return hd.p2pkh_address()
            elif Type == 'p2sh':
                return hd.p2sh_address()
            elif Type == 'p2wpkh':
                return hd.p2wpkh_address()
            elif Type == 'p2wsh':
                return hd.p2wsh_address()
            elif Type == 'p2wpkh_p2sh':
                return hd.p2wpkh_in_p2sh_address()
            elif Type == 'p2wsh_p2sh':
                return hd.p2wsh_in_p2sh_address()
            else:
                return hd.p2pkh_address()
        else:
            ValueError("hex format invalid check again.[format: hex][64 length]")


class Ethereum:
    def __int__(self):
        super().__init__()

    def hex_addr(self, hexed: str) -> str:
        """
        Convert Private key Hex To All Ethereum Format Type Address .
        :param hexed:
        :rtype str:
        :return: str - address
        """
        if is_valid_hex(hexed):
            hd: HD_W = HD_W(ETH)
            hd.from_private_key(hexed)
            return hd.p2pkh_address()
        else:
            ValueError("hex format invalid check again.[format: hex][64 length]")


class Tron:
    def __init__(self):
        super().__init__()

    @staticmethod
    def byte_to_primitive(seed: bytes) -> bytes:
        """Convert seed bytes to primitive bytes."""
        if len(seed) != 32:
            raise ValueError("Invalid seed length")
        # -- Signing Key --
        sk = ecdsa.SigningKey.from_string(seed, curve=ecdsa.SECP256k1)
        # -- Verifying Key --
        key = sk.get_verifying_key()
        # -- Private Key String --
        KEY = key.to_string()
        # -- Keccak Hash --
        Keccak = keccak.new(digest_bits=256)
        Keccak.update(KEY)
        # -- Public Key --
        pub_key = Keccak.digest()
        # -- Primitive Address Bytes --
        primitive = b'\x41' + pub_key[-20:]
        return primitive

    def bytes_to_addr(self, seed: bytes) -> str:  # noqa
        """Convert seed bytes to address string."""
        primitive = self.byte_to_primitive(seed)
        return b58encode_check(primitive).decode("utf-8")

    def bytes_to_hex_addr(self, seed: bytes) -> str:  # noqa
        """Convert seed bytes to hex address string."""
        primitive = self.byte_to_primitive(seed)
        return primitive.hex()

    def hex_to_addr(self, hexed: str) -> str:
        """Convert hex string to address string."""
        seed = bytes.fromhex(hexed)
        return self.bytes_to_addr(seed)

    def dec_to_addr(self, dec: int) -> str:
        """Convert decimal integer to address string."""
        if dec >= MAX_PRIVATE_KEY:
            raise ValueError(f"\nInvalid Decimal Value for Private Key, Must be Less Than {MAX_PRIVATE_KEY}\n")
        seed = int.to_bytes(dec, 32, 'big')
        return self.bytes_to_addr(seed)

    def hex_addr(self, hexed: str) -> str:
        """Convert hex string to address string."""
        return self.hex_to_addr(hexed)

    def pvk_to_hex_addr(self, pvk: str) -> str:
        """Convert hex string to Hex Tron Address string."""
        seed = bytes.fromhex(pvk)
        primitive = self.byte_to_primitive(seed)
        return primitive.hex()


class DigiByte:
    def __int__(self):
        super().__init__()

    def hex_addr(self, hexed: str) -> str:
        """
        Convert Private key Hex To DigiByte Address.

        :param hexed:
        :rtype str:
        :return: Str - address

        """
        if is_valid_hex(hexed):
            hd: HD_W = HD_W(DGB)
            hd.from_private_key(hexed)
            return hd.p2pkh_address()
        else:
            ValueError("hex format invalid check again.[format: hex][64 length]")


class Dogecoin:
    def __int__(self):
        super().__init__()

    def hex_addr(self, hexed: str, Type: str = 'p2pkh') -> str:
        """
        Generate Private key Hex Address To All Dogecoin Format Type Address , Type: `p2pkh`, `p2sh`.

        :param hexed:
        :type hexed: str
        :param Type:
        :type Type: str
        :rtype: str
        :return: str - address

        """

        if is_valid_hex(hexed):
            hd: HD_W = HD_W(DOGE)
            hd.from_private_key(hexed)
            if Type == 'p2pkh':
                return hd.p2pkh_address()
            elif Type == 'p2sh':
                return hd.p2sh_address()
            else:
                return hd.p2pkh_address()
        else:
            ValueError("hex format invalid check again.[format: hex][64 length]")


class Dash:
    def __int__(self):
        super().__init__()

    def hex_addr(self, hexed: str) -> str:
        """
        Convert Private key Hex To All Dash Address .
        :param hexed:
        :rtype str:
        :return: Str - address
        """
        if is_valid_hex(hexed):
            hd: HD_W = HD_W(DASH)
            hd.from_private_key(hexed)
            return hd.p2pkh_address()
        else:
            ValueError("hex format invalid check again.[format: hex][64 length]")


class BitcoinGold:
    def __int__(self):
        super().__init__()

    def hex_addr(self, hexed: str, Type: str = "p2pkh") -> str:
        """

        Convert Private key Hex To All BitcoinGold Format Type Address , Type: `p2pkh`, `p2sh`, `p2wpkh`, `p2wsh`, `p2wpkh_p2sh`, `p2wsh_p2sh`.

        :param hexed:
        :type hexed: Str.
        :param Type:
        :type Type: Str.
        :rtype: Str.
        :return address:


        --------------------------------------------------------------

        >>> btg = BitcoinGold()
        >>> privatekey = "0A9796542F1030931E317...............960DC79C48D20102F6A45517"
        >>> p2pkh_address = btg.hex_addr(privatekey, "p2pkh")
        >>> p2sh_address = btg.hex_addr(privatekey, "p2sh")
        >>> p2wpkh_address = btg.hex_addr(privatekey, "p2wpkh")
        >>> p2wsh_address = btg.hex_addr(privatekey, "p2wsh")
        >>> p2wpkh_in_p2sh_address = btg.hex_addr(privatekey, "p2wpkh_p2sh")
        >>> p2wsh_in_p2sh_address = btg.hex_addr(privatekey, "p2wsh_p2sh")

        --------------------------------------------------------------


        """
        if is_valid_hex(hexed):
            hd: HD_W = HD_W(BTG)
            hd.from_private_key(hexed)
            if Type == "p2pkh":
                return hd.p2pkh_address()
            elif Type == "p2sh":
                return hd.p2sh_address()
            elif Type == "p2wpkh":
                return hd.p2wpkh_address()
            elif Type == "p2wsh":
                return hd.p2wsh_address()
            elif Type == "p2wpkh_p2sh":
                return hd.p2wpkh_in_p2sh_address()
            elif Type == "p2wsh_p2sh":
                return hd.p2wsh_in_p2sh_address()
            else:
                return hd.p2pkh_address()
        else:
            ValueError("hex format invalid check again.[format: hex][64 length]")


class Ravencoin:
    def __int__(self):
        super().__init__()

    def hex_addr(self, hexed: str) -> str:
        """
        Convert Private key Hex To All Ravencoin Format Type Address .
        :param hexed:
        :rtype str:
        :return: str - address
        """
        if is_valid_hex(hexed):
            hd: HD_W = HD_W(RVN)
            hd.from_private_key(hexed)
            return hd.p2pkh_address()
        else:
            ValueError("hex format invalid check again.[format: hex][64 length]")


class Zcash:
    def __int__(self):
        super().__init__()

    def hex_addr(self, hexed: str) -> str:
        """
        Convert Private key Hex To All Zcash Format Type Address .
        :param hexed:
        :rtype str:
        :return: str - address
        """
        if is_valid_hex(hexed):
            hd: HD_W = HD_W(ZEC)
            hd.from_private_key(hexed)
            return hd.p2pkh_address()
        else:
            ValueError("hex format invalid check again.[format: hex][64 length]")


class Qtum:
    def __int__(self):
        super().__init__()

    def hex_addr(self, hexed: str) -> str:
        """
        Convert Private key Hex To All Qtum Format Type Address .
        :param hexed:
        :rtype str:
        :return: str - address
        """
        if is_valid_hex(hexed):
            hd: HD_W = HD_W(QTUM)
            hd.from_private_key(hexed)
            return hd.p2pkh_address()
        else:
            ValueError("hex format invalid check again.[format: hex][64 length]")


class Litecoin:
    def __int__(self):
        super().__init__()

    def hex_addr(self, hexed: str, Type: str = 'p2pkh') -> str:
        """

        ------------------------------------------
        Convert Private key Hex To All Litecoin Format Type Address , Type: `p2pkh`, `p2sh`, `p2wpkh`, `p2wsh`, `p2wpkh_p2sh`, `p2wsh_p2sh`.
        :param hexed:
        :type hexed: str.
        :param Type:
        :type Type: str.
        :returns: address.

        ------------------------------------------

        >>> ltc = Litecoin()
        >>> privatekey = "e3b0c44298fc1c149..................."
        >>> p2pkh_address = ltc.hex_addr(privatekey, 'p2pkh')
        >>> p2sh_address = ltc.hex_addr(privatekey, 'p2sh')
        >>> p2wpkh_address = ltc.hex_addr(privatekey, 'p2wpkh')
        >>> p2wsh_address = ltc.hex_addr(privatekey, 'p2wsh')
        >>> p2wpkh_p2sh_address = ltc.hex_addr(privatekey, 'p2wpkh_p2sh')
        >>> p2wsh_p2sh_address = ltc.hex_addr(privatekey, 'p2wsh_p2sh')

        ------------------------------------------



        """

        if is_valid_hex(hexed):
            hd: HD_W = HD_W(LTC)
            hd.from_private_key(hexed)
            if Type == 'p2pkh':
                return hd.p2pkh_address()
            elif Type == 'p2sh':
                return hd.p2sh_address()
            elif Type == 'p2wpkh':
                return hd.p2wpkh_address()
            elif Type == 'p2wsh':
                return hd.p2wsh_address()
            elif Type == 'p2wpkh_p2sh':
                return hd.p2wpkh_in_p2sh_address()
            elif Type == 'p2wsh_p2sh':
                return hd.p2wsh_in_p2sh_address()
            else:
                return hd.p2pkh_address()

        else:
            ValueError("hex format invalid check again.[format: hex][64 length]")


class Axe:
    def __int__(self):
        super().__init__()

    def hex_addr(self, hexed: str) -> str:
        """
        Convert Private key Hex To All Axe Format Type Addresses.
        :param hexed:
        :type hexed:
        :rtype str:
        :return: Str - address

        -------------------------------------------------------------

        >>> Axe_ = Axe()
        >>> privatekey = "e3b0c44298fc1c149..................."
        >>> Axe_address = Axe_.hex_addr(privatekey)

        -------------------------------------------------------------

        """
        if is_valid_hex(hexed):
            hd: HD_W = HD_W(AXE)
            hd.from_private_key(hexed)
            return hd.p2pkh_address()
        else:
            ValueError("hex format invalid check again.[format: hex][64 length]")


class Ton:
    """
    TON Address Generator for Mnemonic and Private Key inputs.
    Supports both Raw and User-Friendly Address formats.

    # https://docs.ton.org/learn/overviews/addresses#address-of-smart-contract
    # https://docs.ton.org/learn/overviews/addresses#user-friendly-address-encoding-examples

    """

    def __init__(self, workchain: int = 0, mainnet: bool = True):
        """
        Initialize the TON Address Generator.

        :param workchain: Workchain ID for address (0 for basic workchain, -1 for masterchain).
        :param mainnet: Specify if the address is for the mainnet (True) or testnet (False).
        https://docs.ton.org/learn/overviews/addresses#user-friendly-address-structure

        """
        self.WORKCHAIN = workchain
        self.mainnet = mainnet

    @staticmethod
    def _mnemonic_to_seed(in_mnemonic: str, in_passphrase: str = "") -> bytes:
        """
        Convert mnemonic to a 64-byte seed using the BIP-39 standard.

        :param in_mnemonic: Mnemonic string (24 words).
        :param in_passphrase: Optional passphrase for mnemonic.
        :return: Seed derived from the mnemonic.
        """
        salt = "mnemonic" + in_passphrase
        return _pbkdf2_hmac("sha512", in_mnemonic.encode(), salt.encode(), 2048)

    def _mnemonic_to_publickey(self, in_Target: str) -> bytes:
        """
        Convert mnemonic to public key bytes.

        :param in_Target: Mnemonic string.
        :return: Public key as bytes.
        """
        seed = self._mnemonic_to_seed(in_mnemonic=in_Target)
        _key = _new(b"TON seed", seed, hashlib.sha512).digest()[:32]
        return _sha256(_key).digest()

    @staticmethod
    def _pvk_to_publickey(in_Target: str) -> bytes:
        """
        Convert private key to public key bytes.

        :param in_Target: Private key in hexadecimal format.
        :return: Public key as bytes.
        :raises ValueError: If the private key is invalid.
        """
        if len(in_Target) == 64 and all(c in '0123456789abcdefABCDEF' for c in in_Target):
            _key = bytes.fromhex(in_Target)
            return hashlib.sha256(_key).digest()
        raise ValueError("Invalid private key format. Must be a 64-character hex string.")

    @staticmethod
    def cal_crc16(data: bytes) -> bytes:
        """Calculate CRC16-CCITT checksum."""
        crc = 0xFFFF
        for byte in data:
            tbl_idx = ((crc >> 8) ^ byte) & 0xff
            crc = ((crc << 8) ^ CRC16_TAB[tbl_idx]) & 0xffff
        return crc.to_bytes(2, 'big')

    @staticmethod
    def _userFriendly_to_rawAddress(userFriendly_addr: str) -> str:
        """Convert a user-friendly TON address to its raw format."""
        # -- Check validity of Address Format (48 characters Base64)
        pattern = re.compile(r"^[A-Za-z0-9_-]{48}$")
        if not pattern.match(userFriendly_addr):
            raise ValueError("Invalid user-friendly address format. Must be 48 characters Base64.")
        # -- Decode the Base64 address to bytes
        try:
            # Handle both Base64 and Base64 URL-safe decoding
            address_bytes = _urlsafe_b64decode(userFriendly_addr + '==')
        except Exception as e:
            raise ValueError(f"Failed to decode user-friendly address: {e}")

        # -- Extract fields from the address
        if len(address_bytes) != 36:
            raise ValueError("Invalid user-friendly address length. Must be 36 bytes after decoding.")
        # Extract fields from the address
        tag_byte = address_bytes[0]
        workchain_byte = address_bytes[1]
        account_id = address_bytes[2:34]  # 32 bytes
        checksum = address_bytes[34:36]  # CRC16 checksum
        # -- Validate the CRC16 checksum
        calculated_checksum = Ton.cal_crc16(address_bytes[:34])
        if checksum != calculated_checksum:
            raise ValueError("Invalid CRC16 checksum for the given address.")
        # -- Convert `workchain_byte` to `workchain_id`
        workchain_id = -1 if workchain_byte == 0xff else 0
        # -- Convert the account ID to a hexadecimal string
        account_id_hex = account_id.hex().upper()
        # -- Create the final raw address in the format [workchain_id]:[account_id]
        return f"{workchain_id}:{account_id_hex}"


    def publickey_to_address(self, publickey: bytes, bounceable: bool = True) -> str:
        """
        Convert public key to a user-friendly TON address.
        # https://docs.ton.org/learn/overviews/addresses#bounceable-vs-non-bounceable-addresses

        :param publickey: Public key bytes.
        :param bounceable: If True, generates a bounceable address.
        :return: User-friendly TON address in Base64 format.

        """
        tag_byte = 0x11 if bounceable else 0x51
        if not self.mainnet:
            tag_byte += 0x80

        # Prepare the address bytes
        workchain_byte = 0xff if self.WORKCHAIN == -1 else 0x00
        addr_data = bytes([tag_byte]) + bytes([workchain_byte])
        addr_data += publickey
        raw_addr = addr_data + self.cal_crc16(addr_data)
        # Encode the address in Base64 URL-Safe
        return _urlsafe_b64encode(raw_addr).decode('utf-8').rstrip('=')

    def mnemonic_to_address(self, in_mnemonic: str, bounceable: bool = True) -> str:
        """
        Convert mnemonic to a TON wallet address.

        :param in_mnemonic: Mnemonic string (24 words).
        :param bounceable: If True, generates a bounceable address.
        :return: User-friendly TON address in Base64 format.
        :raises ValueError: If the mnemonic is invalid.
        """
        if not isinstance(in_mnemonic, str) or len(in_mnemonic.split()) != 24:
            raise ValueError("Invalid mnemonic. Must be 24 words.")
        pub = self._mnemonic_to_publickey(in_mnemonic)
        return self.publickey_to_address(pub, bounceable)

    def privatekey_to_address(self, in_privatekey: str, bounceable: bool = True) -> str:
        """
        Convert private key to a TON wallet address.

        :param in_privatekey: Private key in hexadecimal format.
        :param bounceable: If True, generates a bounceable address.
        :return: User-friendly TON address in Base64 format.
        :raises ValueError: If the private key is invalid.
        """
        pub = self._pvk_to_publickey(in_privatekey)
        return self.publickey_to_address(pub, bounceable)

    def decimal_to_address(self, dec: int, bounceable: bool = True) -> str:
        """
        Convert decimal integer to a TON wallet address.
        """
        if dec > MAX_PRIVATE_KEY:
            raise ValueError(f"\nInvalid Decimal Value for Private Key, Must be Less Than {MAX_PRIVATE_KEY}\n")
        pvk = "%064x" % dec
        return self.privatekey_to_address(pvk, bounceable)

    def raw_address(self, address: str) -> str:
        """
        Convert address string to user-friendly TON address.
        """
        return self._userFriendly_to_rawAddress(address)
