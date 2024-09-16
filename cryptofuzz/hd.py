from Crypto.Hash import keccak
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


        --------------------------------------------------------------

        >>> dgb = DigiByte()
        >>> privatekey = "0A97965...A45517" # example Private Key
        >>> digibyte_address = dgb.hex_addr(privatekey)

        --------------------------------------------------------------

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


        --------------------------------------------------------------

        >>> doge = Dogecoin()
        >>> privatekey = "0A9796542F1030...02F6A45517" # example Private Key
        >>> p2pkh_doge_addr = doge.hex_addr(privatekey, 'p2pkh')
        >>> p2sh_doge_addr = doge.hex_addr(privatekey, 'p2sh')

        --------------------------------------------------------------

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
