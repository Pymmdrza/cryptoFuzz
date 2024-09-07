# programmer and owner mmdrza.com
import os
from . import Generator, Convertor
from . import (
    Bitcoin, BitcoinGold, Dash, DigiByte, Dogecoin, Ethereum, Litecoin, Qtum, Ravencoin, Tron, Zcash, Axe
)

# ----------------------------------------------------------
convertor = Convertor()
generator = Generator()


# ----------------------------------------------------------
def getPrivateKey() -> str:
    """

    Generate a private key without repeating.
    :return private key:
    :rtype str:


    ---------------------------------------------------

    >>> Privatekey = getPrivateKey()

    ---------------------------------------------------
    """
    return generator.generate_private_key()


# ----------------------------------------------------------
def getMnemonic(size: int = 12) -> str:
    """

    Generate Random Standard Mnemonic BIP39.

    :param size:
    :type size: Int
    :return mnemonic:
    :rtype str:

    --------------------------------------------------

    >>> Mnemonic = getMnemonic()

    --------------------------------------------------

    """
    return generator.generate_mnemonic(size=size)


# ----------------------------------------------------------
def getBinary() -> str:
    """

    Generate random Binary With Length 256 (256 bits).

    :rtype str:
    :return binary:


    -------------------------------------------------

    >>> Binary = getBinary()

    ------------------------------------------------

    """
    return generator.generate_binary()


# ----------------------------------------------------------
def getRootKey() -> str:
    """

    Generate Root Key.

    :rtype str:
    :return root key:

    ------------------------------------------------

    >>> RootKey = getRootKey()

    ------------------------------------------------

    """

    return generator.generate_xprv()


# -------------------------------------------------------------------
def getBytes() -> bytes: return os.urandom(32)


# -------------------------------------------------------------------
def getDecimal() -> int: return generator.generate_decimal()


# -------------------------------------------------------------------
def PrivateKey_To_Addr(hexed: str, compress: bool = False) -> str:
    """

    Convert Private key Hex To Compress and UnCompress Address.

    :param hexed:
    :type hexed: str
    :param compress:
    :type compress: bool
    :return address:
    :rtype str:

    ----------------------------------------------------------

    >>> privatekey = "0A97965...A45517" # example Private Key
    >>> address_compress = PrivateKey_To_Addr(privatekey, True)
    >>> address_uncompress = PrivateKey_To_Addr(privatekey, False)

    ----------------------------------------------------------

    """
    seed = convertor.hex_to_bytes(hexed)
    if compress:
        return convertor.bytes_to_addr(seed, True)
    else:
        return convertor.bytes_to_addr(seed, False)


# ----------------------------------------------------------
def PrivateKey_To_Wif(hexed: str, compress: bool = False) -> str:
    """

    Convert Private key Hex To Compress and UnCompress WIF.

    :param hexed:
    :type hexed: str
    :param compress:
    :type compress: bool
    :return wif:
    :rtype str:

    ------------------------------------------------------------

    >>> privatekey = "0A97965...A45517" # example Private Key
    >>> wif_compress = PrivateKey_To_Wif(privatekey, True)
    >>> wif_uncompress = PrivateKey_To_Wif(privatekey, False)

    ------------------------------------------------------------

    """

    seed = convertor.hex_to_bytes(hexed)
    if compress:
        return convertor.bytes_to_wif(seed, True)
    else:
        return convertor.bytes_to_wif(seed, False)


# ----------------------------------------------------------
def PrivateKey_To_PublicKey(hexed: str, compress: bool = False) -> str:
    """

    Convert Private key Hex To compress and uncompress Public Key.

    :param hexed:
    :type hexed: str
    :param compress:
    :type compress: bool
    :return public key:
    :rtype str:

    ------------------------------------------------

    >>> privatekey = "0A97965...A45517" # example Private Key
    >>> publickey_compress = PrivateKey_To_PublicKey(privatekey, True)
    >>> publickey_uncompress = PrivateKey_To_PublicKey(privatekey, False)

    ------------------------------------------------

    """
    seed = convertor.hex_to_bytes(hexed)
    if compress:
        return convertor.bytes_to_public(seed, True).hex()
    else:
        return convertor.bytes_to_public(seed, False).hex()


# ----------------------------------------------------------
def PrivateKey_To_Mnemonic(hexed: str) -> str:
    """

    Convert Private key Hex To Mnemonic.

    :param hexed:
    :type hexed: str
    :return mnemonic:
    :rtype str:

    --------------------------------------------------------

    >>> privatekey = "0A97965...A45517" # example Private Key
    >>> mnemonic = PrivateKey_To_Mnemonic(privatekey)

    --------------------------------------------------------

    """
    seed = convertor.hex_to_bytes(hexed)
    return convertor.bytes_to_mnemonic(seed)


# ----------------------------------------------------------
def PrivateKey_To_Byte(hexed: str) -> bytes:
    """

    Convert Private key Hex To Byte.

    :param hexed:
    :type hexed: Str.
    :return byte:
    :rtype bytes:

    --------------------------------------------------------

    >>> Privatekey = "0A97965...A45517" # example Private Key
    >>> byte = PrivateKey_To_Byte(Privatekey)

    --------------------------------------------------------
    """
    return convertor.hex_to_bytes(hexed)


# ----------------------------------------------------------
def PrivateKey_To_Binary(hexed: str) -> str:
    """

    Convert Private key Hex To Binary.

    :param hexed:
    :type hexed: Str
    :return binary:
    :rtype str:

    --------------------------------------------------------

    >>> Privatekey = "0A97965...A45517" # example Private Key
    >>> binary = PrivateKey_To_Binary(Privatekey)

    --------------------------------------------------------

    """
    seed = convertor.hex_to_bytes(hexed)
    return convertor.bytes_to_binary(seed)


# ----------------------------------------------------------
def PrivateKey_To_Decimal(hexed: str) -> int:
    """

    Convert Private key Hex To Decimal.

    :param hexed:
    :type hexed: Str
    :return decimal:
    :rtype int:

    --------------------------------------------------------

    >>> Privatekey = "0A97965...A45517" # example Private Key
    >>> decimal = PrivateKey_To_Decimal(Privatekey)

    --------------------------------------------------------

    """
    seed = convertor.hex_to_bytes(hexed)
    return convertor.bytes_to_int(seed)


# ----------------------------------------------------------
def PrivateKey_To_XPRV(hexed: str) -> str:
    """

    Convert Private key Hex To XPRV.

    :param hexed:
    :type hexed: Str
    :return xprv:
    :rtype str:

    --------------------------------------------------------

    >>> Privatekey = "0A97965...A45517" # example Private Key
    >>> xprv = PrivateKey_To_XPRV(Privatekey)

    --------------------------------------------------------

    """
    seed = convertor.hex_to_bytes(hexed)
    return convertor.bytes_to_xprv(seed)


# ----------------------------------------------------------
def PrivateKey_To_CompressAddr(hexed: str) -> str:
    """

    Convert Private key Hex To Compress Address.

    :param hexed:
    :type hexed: Str
    :return address:
    :rtype str:

    --------------------------------------------------------

    >>> Privatekey = "0A97965...A45517" # example Private Key
    >>> address_compress = PrivateKey_To_CompressAddr(Privatekey)

    --------------------------------------------------------

    """
    seed = convertor.hex_to_bytes(hexed)
    return convertor.bytes_to_addr(seed, True)


# ----------------------------------------------------------
def PrivateKey_To_UncompressAddr(hexed: str) -> str:
    """
    
    Convert Private key Hex To UnCompress Address.
    
    :param hexed:
    :type hexed: Str
    :return address:
    :rtype str:
    
    --------------------------------------------------------
    
    >>> Privatekey = "0A97965...A45517" # example Private Key
    >>> address_uncompress = PrivateKey_To_UncompressAddr(Privatekey)
    
    --------------------------------------------------------
    
    """
    seed = convertor.hex_to_bytes(hexed)
    return convertor.bytes_to_addr(seed, False)


# ----------------------------------------------------------
def PrivateKey_To_XPUB(hexed: str) -> str:
    """
    
    Convert Private key Hex To XPUB.
    
    :param hexed:
    :type hexed: Str
    :return xpub:
    :rtype str:
    
    --------------------------------------------------------
    
    >>> Privatekey = "0A97965...A45517" # example Private Key
    >>> xpub = PrivateKey_To_XPUB(Privatekey)
    
    --------------------------------------------------------
    
    
    """
    seed = convertor.hex_to_bytes(hexed)
    return convertor.bytes_to_xpub(seed)


# ----------------------------------------------------------
def Bytes_To_PrivateKey(byte: bytes) -> str:
    """

    Convert Byte To Private Key.

    :param byte:
    :type byte: Bytes
    :return private key:
    :rtype str:

    --------------------------------------------------------

    >>> Privatekey = "0A97965...A45517" # example Private Key
    >>> privatekey = Bytes_To_PrivateKey(Privatekey)

    --------------------------------------------------------

    """
    return convertor.bytes_to_hex(byte)


# ----------------------------------------------------------
def Bytes_To_Address(seed: bytes, compress: bool = False):
    """
    
    Convert Bytes To Compressed and Uncompressed Address.
    
    
    :param seed:
    :type seed: Bytes
    :param compress:
    :type compress: bool
    :return address:
    :rtype str:
    
    --------------------------------------------------------
    
    >>> seedBytes = b"\x00\x00\x00\x00...\x00\x00\x00\x00\x00\x00\x00\x00" # example seed
    >>> address_compress = Bytes_To_Address(seedBytes, True)
    >>> address_uncompress = Bytes_To_Address(seedBytes, False)
    
    --------------------------------------------------------
    
    """
    if compress:
        return convertor.bytes_to_addr(seedBytes=seed, compress=True)
    else:
        return convertor.bytes_to_addr(seedBytes=seed, compress=False)


# ----------------------------------------------------------
def Bytes_To_Mnemonic(seed: bytes) -> str:
    """
    
    
    Convert Bytes To Mnemonic.
    
    :param seed:
    :type seed: Bytes
    :return mnemonic:
    :rtype str:
    
    --------------------------------------------------------
    
    >>> seedBytes = b"\x00\x00\x00\x00...\x00\x00\x00\x00\x00\x00\x00\x00" # example seed
    >>> mnemonic = Bytes_To_Mnemonic(seedBytes)
    
    --------------------------------------------------------
    
    
    """
    return convertor.bytes_to_mnemonic(seed)


# ----------------------------------------------------------
def Bytes_To_XPRV(seed: bytes) -> str:
    """
    
    Convert Bytes To XPRV.
    
    :param seed:
    :type seed: Bytes
    :return xprv:
    :rtype str:
    
    --------------------------------------------------------
    
    >>> seedBytes = b"\x00\x00\x00\x00...\x00\x00\x00\x00\x00\x00\x00\x00" # example seed
    >>> xprv = Bytes_To_XPRV(seedBytes)
    
    --------------------------------------------------------
    
    """
    return convertor.bytes_to_xprv(seed)


# ----------------------------------------------------------
def Bytes_To_Binary(seed: bytes):
    """
    
    Convert Bytes To Binary.
    
    :param seed:
    :type seed: Bytes
    :return binary:
    :rtype str:
    
    --------------------------------------------------------
    
    >>> seedBytes = b"\x00\x00\x00\x00...\x00\x00\x00\x00\x00\x00\x00\x00" # example seed
    >>> binary = Bytes_To_Binary(seedBytes)
    
    --------------------------------------------------------
    
    """
    return convertor.bytes_to_binary(seed)


# ----------------------------------------------------------
def Bytes_To_PublicKey(seed: bytes, compress: bool = False):
    """
    
    Convert Bytes To Public Key Compressed and Uncompressed.
    
    :param seed:
    :type seed: Bytes
    :param compress:
    :type compress: bool
    :return public:
    :rtype str:
    
    --------------------------------------------------------
    
    >>> seedBytes = b"\x00\x00\x00\x00...\x00\x00\x00\x00\x00\x00\x00\x00" # example seed
    >>> public_compress = Bytes_To_PublicKey(seedBytes, True)
    >>> public_uncompress = Bytes_To_PublicKey(seedBytes, False)
    
    --------------------------------------------------------
    
    """

    if compress:
        return convertor.bytes_to_public(seed, True).hex()
    else:
        return convertor.bytes_to_public(seed, False).hex()


# ----------------------------------------------------------
def Bytes_To_Compress_Addr(seed: bytes) -> str:
    """
    
    Convert Bytes To Compressed Address.
    
    :param seed:
    :type seed: Bytes
    :return address:
    :rtype str:
    
    --------------------------------------------------------
    
    >>> seedBytes = b"\x00\x00\x00\x00...\x00\x00\x00\x00\x00\x00\x00\x00" # example seed
    >>> address_compress = Bytes_To_Compress_Addr(seedBytes)
    
    --------------------------------------------------------
    
    """
    return convertor.bytes_to_addr(seed, True)


# ----------------------------------------------------------
def Bytes_To_Uncompress_Addr(seed: bytes) -> str:
    """
    
    Convert Bytes To Uncompressed Address.
    
    :param seed:
    :type seed: Bytes
    :return address:
    :rtype str:
    
    --------------------------------------------------------
    
    >>> seedBytes = b"\x00\x00\x00\x00...\x00\x00\x00\x00\x00\x00\x00\x00" # example seed
    >>> address_uncompress = Bytes_To_Uncompress_Addr(seedBytes)
    
    --------------------------------------------------------
    
    """
    return convertor.bytes_to_addr(seed, False)


# ----------------------------------------------------------
def Bytes_To_Decimal(seed: bytes):
    """
    
    Convert Bytes To Decimal.
    
    :param seed:
    :type seed: Bytes
    :return decimal:
    :rtype int:
    
    --------------------------------------------------------
    
    >>> seedBytes = b"\x00\x00\x00\x00...\x00\x00\x00\x00\x00\x00\x00\x00" # example seed
    >>> decimal = Bytes_To_Decimal(seedBytes)
    
    --------------------------------------------------------
    
    """
    return convertor.bytes_to_int(seed)


# ----------------------------------------------------------
def Bytes_To_XPUB(seed: bytes) -> str:
    return convertor.bytes_to_xpub(seed)


# ----------------------------------------------------------
def Bytes_To_Wif(seed: bytes, compress: bool = False) -> str:
    """
    
    Convert Bytes To Wif Compressed and UnCompressed.
    
    :param seed:
    :type seed: Bytes
    :param compress:
    :type compress: bool
    :return wif:
    :rtype str:
    
    --------------------------------------------------------
    
    >>> seedBytes = b"\x00\x00\x00\x00...\x00\x00\x00\x00\x00\x00\x00\x00" # example seed
    >>> wif_compress = Bytes_To_Wif(seedBytes, True)
    >>> wif_uncompress = Bytes_To_Wif(seedBytes, False)
    
    --------------------------------------------------------
    

    """
    if compress:
        return convertor.bytes_to_wif(seed, True)
    else:
        return convertor.bytes_to_wif(seed, False)


# ----------------------------------------------------------
def Mnemonic_To_Bytes(mnemonic: str) -> bytes:
    return convertor.mne_to_seed(mnemonic=mnemonic)


# ----------------------------------------------------------
def Mnemonic_To_PrivateKey(mnemonic: str) -> str:
    seed = convertor.mne_to_seed(mnemonic=mnemonic)
    return convertor.bytes_to_hex(seed=seed)


# ----------------------------------------------------------
def Mnemonic_To_PublicKey(mnemonic: str, compress: bool = False):
    seed = convertor.mne_to_seed(mnemonic=mnemonic)
    if compress:
        pub = convertor.bytes_to_public(seed, True).hex()
        return convertor.pub_to_addr(pub)
    else:
        pub = convertor.bytes_to_public(seed, False).hex()
        return convertor.pub_to_addr(pub)


# ----------------------------------------------------------
def Mnemonic_To_Decimal(mnemonic: str):
    seed = convertor.mne_to_seed(mnemonic=mnemonic)
    return convertor.bytes_to_int(seed)


# ----------------------------------------------------------
def Mnemonic_To_Binary(mnemonic: str):
    seed = convertor.mne_to_seed(mnemonic=mnemonic)
    return convertor.bytes_to_binary(seed)


# ----------------------------------------------------------
def Mnemonic_To_XPRV(mnemonic: str):
    seedBytes = convertor.mne_to_seed(mnemonic)
    return convertor.bytes_to_xprv(seedBytes)


# ----------------------------------------------------------
def Mnemonic_To_Addr(mnemonic: str, compress: bool = False) -> str:
    seedBytes = convertor.mne_to_seed(mnemonic)
    if compress:
        return convertor.bytes_to_addr(seedBytes, True)
    else:
        return convertor.bytes_to_addr(seedBytes, False)


# ----------------------------------------------------------
def Mnemonic_To_XPUB(mnemonic: str):
    seedBytes = convertor.mne_to_seed(mnemonic)
    return convertor.bytes_to_xpub(seedBytes)


# ----------------------------------------------------------
def Mnemonic_To_Wif(mnemonic: str, compress: bool = False) -> str:
    seedBytes = convertor.mne_to_seed(mnemonic)
    if compress:
        return convertor.bytes_to_wif(seedBytes, True)
    else:
        return convertor.bytes_to_wif(seedBytes, False)


# ----------------------------------------------------------
def Passphrase_To_Addr(passphrase: str, compress: bool = False) -> str:
    if compress:
        return convertor.pass_to_addr(passphrase, True)
    else:
        return convertor.pass_to_addr(passphrase, False)


# ----------------------------------------------------------
def Passphrase_To_Bytes(passphrase: str) -> bytes:
    return convertor.pass_to_bytes(passphrase)


# ----------------------------------------------------------
def Passphrase_To_PrivateKey(passphrase: str) -> str:
    return convertor.bytes_to_hex(convertor.pass_to_bytes(passphrase))


# ----------------------------------------------------------
def Passphrase_To_PublicKey(passphrase: str, compress: bool = False) -> str:
    seed = convertor.pass_to_bytes(passphrase)
    if compress:
        return convertor.bytes_to_public(seed, True).hex()
    else:
        return convertor.bytes_to_public(seed, False).hex()


# ----------------------------------------------------------
def Passphrase_To_Wif(passphrase: str, compress: bool = False) -> str:
    seed = convertor.pass_to_bytes(passphrase)
    if compress:
        return convertor.bytes_to_wif(seed, True)
    else:
        return convertor.bytes_to_wif(seed, False)


# ----------------------------------------------------------
def Passphrase_To_RootKey(passphrase: str) -> str:
    seed = convertor.pass_to_bytes(passphrase)
    return convertor.bytes_to_xprv(seed)


# ----------------------------------------------------------
def Passphrase_To_XPUB(passphrase: str) -> str:
    seed = convertor.pass_to_bytes(passphrase)
    return convertor.bytes_to_xpub(seed)


# ----------------------------------------------------------
def Passphrase_To_Decimal(passphrase: str) -> int:
    seed = convertor.pass_to_bytes(passphrase)
    return convertor.bytes_to_int(seed)


# ----------------------------------------------------------
def Wif_To_Bytes(wif: str) -> bytes:
    return convertor.wif_to_bytes(wif)


# ----------------------------------------------------------
def Wif_To_Addr(wif: str, compress: bool = False) -> str:
    return convertor.wif_to_addr(wif, compress)


# ----------------------------------------------------------
def Wif_To_PrivateKey(wif: str) -> str:
    return convertor.bytes_to_hex(convertor.wif_to_bytes(wif))


# ----------------------------------------------------------
def Wif_To_Mnemonic(wif: str) -> str:
    return convertor.bytes_to_mnemonic(convertor.wif_to_bytes(wif))


# ----------------------------------------------------------
def Wif_To_Decimal(wif: str) -> int:
    return convertor.bytes_to_int(convertor.wif_to_bytes(wif))


# ----------------------------------------------------------
def Wif_To_Binary(wif: str) -> str:
    return convertor.bytes_to_binary(convertor.wif_to_bytes(wif))


# ----------------------------------------------------------
def Wif_To_XPRV(wif: str) -> str:
    return convertor.bytes_to_xprv(convertor.wif_to_bytes(wif))


# ----------------------------------------------------------
def Wif_To_XPUB(wif: str) -> str: return convertor.bytes_to_xpub(convertor.wif_to_bytes(wif))


# ----------------------------------------------------------
def Wif_To_RootKey(wif: str) -> str:
    return Wif_To_XPRV(wif)


# ----------------------------------------------------------
def Wif_To_PublicKey(wif: str, compress: bool = False):
    seed = convertor.wif_to_bytes(wif)
    if compress:
        return convertor.bytes_to_public(seed, True).hex()
    else:
        return convertor.bytes_to_public(seed, False).hex()


# ----------------------------------------------------------
def Decimal_To_PrivateKey(dec: int) -> str:
    return "%064x" % dec


# ----------------------------------------------------------
def Decimal_To_Bytes(dec: int) -> bytes:
    return convertor.int_to_bytes(dec)


# ----------------------------------------------------------
def Decimal_To_PublicKey(dec: int, compress: bool = False) -> str:
    seed = Decimal_To_Bytes(dec)
    if compress:
        return convertor.bytes_to_public(seed, True).hex()
    else:
        return convertor.bytes_to_public(seed, False).hex()


# ----------------------------------------------------------
def Decimal_To_Address(dec: int, compress: bool = False) -> str:
    seed = Decimal_To_Bytes(dec)
    if compress:
        return convertor.bytes_to_addr(seed, True)
    else:
        return convertor.bytes_to_addr(seed, False)


# ----------------------------------------------------------
def Decimal_To_Mnemonic(dec: int) -> str:
    seed = convertor.int_to_bytes(dec)
    return convertor.bytes_to_mnemonic(seed)


# ----------------------------------------------------------
def Decimal_To_XPRV(dec: int) -> str:
    seed = convertor.int_to_bytes(dec)
    return convertor.bytes_to_xprv(seed)


# ----------------------------------------------------------
def Decimal_To_XPUB(dec: int) -> str:
    seed = convertor.int_to_bytes(dec)
    return convertor.bytes_to_xpub(seed)


# ----------------------------------------------------------
def Decimal_To_Binary(dec: int) -> str:
    seed = convertor.int_to_bytes(dec)
    return convertor.bytes_to_binary(seed)


def Decimal_To_Wif(dec: int, compress: bool = False) -> str:
    seed = convertor.int_to_bytes(dec)
    if compress:
        return convertor.bytes_to_wif(seed, True)
    else:
        return convertor.bytes_to_wif(seed, False)


# ----------------------------------------------------------
def Binary_To_Bytes(binary_str: str) -> bytes:
    return convertor.binary_to_bytes(binary_str)


# ----------------------------------------------------------
def Binary_To_Address(binary_str: str, compress: bool = False) -> str:
    seed = convertor.binary_to_bytes(binary_str)
    if compress:
        return convertor.bytes_to_addr(seed, True)
    else:
        return convertor.bytes_to_addr(seed, False)


# ----------------------------------------------------------
def Binary_To_PrivateKey(binary_str: str) -> str: return convertor.bytes_to_hex(convertor.binary_to_bytes(binary_str))


# ----------------------------------------------------------
def Binary_To_Mnemonic(binary_str: str) -> str: return convertor.bytes_to_mnemonic(
    convertor.binary_to_bytes(binary_str))


# ----------------------------------------------------------
def Binary_To_XPRV(binary_str: str) -> str: return convertor.bytes_to_xprv(convertor.binary_to_bytes(binary_str))


# ----------------------------------------------------------
def Binary_To_XPUB(binary_str: str) -> str: return convertor.bytes_to_xpub(convertor.binary_to_bytes(binary_str))


# ----------------------------------------------------------
def Binary_To_Wif(binary_str: str, compress: bool = False) -> str: return convertor.bytes_to_wif(
    convertor.binary_to_bytes(binary_str), compress)


# ----------------------------------------------------------
def Binary_To_PublicKey(binary_str: str, compress: bool = False) -> str: return convertor.bytes_to_public(
    convertor.binary_to_bytes(binary_str), compress).hex()


# ----------------------------------------------------------
def Binary_To_Decimal(binary_str: str) -> int: return convertor.bytes_to_int(convertor.binary_to_bytes(binary_str))


# ----------------------------------------------------------
def XPRV_To_Bytes(xprv: str) -> bytes: return convertor.xprv_to_bytes(xprv)


def XPRV_To_PrivateKey(xprv: str) -> str: return convertor.bytes_to_hex(convertor.xprv_to_bytes(xprv))


def XPRV_To_PublicKey(xprv: str, compress: bool = False) -> str: return convertor.bytes_to_public(
    convertor.xprv_to_bytes(xprv), compress).hex()


def XPRV_To_Wif(xprv: str, compress: bool = False) -> str: return convertor.bytes_to_wif(convertor.xprv_to_bytes(xprv),
                                                                                         compress)


def XPRV_To_Address(xprv: str, compress: bool = False) -> str: return convertor.bytes_to_addr(
    convertor.xprv_to_bytes(xprv), compress)


def XPRV_To_Mnemonic(xprv: str) -> str: return convertor.bytes_to_mnemonic(convertor.xprv_to_bytes(xprv))


def XPRV_To_XPUB(xprv: str) -> str: return convertor.bytes_to_xpub(convertor.xprv_to_bytes(xprv))


def XPRV_To_Decimal(xprv: str) -> int: return convertor.bytes_to_int(convertor.xprv_to_bytes(xprv))


# ----------------------------------------------------------
def PrivateKey_To_Bitcoin_Addr(privatekey: str, Type: str = 'p2pkh') -> str:
    """
    
    Convert Private Key To Bitcoin All Type Address, Type: p2pkh, p2sh, p2wpkh, p2wsh, p2wpkh_p2sh, p2wsh_p2sh.
    
    :param privatekey:
    :type privatekey: str
    :param Type:
    :type Type: str
    :returns:
    
    
    --------------------------------------------------------
    
    >>> from cryptofuzz.Wallet import PrivateKey_To_Bitcoin_Addr
    
    >>> Privatekey = "e3bfc1c...ca52b8" # example key
    >>> p2pkh = PrivateKey_To_Bitcoin_Addr(Privatekey, 'p2pkh')
    >>> p2sh = PrivateKey_To_Bitcoin_Addr(Privatekey, 'p2sh')
    >>> p2wpkh = PrivateKey_To_Bitcoin_Addr(Privatekey, 'p2wpkh')
    >>> p2wsh = PrivateKey_To_Bitcoin_Addr(Privatekey, 'p2wsh')
    >>> p2wpkh_p2sh = PrivateKey_To_Bitcoin_Addr(Privatekey, 'p2wpkh_p2sh')
    >>> p2wsh_p2sh = PrivateKey_To_Bitcoin_Addr(Privatekey, 'p2wsh_p2sh')
    
    --------------------------------------------------------
    
    
    """
    BTC = Bitcoin()
    if Type == 'p2pkh':
        return BTC.hex_addr(privatekey, 'p2pkh')
    elif Type == 'p2sh':
        return BTC.hex_addr(privatekey, 'p2sh')
    elif Type == 'p2wpkh':
        return BTC.hex_addr(privatekey, 'p2wpkh')
    elif Type == 'p2wsh':
        return BTC.hex_addr(privatekey, 'p2wsh')
    elif Type == 'p2wpkh_p2sh':
        return BTC.hex_addr(privatekey, 'p2wpkh_p2sh')
    elif Type == 'p2wsh_p2sh':
        return BTC.hex_addr(privatekey, 'p2wsh_p2sh')
    else:
        return BTC.hex_addr(privatekey, 'p2pkh')


# ----------------------------------------------------------
def PrivateKey_To_Ethereum_Addr(privatekey: str) -> str:
    """
    
    Convert Private Key To Ethereum Address.
    
    :param privatekey:
    :type privatekey: str
    :returns:
    
    
    --------------------------------------------------------
    
    >>> from cryptofuzz.Wallet import PrivateKey_To_Ethereum_Addr
    >>> Privatekey = "e3bfc1c...ca52b8" # example key
    >>> addr = PrivateKey_To_Ethereum_Addr(Privatekey)
    
    --------------------------------------------------------
    
    
    """
    ETH = Ethereum()
    return ETH.hex_addr(privatekey)


# ----------------------------------------------------------
def PrivateKey_To_BitcoinGold_Addr(privatekey: str) -> str:
    """
    
    Convert Private Key To Bitcoin Gold Address.
    
    :param privatekey:
    :type privatekey: str
    :returns:
    
    
    --------------------------------------------------------
    
    >>> from cryptofuzz.Wallet import PrivateKey_To_BitcoinGold_Addr
    >>> Privatekey = "e3bfc1c...ca52b8" # example key
    >>> addr = PrivateKey_To_BitcoinGold_Addr(Privatekey)
    
    --------------------------------------------------------
    
    
    """
    BTG = BitcoinGold()
    return BTG.hex_addr(privatekey)


# ----------------------------------------------------------
def PrivateKey_To_Dash_Addr(privatekey: str) -> str:
    """
    
    Convert Private Key To Dash Address.
    
    :param privatekey:
    :type privatekey: str
    :returns:
    
    
    --------------------------------------------------------
    
    >>> from cryptofuzz.Wallet import PrivateKey_To_Dash_Addr
    >>> Privatekey = "e3bfc1c...ca52b8" # example key
    >>> addr = PrivateKey_To_Dash_Addr(Privatekey)
    
    --------------------------------------------------------
    
    
    """
    DASH = Dash()
    return DASH.hex_addr(privatekey)


# ----------------------------------------------------------
def PrivateKey_To_DigiByte_Addr(privatekey: str) -> str:
    """
    
    Convert Private Key To Digibyte Address.
    
    :param privatekey:
    :type privatekey: str
    :returns:
    
    
    --------------------------------------------------------
    
    >>> from cryptofuzz.Wallet import PrivateKey_To_Digibyte_Addr
    >>> Privatekey = "e3bfc1c...ca52b8" # example key
    >>> addr = PrivateKey_To_DigiByte_Addr(Privatekey)
    
    --------------------------------------------------------
    
    
    """
    DGB = DigiByte()
    return DGB.hex_addr(privatekey)


# ----------------------------------------------------------
def PrivateKey_To_Tron_Addr(privatekey: str) -> str:
    """
    
    Convert Private Key To Tron Address.
    
    :param privatekey:
    :type privatekey: str
    :returns:
    
    
    --------------------------------------------------------
    
    >>> from cryptofuzz.Wallet import PrivateKey_To_Tron_Addr
    >>> Privatekey = "e3bfc1c...ca52b8" # example key
    >>> addr = PrivateKey_To_Tron_Addr(Privatekey)
    
    --------------------------------------------------------
    
    
    """
    TRX = Tron()
    return TRX.hex_addr(privatekey)


# ----------------------------------------------------------
def PrivateKey_To_Litecoin_Addr(privatekey: str, Type: str = 'p2pkh') -> str:
    """
    
    Convert Private Key To Litecoin Address.
    
    :param privatekey:
    :type privatekey: str
    :param Type:
    :type Type: str
    :returns:
    
    
    --------------------------------------------------------
    
    >>> from cryptofuzz.Wallet import PrivateKey_To_Litecoin_Addr
    >>> Privatekey = "e3bfc1c...ca52b8" # example key
    >>> p2pkh = PrivateKey_To_Litecoin_Addr(Privatekey, 'p2pkh')
    >>> p2sh = PrivateKey_To_Litecoin_Addr(Privatekey, 'p2sh')
    >>> p2wpkh = PrivateKey_To_Litecoin_Addr(Privatekey, 'p2wpkh')
    >>> p2wsh = PrivateKey_To_Litecoin_Addr(Privatekey, 'p2wsh')
    >>> p2wpkh_p2sh = PrivateKey_To_Litecoin_Addr(Privatekey, 'p2wpkh_p2sh')
    >>> p2wsh_p2sh = PrivateKey_To_Litecoin_Addr(Privatekey, 'p2wsh_p2sh')

    --------------------------------------------------------
    
    """
    LTC = Litecoin()
    if Type == 'p2pkh':
        return LTC.hex_addr(privatekey, 'p2pkh')
    elif Type == 'p2sh':
        return LTC.hex_addr(privatekey, 'p2sh')
    elif Type == 'p2wpkh':
        return LTC.hex_addr(privatekey, 'p2wpkh')
    elif Type == 'p2wsh':
        return LTC.hex_addr(privatekey, 'p2wsh')
    elif Type == 'p2wpkh_p2sh':
        return LTC.hex_addr(privatekey, 'p2wpkh_p2sh')
    elif Type == 'p2wsh_p2sh':
        return LTC.hex_addr(privatekey, 'p2wsh_p2sh')
    else:
        return LTC.hex_addr(privatekey, 'p2pkh')


# ----------------------------------------------------------
def PrivateKey_To_Zcash_Addr(privatekey: str) -> str:
    """
    
    Convert Private Key To Zcash Address.
    
    :param privatekey:
    :type privatekey: str
    :returns:
    
    
    --------------------------------------------------------
    
    >>> from cryptofuzz.Wallet import PrivateKey_To_Zcash_Addr
    >>> Privatekey = "e3bfc1c...ca52b8" # example key
    >>> addr = PrivateKey_To_Zcash_Addr(Privatekey)
    
    --------------------------------------------------------
    
    
    """
    ZEC = Zcash()
    return ZEC.hex_addr(privatekey)


# ----------------------------------------------------------
def PrivateKey_To_Qtum_Addr(privatekey: str) -> str:
    """
    
    Convert Private Key To Qtum Address.
    
    :param privatekey:
    :type privatekey: str
    :returns:
    
    
    --------------------------------------------------------
    
    >>> from cryptofuzz.Wallet import PrivateKey_To_Qtum_Addr
    >>> Privatekey = "e3bfc1c...ca52b8" # example key
    >>> addr = PrivateKey_To_Qtum_Addr(Privatekey)
    
    --------------------------------------------------------
    
    
    """
    QTUM = Qtum()
    return QTUM.hex_addr(privatekey)


# ----------------------------------------------------------
def PrivateKey_To_Ravencoin_Addr(privatekey: str) -> str:
    """
    
    Convert Private Key To Ravencoin Address.
    
    :param privatekey:
    :type privatekey: str
    :returns:
    
    
    --------------------------------------------------------
    
    >>> from cryptofuzz.Wallet import PrivateKey_To_Ravencoin_Addr
    >>> Privatekey = "e3bfc1c...ca52b8" # example key
    >>> addr = PrivateKey_To_Ravencoin_Addr(Privatekey)
    
    --------------------------------------------------------
    
    
    """
    RVN = Ravencoin()
    return RVN.hex_addr(privatekey)


# ----------------------------------------------------------
def PrivateKey_To_Dogecoin_Addr(privatekey: str) -> str:
    """
    
    Convert Private Key To Dogecoin Address.
    
    :param privatekey:
    :type privatekey: str
    :returns:
    
    
    --------------------------------------------------------
    
    >>> from cryptofuzz.Wallet import PrivateKey_To_Dogecoin_Addr
    >>> Privatekey = "e3bfc1c...ca52b8" # example key
    >>> addr = PrivateKey_To_Dogecoin_Addr(Privatekey)
    
    --------------------------------------------------------
    
    
    """
    DOGE = Dogecoin()
    return DOGE.hex_addr(privatekey)


def PrivateKey_To_Axe_Addr(privatekey: str) -> str:
    axe = Axe()
    return axe.hex_addr(privatekey)


if __name__ == "__main__" and __package__ is None:
    __package__ = "cryptofuzz"
