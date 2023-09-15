import os, random
import utils


def getPrivateKey(): return utils.generate_private_key()


def getByte(size: int = 32) -> bytes: return os.urandom(size)


def getMnemonic(size: int) -> str:
    if size:
        return utils.generate_mnemonic(size)
    else:
        return utils.generate_mnemonic(size=12)


def getRootKey(): return utils.generate_xprv()


def getBinary():
    bin_data = [''.join(random.choices('01', k=8)) for _ in range(32)]
    return ''.join(bin_data)


def getEntropy(size: int = 256) -> bytes:
    return utils.generate_entropy(size)


def getChecksum(data: bytes) -> bytes:
    return utils.SHA256(data).digest()[:4]


def PrivateKey_To_Addr(private_key: str, compress: bool = False) -> str:
    seed = utils.hex_to_bytes(private_key)
    priv, pub = utils.byte_to_keys(seed)
    if compress:
        return utils.pub_to_addr(pub, True)
    else:
        return utils.pub_to_addr(pub, False)


def PrivateKey_To_WIF(private_key: str, compress: bool = False) -> str:
    seed = utils.hex_to_bytes(private_key)
    priv, pub = utils.byte_to_keys(seed)
    if compress:
        return utils.byte_to_wif(priv, True)
    else:
        return utils.byte_to_wif(priv, False)


def Mnemonic_To_Addr(mnemonic: str, password: str = "", compress: bool = False) -> str:
    seed = utils.mne_to_seed(mnemonic, password)
    priv, pub = utils.byte_to_keys(seed)
    if compress:
        return utils.pub_to_addr(pub, True)
    else:
        return utils.pub_to_addr(pub, False)


def Bytes_To_PrivateKey(data: bytes) -> str: return utils.byte_to_hex(data)


def Bytes_To_WIF(data: bytes, compress: bool = False) -> str:
    if compress:
        return utils.byte_to_wif(data, True)
    else:
        return utils.byte_to_wif(data, False)


def Bytes_To_Mnemonic(data: bytes) -> str: return utils.byte_to_mne(data)


def Bytes_To_Dec(data: bytes) -> int: return int.from_bytes(data, byteorder='big')


def Bytes_To_Hex(data: bytes) -> str: return data.hex()


def Bytes_To_Addr(data: bytes, compress: bool = False) -> str:
    pvk, pub = utils.byte_to_keys(data)
    if compress:
        return utils.pub_to_addr(pub, True)
    else:
        return utils.pub_to_addr(pub, False)


def Bytes_To_PublicKey(data: bytes) -> str:
    _, pub = utils.byte_to_keys(data)
    return pub.hex()

