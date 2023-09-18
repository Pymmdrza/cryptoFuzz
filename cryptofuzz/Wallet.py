# programmer and owner mmdrza.com

from . import Convertor, Generator


def getPrivateKey():
    return Generator.generate_private_key()


def getMnemonic(size: int = 12) -> str:
    return Generator.generate_mnemonic(size)


def getBinary() -> str:
    return Generator.generate_binary()


def getRootKey() -> str:
    return Generator.generate_xprv()


def PrivateKey_To_Addr(hexed: str, compress: bool = False) -> str:
    seed = Convertor.hex_to_bytes(hexed)
    if compress:
        return Convertor.byte_to_addr(seed, True)
    else:
        return Convertor.byte_to_addr(seed, False)


def PrivateKey_To_Wif(hexed: str, compress: bool = False) -> str:
    seed = Convertor.hex_to_bytes(hexed)
    if compress:
        return Convertor.byte_to_wif(seed, True)
    else:
        return Convertor.byte_to_wif(seed, False)


def PrivateKey_To_PublicKey(hexed: str) -> str:
    seed = Convertor.hex_to_bytes(hexed)
    pub = Convertor.bytes_to_pub(seed)
    return pub.hex()


def PrivateKey_To_Mnemonic(hexed: str) -> str:
    seed = Convertor.hex_to_bytes(hexed)
    return Convertor.byte_to_mne(seed[:32])


def PrivateKey_To_Byte(hexed: str) -> bytes:
    return Convertor.hex_to_bytes(hexed)


def PrivateKey_To_Binary(hexed: str):
    seed = Convertor.hex_to_bytes(hexed)
    chunks = [bin_str[i:i + 8] for i in range(0, len(bin_str), 8)]

    # Convert each chunk into a byte and concatenate
    return bytes([int(chunk, 2) for chunk in chunks])



