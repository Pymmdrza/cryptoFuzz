from functools import lru_cache
from hashlib import sha256
from typing import Mapping, Union
from assest import (
    BITCOIN_ALPHABET as ALPHABET,
    RIPPLE_ALPHABET as XRP_ALPHABET,
    BASE58_ALPHABET
)


def scrub_input(v: Union[str, bytes]) -> bytes:
    if isinstance(v, str):
        v = v.encode('ascii')

    return v


def b58encode_int(
    i: int, default_one: bool = True, alphabet: bytes = ALPHABET
) -> bytes:
    """
    Encode an integer using Base58
    """
    if not i and default_one:
        return alphabet[0:1]
    string = b""
    base = len(alphabet)
    while i:
        i, idx = divmod(i, base)
        string = alphabet[idx:idx+1] + string
    return string


def b58encode(
    v: Union[str, bytes], alphabet: bytes = ALPHABET
) -> bytes:
    """
    Encode a string using Base58
    """
    v = scrub_input(v)

    mainSize = len(v)
    v = v.lstrip(b'\0')
    newSize = len(v)

    acc = int.from_bytes(v, byteorder='big')  # first byte is most significant

    result = b58encode_int(acc, default_one=False, alphabet=alphabet)
    return alphabet[0:1] * (mainSize - newSize) + result


@lru_cache()
def _get_base58_decode_map(alphabet: bytes,
                           autofix: bool) -> Mapping[int, int]:
    invmap = {char: index for index, char in enumerate(alphabet)}

    if autofix:
        groups = [b'0Oo', b'Il1']
        for group in groups:
            pivots = [c for c in group if c in invmap]
            if len(pivots) == 1:
                for alternative in group:
                    invmap[alternative] = invmap[pivots[0]]

    return invmap


def b58decode_int(
    v: Union[str, bytes], alphabet: bytes = ALPHABET, *,
    autofix: bool = False
) -> int:
    """
    Decode a Base58 encoded string as an integer
    """
    if b' ' not in alphabet:
        v = v.rstrip()
    v = scrub_input(v)

    map = _get_base58_decode_map(alphabet, autofix=autofix)

    decimal = 0
    base = len(alphabet)
    try:
        for char in v:
            decimal = decimal * base + map[char]
    except KeyError as e:
        raise ValueError(
            "Invalid character {!r}".format(chr(e.args[0]))
        ) from None
    return decimal


def b58decode(
    v: Union[str, bytes], alphabet: bytes = ALPHABET, *,
    autofix: bool = False
) -> bytes:
    """
    Decode a Base58 encoded string
    """
    v = v.rstrip()
    v = scrub_input(v)

    mainSize = len(v)
    v = v.lstrip(alphabet[0:1])
    newSize = len(v)

    acc = b58decode_int(v, alphabet=alphabet, autofix=autofix)

    return acc.to_bytes(mainSize - newSize + (acc.bit_length() + 7) // 8, 'big')


def b58encode_check(
    v: Union[str, bytes], alphabet: bytes = ALPHABET
) -> bytes:
    """
    Encode a string using Base58 with a 4 character checksum
    """
    v = scrub_input(v)

    digest = sha256(sha256(v).digest()).digest()
    return b58encode(v + digest[:4], alphabet=alphabet)


def b58decode_check(
    v: Union[str, bytes], alphabet: bytes = ALPHABET, *,
    autofix: bool = False
) -> bytes:
    """Decode and verify the checksum of a Base58 encoded string"""

    result = b58decode(v, alphabet=alphabet, autofix=autofix)
    result, check = result[:-4], result[-4:]
    digest = sha256(sha256(result).digest()).digest()

    if check != digest[:4]:
        raise ValueError("Invalid checksum")

    return result


def base58_encode(num):
    num = int(num, 16)
    encoded = ''
    while num:
        num, remainder = divmod(num, 58)
        encoded = BASE58_ALPHABET[remainder] + encoded
    return encoded

def base58_check_encode(payload, prefix=0x00):
    payload = bytes([prefix]) + payload
    checksum = sha256(sha256(payload).digest()).digest()[:4]
    return base58_encode(payload.hex() + checksum.hex())