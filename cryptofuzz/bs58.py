from functools import lru_cache
from hashlib import sha256
from typing import Mapping, Union
from .assest import (
    BITCOIN_ALPHABET as ALPHABET,
    RIPPLE_ALPHABET as XRP_ALPHABET,
    BASE58_ALPHABET,
    MAIN_DIGEST_RMD160
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
        string = alphabet[idx:idx + 1] + string
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


def base58encodeCheck(prefix, payload):
    s = prefix + payload
    raw = sha256(sha256(s).digest()).digest()[:4]
    return base58encode(int.from_bytes(s + raw, 'big'))


def string_to_int(data):
    val = 0

    if type(data) == str:
        data = bytearray(data)

    for (i, c) in enumerate(data[::-1]):
        val += (256 ** i) * c
    return val


def encode_(data):
    enc = ""
    val = string_to_int(data)
    bs58size = len(BASE58_ALPHABET)
    while val >= bs58size:
        val, mod = divmod(val, bs58size)
        enc = BASE58_ALPHABET[mod] + enc
    if val:
        enc = BASE58_ALPHABET[val] + enc
    n = len(data) - len(data.lstrip(b"\0"))
    return BASE58_ALPHABET[0] * n + enc


def check_encode(raw):
    check = sha256(sha256(raw).digest()).digest()[:4]
    return encode_(raw + check)


def decode_(data):
    if isinstance(data, bytes):
        data = data.decode("ascii")

    val = 0
    prefix = 0
    bs58size = len(BASE58_ALPHABET)
    for cx in data:
        val = (val * bs58size) + BASE58_ALPHABET.find(cx)
        if val == 0:
            prefix += 1

    dec = bytearray()
    while val > 0:
        val, mod = divmod(val, 256)
        dec.append(mod)

    dec.extend(bytearray(prefix))
    return bytes(dec[::-1])


def check_decode(e):
    dec = decode_(e)
    raw, ck = dec[:-4], dec[-4:]
    if ck != sha256(sha256(raw).digest()).digest()[:4]:
        raise ValueError("base58 decoding checksum error")
    else:
        return raw


def base58encode(num):
    if num == 0:
        return BASE58_ALPHABET[0]
    arr = []
    while num:
        num, rem = divmod(num, 58)
        arr.append(BASE58_ALPHABET[rem])
    arr.reverse()
    return ''.join(arr)


def base58decode(raw):
    decoded = 0
    for char in raw:
        decoded = decoded * 58 + BASE58_ALPHABET.index(char)
    bytes_rep = decoded.to_bytes((decoded.bit_length() + 7) // 8, byteorder='big')
    landing = bytes_rep.lstrip(MAIN_DIGEST_RMD160)
    data_size = (len(raw) - len(landing))
    return MAIN_DIGEST_RMD160 * data_size + bytes_rep
