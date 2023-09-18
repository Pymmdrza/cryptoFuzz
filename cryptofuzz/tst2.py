import hashlib
import struct
import binascii

BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'


def base58encode(num):
    """Encode a number using Base58."""
    if num == 0:
        return BASE58_ALPHABET[0]
    arr = []
    while num:
        num, rem = divmod(num, 58)
        arr.append(BASE58_ALPHABET[rem])
    arr.reverse()
    return ''.join(arr)


def base58encodeCheck(prefix, payload):
    """Encode a byte string using Base58 with a 4-byte checksum."""
    s = prefix + payload
    raw = hashlib.sha256(hashlib.sha256(s).digest()).digest()[:4]
    return base58encode(int.from_bytes(s + raw, 'big'))


def byte_to_xprv(byte_code):
    # Default chain code
    chain_code = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")
    # Main map xprv
    xprv_version = b'\x04\x88\xAD\xE4'  # for bitcoin version
    depth = b'\x00'  # zero depth
    parent_fingerprint = b'\x00\x00\x00\x00'  # main key
    child_number = struct.pack('>L', 0)  # child number for main key
    key = b'\x00' + byte_code  # 0x00 + private key

    xprv_main = xprv_version + depth + parent_fingerprint + child_number + chain_code + key

    return base58encodeCheck(b"", xprv_main)


# Test
byte_code = binascii.unhexlify("c37c299bb6d7ab2c9a2e6da66e9b69404b25bb209e377e9f6a37f1f3e7c2928c")
print(byte_to_xprv(byte_code))
