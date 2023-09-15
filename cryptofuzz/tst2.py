import os
import binascii
import ecdsa
import hashlib
import base58


def generate_xprv():
    seed = os.urandom(64)
    return "xprv" + binascii.hexlify(seed).decode('utf-8')


def xprv_to_private_key(xprv):
    return binascii.unhexlify(xprv[4:])[:32]  # Take the first 32 bytes as the private key


def double_sha256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def ripemd160(data):
    h = hashlib.new('ripemd160')
    h.update(data)
    return h.digest()


def private_key_to_public_key(private_key):
    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    return sk.get_verifying_key()


def public_key_to_address(pubkey, compressed=True):
    # Get x and y coordinates from the public key
    x = pubkey.pubkey.point.x()
    y = pubkey.pubkey.point.y()

    if compressed:
        if y & 1:
            pubkey_bytes = b'\x03' + x.to_bytes(32, 'big')
        else:
            pubkey_bytes = b'\x02' + x.to_bytes(32, 'big')
    else:
        pubkey_bytes = b'\x04' + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')

    hashed_pubkey = ripemd160(double_sha256(pubkey_bytes))
    address_bytes = b'\x00' + hashed_pubkey
    checksum = double_sha256(address_bytes)[:4]

    return base58.b58encode(address_bytes + checksum).decode('utf-8')


def main():
    xprv = generate_xprv()
    print("XPRV:", xprv)

    private_key = xprv_to_private_key(xprv)
    public_key = private_key_to_public_key(private_key)

    compressed_address = public_key_to_address(public_key, compressed=True)
    uncompressed_address = public_key_to_address(public_key, compressed=False)

    print("Compressed Address:", compressed_address)
    print("Uncompressed Address:", uncompressed_address)


if __name__ == "__main__":
    main()
