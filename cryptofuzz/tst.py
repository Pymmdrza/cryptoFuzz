from utils import *

import os


pvk = os.urandom(32).hex()

seed = hex_to_bytes(pvk)

pub = bytes_to_pub(seed)

caddr = pub_to_addr(pub, True)
uaddr = pub_to_addr(pub, False)

print(f"Private Key: {pvk}")
print(f"Seed: {seed}")
print(f"Public Key: {pub}")
print(f"Compressed Address: {caddr}")
print(f"Uncompressed Address: {uaddr}")

