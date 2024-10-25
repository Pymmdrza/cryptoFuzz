# Example Use Cryptofuzz

## Decimal 

Generated and Converted Decimal (Number) For Bitcoin Address Wallet

```python
import os

from cryptofuzz import Convertor, Generator

conv = Convertor()
gen = Generator()


# generate random number decimal
dec = gen.generate_decimal()
# decimal to mnemonic
mnemonic = conv.int_to_mnemonic(dec)
# Convert decimal To Hex
privatekey = conv.int_to_hex(dec)
# Convert decimal To WIF Compress
wif_compress = conv.int_to_wif(dec, True)
# Convert decimal To WIF Uncompress
wif_uncompress = conv.int_to_wif(dec, False)
# Convert Wif To Binary
binary_str = conv.int_to_binary(dec)
# Convert Wif To xprv
xprv = conv.int_to_xprv(dec)
# Convert Wif To xpub
xpub = conv.int_to_xpub(dec)
# Convert Wif To compress address
compress_address = conv.int_to_addr(dec, True)
# Convert Wif To uncompress address
uncompress_address = conv.int_to_addr(dec, False)
# Output
print('Private key', privatekey)
print('Mnemonic', mnemonic)
print('Compress address', compress_address)
print('Uncompress address', uncompress_address)
print('Wif', wif_compress)
print('WIF uncompress', wif_uncompress)
print('Dec', dec)
print('Binary', binary_str)
print('XPRV', xprv)
print('XPUB', xpub)
```

---

## Mnemonic

Convert and Generated Mnemonic For Bitcoin Wallet address

```python
from cryptofuzz import Convertor, Generator

conv = Convertor()
gen = Generator()

# Generate Mnemonic
mnemonic = gen.generate_mnemonic(12)
# Convert Mnemonic To Seed Bytes
seed = conv.mne_to_bytes(mnemonic)
# Convert Mnemonic To Hex
privatekey = conv.mne_to_hex(mnemonic)
# Convert Mnemonic To WIF Compress
wif_compress = conv.mne_to_wif(mnemonic, True)
# Convert Mnemonic To WIF Uncompress
wif_uncompress = conv.mne_to_wif(mnemonic, False)
# Convert Mnemonic To Decimal Number
dec = conv.mne_to_int(mnemonic)
# Convert Mnemonic To Binary
binary_str = conv.mne_to_binary(mnemonic)
# Convert Mnemonic To xprv
xprv = conv.mne_to_xprv(mnemonic)
# Convert Mnemonic To xpub
xpub = conv.mne_to_xpub(mnemonic)
# Convert Mnemonic To compress address
compress_address = conv.mne_to_addr(mnemonic, True)
# Convert Mnemonic To uncompress address
uncompress_address = conv.mne_to_addr(mnemonic, False)
# Output
print('Private key', privatekey)
print('Compress address', compress_address)
print('Uncompress address', uncompress_address)
print('Mnemonic', mnemonic)
print('Seed', seed)
print('WIF compress', wif_compress)
print('WIF uncompress', wif_uncompress)
print('Dec', dec)
print('Binary', binary_str)
print('XPRV', xprv)
print('XPUB', xpub)
```

---

## Private Key

Generated and Converted Private Key (Hex) To Bitcoin Wallet With Cryptofuzz

```python
from cryptofuzz import Convertor, Generator


conv = Convertor()
gen = Generator()
# Generate private key
privatekey = gen.generate_private_key()
# Convert private key To bytes
seed = conv.hex_to_bytes(privatekey)
# Convert private key To mnemonic
mnemonic = conv.hex_to_mne(privatekey)
# Convert private key To wif compress
wif_compress = conv.hex_to_wif(privatekey, True)
# Convert private key To wif uncompress
wif_uncompress = conv.hex_to_wif(privatekey, False)
# Convert private key To decimal number
dec = conv.hex_to_int(privatekey)
# Convert private key To binary
binary_str = conv.hex_to_binary(privatekey)
# Convert private key To xprv
xprv = conv.hex_to_xprv(privatekey)
# Convert private key To xpub
xpub = conv.hex_to_xpub(privatekey)
# Convert private key To compress address
compress_address = conv.hex_to_addr(privatekey, True)
# Convert private key To uncompress address
uncompress_address = conv.hex_to_addr(privatekey, False)

print('Private key', privatekey)
print('Compress address', compress_address)
print('Uncompress address', uncompress_address)
print('Mnemonic', mnemonic)
print('Seed', seed)
print('WIF compress', wif_compress)
print('WIF uncompress', wif_uncompress)
print('Dec', dec)
print('Binary', binary_str)
print('XPRV', xprv)
print('XPUB', xpub)
```

---

## WIF

```python
import os
from cryptofuzz import Convertor, Generator

conv = Convertor()
gen = Generator()

# generate byte
byte = os.urandom(32)
# convert Byte To wif
wif = conv.bytes_to_wif(byte)
# wif to mnemonic
mnemonic = conv.wif_to_mne(wif)
# Convert Wif To Hex
privatekey = conv.wif_to_hex(wif)
# Convert bytes To WIF Uncompress
wif_uncompress = conv.bytes_to_wif(byte, False)
# Convert Wif To Decimal Number
dec = conv.wif_to_int(wif)
# Convert Wif To Binary
binary_str = conv.wif_to_binary(wif)
# Convert Wif To xprv
xprv = conv.wif_to_xprv(wif)
# Convert Wif To xpub
xpub = conv.wif_to_xpub(wif)
# Convert Wif To compress address
compress_address = conv.wif_to_addr(wif, True)
# Convert Wif To uncompress address
uncompress_address = conv.wif_to_addr(wif, False)
# Output
print('Private key', privatekey)
print('Mnemonic', mnemonic)
print('Compress address', compress_address)
print('Uncompress address', uncompress_address)
print('Wif', wif)
print('WIF uncompress', wif_uncompress)
print('Dec', dec)
print('Binary', binary_str)
print('XPRV', xprv)
print('XPUB', xpub)
```
