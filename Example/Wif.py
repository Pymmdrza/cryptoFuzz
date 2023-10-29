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