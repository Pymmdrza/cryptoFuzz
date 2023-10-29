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