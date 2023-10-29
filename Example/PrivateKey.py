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
