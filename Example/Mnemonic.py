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