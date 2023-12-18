<div style="display: flex; justify-content: space-between; align-items: center;">


<img src="https://raw.githubusercontent.com/Pymmdrza/cryptoFuzz/gh-pages/doc/img/cryptoFuzz_Logo.png" title="Cryptofuzz / Generated and Converted Private and Public Key Very Easy On Python With cryptofuzz" alt="cryptofuzz python cryptography library" width="136" height="136"> 

</div> 

# CryptoFuzz



## Installing & Quick Use

### Windows

On Windows, you can install CryptoFuzz using the following pip command:

```bash
pip install cryptofuzz
```

### Linux & Mac

On Linux and macOS, you should use pip3 for installation:

```bash
pip3 install cryptofuzz
```

### Git

To use the latest version from the source, you can clone the CryptoFuzz repository:

1. Clone the repository:

```bash
git clone https://github.com/Pymmdrza/cryptofuzz
```

2. Navigate to the cloned directory:

```bash
cd cryptofuzz
```

3. Install the package:

### Windows

You can either run the `install.bat` or `install` command:

```bash
./install.bat
# or
./install
```

### Linux & Mac

On Linux and Mac, you can use the following commands to install:

```bash
bash install.sh
# or simply:
./install.sh
```

**Note:** If you face any permission issues on Linux, make the script executable using:

```bash
sudo chmod +x install.sh
```
---
### CLI

generated and converted private key (hex) , bytes (seed), wif compressed and uncompressed and mnemonic , Root Key (xprv) , XPUB, Decimal (Number) , Public Key and Binary To Compressed and Uncompressed Bitcoin Address :

- Generated Option : `--generate` and `-g`
- Total Generated and convereted Key Option: `--total`, `-t` (integer/number type)
- Saved all Details and full information to `JSON file (OutputFile.json)` option `--save` and `-s`
this example just generated `1000` key without save details
```shell
# windows
cryptofuzz --generate --total 1000
# linux & mac
cryptofuzz --generate --total 1000
```
example Generated `1000` Key and saved to `OutputFile.json`:
```shell
# windows
cryptofuzz -g -t 1000 -s
# linux & mac
cryptofuzz --generate --total 1000 --save
# or can use : -g -t 1000 -s
```
**Run this command anywhere in your system (in any Path folder) Saved `OutputFile.json`**


create with CryptoFuzz, you can see from the `example` section with the following `cryptofuzz-example` command in your terminal:


#### Generated example Private Key From CLI `cryptofuzz-example` :


all option command for windows `cryptofuzz-example OPTION` and Linux or Mac `cryptofuzz-example OPTION` :

- Generated `private key` (hex) & Converted : `cryptofuzz-example privatekey`
- Generated `bytes` & Converted : `cryptofuzz-example bytes`
- Generated `mnemonic` & Converted : `cryptofuzz-example mnemonic`
- Generated `wif` & Converted : `cryptofuzz-example wif`
- Generated `binary` & Converted : `cryptofuzz-example binary`
- Generated Root Key (`xprv`) & Converted : `cryptofuzz-example xprv`
- Generated `decimal` & Converted : `cryptofuzz-example decimal`

Generated and Converted Private Key (HEX) To another cryptocurrency:
- Generated Private Key (Hex) and Converted To Ethereum Address [Example command]:
```shell
# windows
cryptofuzz-example ethereum
# linux and macOs:
cryptofuzz-example ethereum
```
- Generated Private Key (Hex) and Converted To bitcoin Address [Example command]:
```shell
# windows
cryptofuzz-example bitcoin
# linux and macOs:
cryptofuzz-example bitcoin
```
- Generated Private Key (Hex) and Converted To dash Address [Example command]:
```shell
# windows
cryptofuzz-example dash
# linux and macOs:
cryptofuzz-example dash
```
- Generated Private Key (Hex) and Converted To dogecoin Address [Example command]:
```shell
# windows
cryptofuzz-example dogecoin
# linux and macOs:
cryptofuzz-example dogecoin
```
- Generated Private Key (Hex) and Converted To digibyte Address [Example command]:
```shell
# windows
cryptofuzz-example digibyte
# linux and macOs:
cryptofuzz-example digibyte
```
- Generated Private Key (Hex) and Converted To Bitcoin Gold Address [Example command]:
```shell
# windows
cryptofuzz-example bitcoingold
# linux and macOs:
cryptofuzz-example bitcoingold
```
- Generated Private Key (Hex) and Converted To qtum Address [Example command]:
```shell
# windows
cryptofuzz-example qtum
# linux and macOs:
cryptofuzz-example qtum
```
- Generated Private Key (Hex) and Converted To zcash Address [Example command]:
```shell
# windows
cryptofuzz-example zcash
# linux and macOs:
cryptofuzz-example zcash
```
- Generated Private Key (Hex) and Converted To Ravencoin Address [Example command]:
```shell
# windows
cryptofuzz-example rvn
# linux and macOs:
cryptofuzz-example rvn
```
- Generated Private Key (Hex) and Converted To Litecoin Address [Example command]:
```shell
# windows
cryptofuzz-example litecoin
# linux and macOs:
cryptofuzz-example litecoin
```

---

### Private Key

```python
from cryptofuzz import Convertor, Generator
# // Convertor and Generator Shortcut
conv = Convertor()
gen = Generator()
# // Generate private key
privatekey = gen.generate_private_key()
# // Convert private key To bytes
seed = conv.hex_to_bytes(privatekey)
# // Convert private key To mnemonic
mnemonic = conv.hex_to_mne(privatekey)
# // Convert private key To wif compress
wif_compress = conv.hex_to_wif(privatekey, True)
# // Convert private key To wif uncompress
wif_uncompress = conv.hex_to_wif(privatekey, False)
# // Convert private key To decimal number
dec = conv.hex_to_int(privatekey)
# // Convert private key To binary
binary_str = conv.hex_to_binary(privatekey)
# // Convert private key To xprv
xprv = conv.hex_to_xprv(privatekey)
# // Convert private key To xpub
xpub = conv.hex_to_xpub(privatekey)
# // Convert private key To compress address
compress_address = conv.hex_to_addr(privatekey, True)
# // Convert private key To uncompress address
uncompress_address = conv.hex_to_addr(privatekey, False)
```

### Wif 

Convert From Wif 

```python
import os
from cryptofuzz import Convertor

conv = Convertor()

# // generate byte
byte = os.urandom(32)
# // convert Byte To wif
wif = conv.bytes_to_wif(byte)
# // wif to mnemonic
mnemonic = conv.wif_to_mne(wif)
# // Convert Wif To Hex
privatekey = conv.wif_to_hex(wif)
# // Convert bytes To WIF Uncompress
wif_uncompress = conv.bytes_to_wif(byte, False)
# // Convert Wif To Decimal Number
dec = conv.wif_to_int(wif)
# // Convert Wif To Binary
binary_str = conv.wif_to_binary(wif)
# // Convert Wif To xprv
xprv = conv.wif_to_xprv(wif)
# // Convert Wif To xpub
xpub = conv.wif_to_xpub(wif)
# // Convert Wif To compress address
compress_address = conv.wif_to_addr(wif, True)
# // Convert Wif To uncompress address
uncompress_address = conv.wif_to_addr(wif, False)

```

### Mnemonic

Convert From Mnemonic (BIP39)

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
```
---

### Decimal

Convert From Decimal (Number)

```python
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

```



---

More example follow : [Example](https://github.com/Pymmdrza/cryptoFuzz/tree/main/Example)

---

### contact


Programmer & Owner : Mr. [PyMmdrza](https://github.com/Pymmdrza)



Email : PyMmdrza@Gmail.Com

Github: [cryptofuzz/cryptofuzz](https://github.com/Pymmdrza/cryptoFuzz)

Document: [cryptofuzz](https://pymmdrza.github.io/cryptoFuzz)

---
### Donate:

Bitcoin (BTC): `1MMDRZA12xdBLD1P5AfEfvEMErp588vmF9`

Ethereum & USDT (ERC20): `0x348e3C3b17784AafD7dB67d011b85F838F16E2D1`

USDT & TRON (TRC20): `TR4mA5quGVHGYS186HKDuArbD8SVssiZVx`

Litecoin (LTC): `ltc1qtgvxc6na9pxvznu05yys3j5rq9ej6kahe2j50v`
