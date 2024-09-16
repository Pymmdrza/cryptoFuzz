<div style="display: flex; justify-content: space-between; align-items: center;">


<img src="https://raw.githubusercontent.com/Pymmdrza/cryptoFuzz/gh-pages/doc/img/cryptoFuzz_Logo.png" title="Cryptofuzz / Generated and Converted Private and Public Key Very Easy On Python With cryptofuzz" alt="cryptofuzz python cryptography library" width="136" height="136"> 

</div> 

# CryptoFuzz

[![Read the Docs](https://img.shields.io/readthedocs/cryptofuzz)](https://cryptofuzz.readthedocs.io/en/latest 'cryptofuzz documentation') [![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/Pymmdrza/cryptoFuzz/python-publish.yml)](https://github.com/Pymmdrza/cryptoFuzz) [![GitHub commit check runs](https://img.shields.io/github/check-runs/Pymmdrza/cryptoFuzz/main)](https://github.com/Pymmdrza/cryptoFuzz)  [![GitHub last commit](https://img.shields.io/github/last-commit/Pymmdrza/cryptoFuzz)](https://github.com/Pymmdrza/cryptoFuzz)  [![GitHub commit activity](https://img.shields.io/github/commit-activity/m/Pymmdrza/cryptoFuzz)](https://github.com/Pymmdrza/cryptoFuzz)  [![GitHub top language](https://img.shields.io/github/languages/top/Pymmdrza/cryptoFuzz)](https://github.com/Pymmdrza/cryptoFuzz)  [![PyPI - Downloads](https://img.shields.io/pypi/dm/cryptoFuzz)](https://pypi.org/project/cryptofuzz/)  [![Website](https://img.shields.io/website?url=https%3A%2F%2Fcryptofuzz.readthedocs.io&up_color=blue&style=plastic)](https://cryptofuzz.readthedocs.io/en/latest)


## Installing & Quick Use

### Windows

On Windows, you can install CryptoFuzz using the following pip command:

```bash
pip install --upgrade cryptofuzz
```

### Linux & Mac

On Linux and macOS, you should use pip3 for installation:

```bash
pip3 install --upgrade cryptofuzz
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

[![](https://img.shields.io/badge/%20Update%20at-2024.09.16-009848?style=plastic)]() 
[![](https://img.shields.io/badge/More%20Detail-0049AB?style=plastic)](https://cryptofuzz.readthedocs.io/en/latest/tron/ 'cryptoFuzz - Tron')

Add Function for Convert Private Key To Hex Address
TRON :

- `cryptofuzz.hd.Tron.bytes_to_addr`
- `cryptofuzz.hd.Tron.bytes_to_hex_addr`
- `cryptofuzz.hd.Tron.pvk_to_hex_addr`

Add Function for Convert Decimal Number to Tron
Address :

- `cryptofuzz.hd.Tron.dec_to_addr`

---


[![](https://img.shields.io/badge/%20Update%20at-2024.09.07-009848?style=plastic)]() 

Add Function for checking mnemonic standard type :

- `cryptofuzz.utils.is_mnemonic`

```python
from cryptofuzz import Convertor

cn = Convertor()
isValid = cn.is_mnemonic("abandon ... help abandon flower")  # Mnemonic 12/18/24
```

---


[![](https://img.shields.io/badge/%20Update%20at-2024.08.24-009848?style=plastic)]() 


Add Short Key (Mini Private Key) Converter for bitcoin wallet. (Mini Private
Key : [More Detail's](https://en.bitcoin.it/wiki/Mini_private_key_format))

Short Key Like: `S6c56bnXQiBjk9mqSYE7ykVQ7NzrRy`

- Convert Short Key To Private Key (hex).
- Convert Short Key To Seed (bytes)
- Convert Short Key To Wif Compress and Uncompress.
- Convert Short Key To Decimal Number.

---

- More example follow : [Example/Source](https://github.com/Pymmdrza/cryptoFuzz/tree/main/Example)
- [Convert Private key To Bitcoin (All Format) Address With Cryptofuzz](https://guide.mmdrza.com/guidelines/cryptofuzz/private-key-to-bitcoin 'Private key To Bitcoin (All Format) Address')
- [Convert Private key To Ethereum Address With Cryptofuzz](https://guide.mmdrza.com/guidelines/cryptofuzz/private-key-to-ethereum 'Private key To Ethereum Address')
- [Convert Private key To TRON (TRX) Address With Cryptofuzz](https://guide.mmdrza.com/guidelines/cryptofuzz/private-key-to-tron-trx 'Private key To TRON (TRX) Address')
- [Convert Private key To Dogecoin Address With Cryptofuzz](https://guide.mmdrza.com/guidelines/cryptofuzz/private-key-to-dogecoin 'Private key To Dogecoin Address')
- [Convert Private key To Litecoin Address With Cryptofuzz](https://guide.mmdrza.com/guidelines/cryptofuzz/private-key-to-litecoin 'Private key To Litecoin Address ')
- [Convert Private key To Digibyte Address With Cryptofuzz](https://guide.mmdrza.com/guidelines/cryptofuzz/private-key-to-digibyte 'Private key To Digibyte')
- [Convert Private key To DASH Address With Cryptofuzz](https://guide.mmdrza.com/guidelines/cryptofuzz/private-key-to-dash 'Private key To DASH')
- [Convert Private key To Bitcoin Gold (BTG) Address With Cryptofuzz](https://guide.mmdrza.com/guidelines/cryptofuzz/private-key-to-bitcoin-gold 'Private key To Bitcoin Gold')
- [Convert Private key To Ravencoin (rvn) Address With Cryptofuzz](https://guide.mmdrza.com/guidelines/cryptofuzz/private-key-to-ravencoin 'Private key To Ravencoin (rvn) Address')

---

## Private Key

More details about private key convert in python with
cryptofuzz : [cryptofuzz/Example/Privatekey](https://guide.mmdrza.com/guidelines/cryptofuzz/example/private-key-hex 'cryptofuzz private key hex source code python')

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

## Wif

Convert From
Wif ( [More detail and Example](https://guide.mmdrza.com/guidelines/cryptofuzz/example/private-key-wif 'more detail wif convert with cryptofuzz') )

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

## Mnemonic

Convert From Mnemonic (BIP39) ( [More Detail](https://guide.mmdrza.com/guidelines/cryptofuzz/example/mnemonic) )

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

## Decimal

Convert From Decimal (Number) ( [More Detail](https://guide.mmdrza.com/guidelines/cryptofuzz/example/decimal) )

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

## Block

read block data from block file (bitcoin core sync data file's) [ `blk00001.dat` ]

```python
from cryptofuzz import block
import os

# path block file
path_data = os.path.join("BITCOIN_CORE_SYNC_BLOCK_FOLDER")
block_path = os.path.join(path_data, "blk00001.dat")  # first block file sync
# full block data
block_data = block.reader(block_path) 
```

---

## Command-Line Usage

After installing the `cryptofuzz` package, you can use the `cryptofuzz` command-line tool to perform various
cryptographic operations directly from your terminal.

### Examples

Here are some examples demonstrating how to use the `cryptofuzz` command-line tool:

### Generate a New Private Key

```bash
cryptofuzz --privatekey
```

**Output:**

```
Generating a new private key...
Private Key (Hex): 0x1e99423a4ed27608a15a2616c1...
WIF: L5BmW3B5xBv...
Public Key: 04a34b...
Bitcoin Address (P2PKH): 1BoatSLRHtKNngkdXEeobR76b53LETtpyT
Ethereum Address: 0x742d35Cc6634C0532925a3b844Bc454e4438f44e
...
```

### Generate a New Mnemonic Phrase

```bash
cryptofuzz --mnemonic
```

**Output:**

```
Generating a new mnemonic phrase...
Mnemonic: abandon amount liar amount expire adjust cage candy arch gather drum buyer
Seed: 5eb00bbddcf069084889a8ab9155568165f5c0...
Private Key: 0x8f2a559490...
Public Key: 04bfcab...
Bitcoin Address (P2PKH): 1HZwkCg...
Ethereum Address: 0xAb5801a7...
```

### Convert Private Key to Bitcoin Addresses

```bash
cryptofuzz --bitcoin
```

**Output:**

```
Converting private key to Bitcoin addresses...
Private Key (Hex): 0x1e99423a4ed27608a15a2616c1...
P2PKH Address: 1BoatSLRHtKNngkdXEeobR76b53LETtpyT
P2SH Address: 3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy
Bech32 Address: bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080
```

### Display Example Usages

```bash
cryptofuzz --example
```

**Output:**

```
Cryptofuzz Usage Examples:

1. Generate a new private key:
   cryptofuzz --privatekey

2. Generate a new mnemonic phrase:
   cryptofuzz --mnemonic

3. Convert a private key to Ethereum address:
   cryptofuzz --ethereum

4. Display help information:
   cryptofuzz --help
```

### Handling Incorrect Commands

If you enter an incorrect or unsupported command, `cryptofuzz` will suggest the closest matching command or prompt you
to view the help documentation.

**Example:**

```bash
cryptofuzz --bitcon
```

**Output:**

```bash
Unknown command '--bitcon'.
Did you mean '--bitcoin'?
For a list of available commands, type: cryptofuzz --help
```

### Display Help Information

To view detailed help information about all available commands, use the `--help` flag:

```bash
cryptofuzz --help
```

**Output:**

usage: `cryptofuzz [OPTIONS]`

### Example Cryptofuzz Operations

optional arguments:

- `-h`, `--help`            show this help message and exit
- `-p`, `--privatekey`      Generate a new private key and display associated data.
- `-m`, `--mnemonic`        Generate a new mnemonic phrase and display associated data.
- `-b`, `--bytes`           Generate a random byte sequence and display associated data.
- `-bin`,` --binary`        Generate a random binary string and display associated data.
- `-x`, `--xprv`            Generate a new extended private key (XPRV) and display associated data.
- `-d`, `--decimal`         Generate a random decimal number and display associated data.
- `-w`, `--wif`             Generate a new WIF key and display associated data.
- `-btc`, `--bitcoin`       Convert a private key to Bitcoin addresses.
- `-eth`, `--ethereum`      Convert a private key to an Ethereum address.
- `-dash`, `--dash`         Convert a private key to a Dash address.
- `-ltc`, `--litecoin`      Convert a private key to Litecoin addresses.
- `-doge`, `--dogecoin`     Convert a private key to a Dogecoin address.
- `-btg`, `--bitcoingold`   Convert a private key to a Bitcoin Gold address.
- `-qtum`, `--qtum `        Convert a private key to a Qtum address.
- `-zcash`, `--zcash `      Convert a private key to a Zcash address.
- `-rvn`, `--ravencoin`     Convert a private key to a Ravencoin address.
- `-ex`, `--example`        Display example usages of different commands.

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
