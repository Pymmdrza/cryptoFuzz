# CryptoFuzz
---

[Installation](#installation) | [Example](/example) | [Donate](#donate) | [Contact](#contact)

---

### installation

cryptofuzz Python Package for Generate and Converting Wallet Private Key and Mnemonic for Address Bitcoin

```bash
# on windows
pip install cryptofuzz

# on Linux
pip3 install cryptofuzz
```

if problem on installing on linux / debian :
```bash
sudo apt-get update&&sudo apt-get upgrade -y
sudo apt-get install -y autoconf automake build-essential libffi-dev libtool pkg-config python3-dev
```

or for download manual:
```bash
git clone https://github.com/cryptofuzz/cryptofuzz
cd cryptofuzz
make
```
---

### Private Key

generated random private key without repeat :

```python
from cryptofuzz import getPrivateKey

Privatekey = getPrivateKey()
```
---
### Mnemonic
Generated random mnemonic with standard size :
```python
from cryptofuzz import getMnemonic
# default size 12 . can use [12, 18, 24]
mnemonicString = getMnemonic(size=12)
```
----
### Bytes (seed)

Generated Random Bytes Without Repeat :

```python
from cryptofuzz import getBytes
byte = getBytes()
```
---
### Binary
Generate Random Binary Without repeat `0/1`:

```python
from cryptofuzz import getBin

binary_string = getBin(256)
```
---
### Private Key To Bytes
```python
from cryptofuzz import PrivateKey_To_Bytes

privatekey = Wallet.getPrivateKey()
# Convert Private Key HEX To Bytes SEED
byte = Wallet.PrivateKey_To_Bytes(privatekey)

```
---
### Private Key To Wif

generated private key (hex) and convert to wif compressed and uncompressed.
```python
from cryptofuzz import getPrivateKey, PrivateKey_To_Wif

privatekey = getPrivateKey()
# Convert Private key Hex To Wif
#  compressed
wif_compress = PrivateKey_To_Wif(privatekey, compress=True)
# wif Uncompressed
wif_uncompress = PrivateKey_To_Wif(privatekey, compress=False)
```
---
### Private Key To Mnemonic

```python
from cryptofuzz import getPrivateKey, PrivateKey_To_Mnemonic

privatekey = getPrivateKey()
# convert private key [hex] To mnemonic
mnemonic_string = PrivateKey_To_Mnemonics(privatekey)
# for size mnemonic can use [12, 18, 24]
```
---
### Private Key To Binary

```python
from cryptofuzz import getPrivateKey, PrivateKey_To_Binary

privatekey = getPrivateKey()

# convert hex to bin
binary_string = PrivateKey_To_Binary(privatekey)
```
---
### Private Key To Decimal (int)
```python
from cryptofuzz import getPrivateKey, PrivateKey_To_Decimal

privatekey = getPrivateKey()
# convert private key hex to number (dec)
dec = PrivateKey_To_Decimal(privatekey)
```
---
### Private Key To Address

convert private key `Hex` to Compress and Uncompress Address
```python
from cryptofuzz import getPrivateKey, PrivateKey_To_Wif

privatekey = getPrivateKey()
# convert private key to compress address
compress_Address = PrivateKey_To_Address(privatekey, compress=True)
# convert to uncompress address
uncompress_Address = PrivateKey_To_Address(privatekey, compress=False)
```
---
### Private Key To Public Key

generated private key and convert to public key compress and uncompress:

```python
from cryptofuzz import getPrivateKey, PrivateKey_To_PublicKey

privatekey = getPrivateKey()
# convert to public key uncompress
public_uncompress = PrivateKey_To_PublicKey(privatekey)
# convert private key hex to public key compress
public_compress = PrivateKey_To_PublicKey(privatekey, compress=True)
```
---
### Bytes To Private Key
```python
from cryptofuzz import getBytes, Bytes_To_PrivateKey

byte = getBytes()
# convert bytes to hex (private key)
privatekey = Bytes_To_PrivateKey(byte)
```
### Bytes To mnemonic 
convert bytes to mnemonic with default `size=12`

can use standard sizr: `12, 18, 24`

```python
from cryptofuzz import getBytes, Bytes_To_Mnemonic

byte = getBytes()
# Convert bytes to mnemonic with default size 12
mnemonic_words = Bytes_To_Mnemonic(byte)
```
---
### Bytes To Wif
convert bytes To wif Compress and uncompress:
```python
from cryptofuzz import getBytes, Bytes_To_Wif

byte = getBytes()
# compress wif
wif_compress = Bytes_To_Wif(byte, compress=True)
#uncompress Wif
wif_uncompress = Bytes_To_Wif(byte, compress=False)
```
---
### Bytes To Public Key

convert bytes to public key compress and uncompress
```python
from cryptofuzz import getBytes, Bytes_To_PublicKey

byte = getBytes()
# compress Publickey
Pub_compress = Bytes_To_PublicKey(byte, compress=True)
#uncompress Wif
Pub_uncompress = Bytes_To_PublicKey(byte, compress=False)
```
---
### Bytes to Dec (number)

convert bytes to decimal number

```python
from cryptofuzz import getBytes, Bytes_To_Decimal

byte = getBytes()
#convert to integer 
dec = Bytes_To_Decimal(byte)
```
---
### Wif To Public Key
convert wif to public key compress and uncompress
```python
from cryptofuzz import Wif_To_PublicKey

wif = "WIF_STRING_HERE"
pub_compress = Wif_To_PublicKey(wif, compress=True)
pub_uncompress = Wif_To_PublicKey(wif, compress=False)
```
---
### Wif To Mnemonic 
convert Wif To Mnemonic With Default `size=12`
```python
from cryptofuzz import Wif_To_Mnemonic

wif = "WIF_STRING_HERE"
mnemonic_string = Wif_To_Mnemonic(wif)
```
---
### Passphrase To Compress And Uncompress Address
```python
from cryptofuzz.Wallet import *

passphrase = "Mmdrza.com"
compress_address = Passphrase_To_Address(passphrase, True)
uncompress_address = Passphrase_To_Address(passphrase, False)

```
### Generated XPRV and XPUB :

```python
from cryptofuzz.Wallet import *

seed = getBytes()

xprv = Bytes_To_XPRV(seed)

xpub = Bytes_To_XPUB(seed)

```

---

### contact

Programmer & Owner : Mmdrza.Com

Email : PyMmdrza@Gmail.Com

Github: [cryptofuzz/cryptofuzz](https://github.com/Pymmdrza/cryptofuzz)

Document: [cryptofuzz](https://github.com/Pymmdrza/cryptofuzz)

---
### Donate:

Bitcoin (BTC): `1MMDRZA12xdBLD1P5AfEfvEMErp588vmF9`

Ethereum & USDT (ERC20): `0x348e3C3b17784AafD7dB67d011b85F838F16E2D1`

USDT & TRON (TRC20): `TR4mA5quGVHGYS186HKDuArbD8SVssiZVx`

Litecoin (LTC): `ltc1qtgvxc6na9pxvznu05yys3j5rq9ej6kahe2j50v`
