# Generated and Convert TON Addresses With Standard Format

---

### basic chain (workchain 0)
```python
from cryptofuzz import Ton
ton = Ton(mainnet=True, workchain=0)
```

### masterchain (workchain -1)
```python
from cryptofuzz import Ton
ton = Ton(mainnet=True, workchain=-1)
```
---
```python
from cryptofuzz import Ton
ton = Ton(mainnet=True, workchain=-1)
# or
ton = Ton(mainnet=True, workchain=0) # default
```
testnet supported `mainnet=False`

### Convert Private Key (HEX) to User-Friendly TON Address (bounceable, Un-Bounceable)

```python
from cryptofuzz import Ton
ton = Ton(mainnet=True)
key = '0abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef'
# Convert private key to Bounceable TON address
baddr = ton.privatekey_to_address(key, True)
# Convert private key to Unbounceable TON address
uaddr = ton.privatekey_to_address(key, False)
```
- **Parameters `privatekey_to_address`**: in_privatekey: `str`, bounceable: `bool` (_default: True_)
- **Returns**: `str` address in Base64 format (`urlsafe_b64encode`)
- **Example**: `baddr = ton.privatekey_to_address('0abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef', True)`
- **Example**: `uaddr = ton.privatekey_to_address('0abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef', False)`

### Convert Mnemonic to User-Friendly TON Address (bounceable, Un-Bounceable)

```python
from cryptofuzz import Ton
ton = Ton(mainnet=True)
# Create mnemonic (Only : *24 words)
mnemonic = ('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon '
            'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about')
# Convert mnemonic to Bounceable TON address
baddr = ton.mnemonic_to_address(mnemonic, True)
# Convert mnemonic to Unbounceable TON address
uaddr = ton.mnemonic_to_address(mnemonic, False)
```
- **Parameters `mnemonic_to_address`**: mnemonic: `str`, bounceable: `bool` (_default: True_)
- **Returns**: `str` address in Base64 format (`urlsafe_b64encode`)
- **Example**: `baddr = ton.mnemonic_to_address('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about', True)`
- **Example**: `uaddr = ton.mnemonic_to_address('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about', False)`

### Convert Decimal Number To User-Friendly TON Address (bounceable, Un-Bounceable)

```python
from cryptofuzz import Ton
ton = Ton(mainnet=True)
# Convert decimal number to Bounceable TON address
baddr = ton.decimal_to_address(1234567890, True)
# Convert decimal number to Unbounceable TON address
uaddr = ton.decimal_to_address(1234567890, False)
```
- **Parameters `decimal_to_address`**: decimal_number: `int`, bounceable: `bool` (_default: True_)
- **Returns**: `str` address in Base64 format (`urlsafe_b64encode`)
- **Example**: `baddr = ton.decimal_to_address(1234567890, True)`
- **Example**: `uaddr = ton.decimal_to_address(1234567890, False)`
- **Note**: Decimal number must be less than `2^64 - 1`

### Convert User-Friendly TON Address To Raw Address

```python
from cryptofuzz import Ton
ton = Ton(mainnet=True)
addr = 'EQDlW5BbpUj6J0ApOxTlZ_CHYYR9NlPc3ahYQ8HtVlbQc6AA'
baddr = ton.raw_address(addr)
# output: 0:E55B905BA548FA2740293B14E567F08761847D3653DCDDA85843C1ED5656D073
```
- **Parameters `raw_address`**: address: `str`
- **Returns**: `str` address (hex - workchain 0, masterchain -1: 64 hex characters)

## Install Cryptofuzz with pip

```bash
pip install cryptofuzz
```
or use `pip install -U cryptofuzz` to upgrade.

## Install Cryptofuzz with pip3

```bash
pip3 install cryptofuzz
```
or use `pip3 install --upgrade cryptofuzz` to upgrade.

#### Programmer and Owner : [@Pymmdrza](https://github.com/Pymmdrza) | [Mmdrza.Com](https://mmdrza.com)
