# Cryptofuzz - Tron (trx)

In the following, you can see a collection of code fragments that can be implemented with the Cryptofuse package for the Tron currency, which is briefly included to introduce parts of this library.

```python
from cryptofuzz import Tron
import os
# -- Shortcut Class --
trx = Tron()
# -- Seed Key Bytes --
seed = os.urandom(32)
# -- Priv Hex --
privatekey = seed.hex()
# -- Tron Address --
Address = trx.hex_addr(privatekey)
# output: TAHQbx0t4LopDY77GBmxnMaXrecdgBKxTq
```
### Private Key (Hex) To Tron Hex Address

```python
# -- Tron Hex Address From Seed (bytes) --
Address_Hex = trx.bytes_to_hex_addr(seed)
# or 
# -- Tron Hex Address From Private Key --
Address_Hex = trx.pvk_to_hex_addr(privatekey)
```

### Seed (bytes) Key To Tron Hex Address

```python
# -- Tron Hex Address From Seed (bytes) --
Address_Hex = trx.bytes_to_hex_addr(seed)
```
