# Cryptofuzz (Tron)

In the following, you can see a collection of code fragments that can be implemented with the **Cryptofuzz** package for
the Tron currency, which is briefly included to introduce parts of this library.

```python
from cryptofuzz import Tron
import os

trx = Tron()
# -- Seed Key Bytes --
seed = os.urandom(32)
# -- Priv Hex --
privatekey = seed.hex()
# -- Tron Address --
Address = trx.hex_addr(privatekey)
# output: TAHQbx0t4LopDY77GBmxnMaXrecdgBKxTq
```

Tron Hex Address Format

```python
# -- Tron Hex Address From Seed (bytes) --
Address_Hex = trx.bytes_to_hex_addr(seed)
# or 
# -- Tron Hex Address From Private Key --
Address_Hex = trx.pvk_to_hex_addr(privatekey)
```

Tron Address From Decimal Number `int`

```python
# -- Tron Address From Decimal (Number - Integer) --
Address = trx.dec_to_addr(1234567890)
```
