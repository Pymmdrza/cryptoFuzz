
# Mnemonic (BIP39)

```python
from cryptofuzz import Mnemonic

# -- Mnemonic Object
mnemonic = Mnemonic("english")

# -- Generate Mnemonic With Standard Size
generate_mnemonic = mnemonic.generate(strength=128)

# -- Check Valid Mnemonic
is_mnemonic = mnemonic.check(generate_mnemonic)
```
