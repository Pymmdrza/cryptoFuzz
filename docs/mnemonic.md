
# Mnemonic (BIP39)

```python
from cryptofuzz import Mnemonic

mne = Mnemonic()

words = "abort able abandon ability absent absent attitude audio avoid baby badge bacon bag ban banana bank banner bar base basis bat battle battle bus busy buy buy bus"

seed = mne.to_seed(words)

```
