from __future__ import annotations
import re
import hashlib
import hmac
import itertools
import secrets
import typing as t
import unicodedata
from .assest import BIP39
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor

PBKDF2_ROUNDS = 2048
WORDS_LIST = [word.lower() for word in re.findall('[A-Z][a-z]*', BIP39)]
WORDS_SET = set(WORDS_LIST)


class ConfigurationError(Exception):
    pass


# Refactored code segments from <https://github.com/keis/base58>
def b58encode(v: bytes) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    p, acc = 1, 0
    for c in reversed(v):
        acc += p * c
        p = p << 8

    string = ""
    while acc:
        acc, idx = divmod(acc, 58)
        string = alphabet[idx: idx + 1] + string
    return string


class Mnemonic(object):
    def __init__(self, language: str = "english", wordlist: list[str] | None = None):
        self.radix = 2048
        self.language = language

        if wordlist is None:
            wordlist = WORDS_LIST

        if len(wordlist) != self.radix:
            raise ConfigurationError(f"Wordlist must contain {self.radix} words.")

        self.wordlist = wordlist
        # Japanese must be joined by ideographic space
        self.delimiter = "\u3000" if language == "japanese" else " "

    @staticmethod
    @lru_cache(maxsize=1024)
    def normalize_string(txt: t.AnyStr) -> str:
        if isinstance(txt, bytes):
            utxt = txt.decode("utf8")
        elif isinstance(txt, str):
            utxt = txt
        else:
            raise TypeError("String value expected")

        return unicodedata.normalize("NFKD", utxt)

    def generate(self, strength: int = 128) -> str:
        if strength not in [128, 160, 192, 224, 256]:
            raise ValueError(
                "Invalid strength value. Allowed values are [128, 160, 192, 224, 256]."
            )
        return self.to_mnemonic(secrets.token_bytes(strength // 8))

    # Adapted from <http://tinyurl.com/oxmn476>
    def to_entropy(self, words: list[str] | str) -> bytearray:
        if not isinstance(words, list):
            words = words.split(" ")
        if len(words) not in [12, 15, 18, 21, 24]:
            raise ValueError(
                "Number of words must be one of the following: [12, 15, 18, 21, 24], but it is not (%d)."
                % len(words)
            )
        # Look up all the words in the list and construct the
        # concatenation of the original entropy and the checksum.
        concatLenBits = len(words) * 11
        concatBits = [False] * concatLenBits
        word_index = 0
        for word in words:
            # Find the words index in the wordlist
            ndx = self.wordlist.index(self.normalize_string(word))
            if ndx < 0:
                raise LookupError('Unable to find "%s" in word list.' % word)
            # Set the next 11 bits to the value of the index.
            for ii in range(11):
                concatBits[(word_index * 11) + ii] = (ndx & (1 << (10 - ii))) != 0
            word_index += 1
        checksumLengthBits = concatLenBits // 33
        entropyLengthBits = concatLenBits - checksumLengthBits
        # Extract original entropy as bytes.
        entropy = bytearray(entropyLengthBits // 8)
        for ii in range(len(entropy)):
            for jj in range(8):
                if concatBits[(ii * 8) + jj]:
                    entropy[ii] |= 1 << (7 - jj)
        # Take the digest of the entropy.
        hashBytes = hashlib.sha256(entropy).digest()
        hashBits = list(
            itertools.chain.from_iterable(
                [c & (1 << (7 - i)) != 0 for i in range(8)] for c in hashBytes
            )
        )
        # Check all the checksum bits.
        for i in range(checksumLengthBits):
            if concatBits[entropyLengthBits + i] != hashBits[i]:
                raise ValueError("Failed checksum.")
        return entropy

    def to_mnemonic(self, data: bytes) -> str:
        if len(data) not in [16, 20, 24, 28, 32]:
            raise ValueError(
                f"Data length should be one of the following: [16, 20, 24, 28, 32], but it is not {len(data)}."
            )
        h = hashlib.sha256(data).hexdigest()
        b = (
                bin(int.from_bytes(data, byteorder="big"))[2:].zfill(len(data) * 8)
                + bin(int(h, 16))[2:].zfill(256)[: len(data) * 8 // 32]
        )
        result = []
        for i in range(len(b) // 11):
            idx = int(b[i * 11: (i + 1) * 11], 2)
            result.append(self.wordlist[idx])
        return self.delimiter.join(result)

    def check(self, mnemonic: str) -> bool:
        mnemonic_list = self.normalize_string(mnemonic).split(" ")
        # list of valid mnemonic lengths
        if len(mnemonic_list) not in [12, 15, 18, 21, 24]:
            return False
        if not set(mnemonic_list).issubset(WORDS_SET):
            return False
        try:
            b = ''.join([bin(WORDS_LIST.index(word))[2:].zfill(11) for word in mnemonic_list])
            l = len(b)
            entropy_bits = l // 33 * 32
            checksum_bits = l - entropy_bits
            # Entropy Extraction Checksum
            entropy = int(b[:entropy_bits], 2).to_bytes(entropy_bits // 8, byteorder="big")
            hash_checksum = bin(int(hashlib.sha256(entropy).hexdigest(), 16))[2:].zfill(256)[:checksum_bits]
            # Checksum Validation Check
            return b[-checksum_bits:] == hash_checksum
        except ValueError:
            return False

    def expand_word(self, prefix: str) -> str:
        if prefix in self.wordlist:
            return prefix
        else:
            matches = [word for word in self.wordlist if word.startswith(prefix)]
            if len(matches) == 1:  # matched exactly one word in the wordlist
                return matches[0]
            else:
                # exact match not found.
                # this is not a validation routine, just return the input
                return prefix

    def expand(self, mnemonic: str) -> str:
        return " ".join(map(self.expand_word, mnemonic.split(" ")))

    @classmethod
    def to_seed(cls, mnemonic: str, passphrase: str = "") -> bytes:
        mnemonic = cls.normalize_string(mnemonic)
        passphrase = cls.normalize_string(passphrase)
        passphrase = "mnemonic" + passphrase
        mnemonic_bytes = mnemonic.encode("utf-8")
        passphrase_bytes = passphrase.encode("utf-8")
        stretched = hashlib.pbkdf2_hmac(
            "sha512", mnemonic_bytes, passphrase_bytes, PBKDF2_ROUNDS
        )
        return stretched[:64]

    @staticmethod
    def to_hd_master_key(seed: bytes, testnet: bool = False) -> str:
        if len(seed) != 64:
            raise ValueError("Provided seed should have length of 64")

        # Compute HMAC-SHA512 of seed
        seed = hmac.new(b"Bitcoin seed", seed, digestmod=hashlib.sha512).digest()

        # Serialization format can be found at: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
        # #serialization-format
        xprv = b"\x04\x88\xad\xe4"  # Version for private mainnet
        if testnet:
            xprv = b"\x04\x35\x83\x94"  # Version for private testnet
        xprv += b"\x00" * 9  # Depth, parent fingerprint, and child number
        xprv += seed[32:]  # Chain code
        xprv += b"\x00" + seed[:32]  # Master key

        # Double hash using SHA256
        hashed_xprv = hashlib.sha256(xprv).digest()
        hashed_xprv = hashlib.sha256(hashed_xprv).digest()

        # Append 4 bytes of checksum
        xprv += hashed_xprv[:4]

        # Return base58
        return b58encode(xprv)

    def check_multiple_mnemonics(self, mnemonics: list[str]) -> list[bool]:
        """
        Check multiple mnemonics for validity.

        :param: mnemonics: list of mnemonics
        :return: list of booleans
        """
        with ThreadPoolExecutor() as executor:
            results = list(executor.map(self.check, mnemonics))
        return results
