from . import Convertor, Generator
from .Wallet import (

    # Conversions related to Binary ------------------------------------------------------------

    Binary_To_Address,  # Convert binary to address
    Binary_To_Decimal,  # Convert binary to decimal Number
    Binary_To_Bytes,  # Convert binary to bytes
    Binary_To_Mnemonic,  # Convert binary to mnemonic
    Binary_To_PrivateKey,  # Convert binary to private key
    Binary_To_PublicKey,  # Convert binary to publickey
    Binary_To_Wif,  # Convert binary to WIF
    Binary_To_XPRV,  # Convert binary to XPRV
    
    # Conversions related to Bytes ------------------------------------------------------------
    
    Bytes_To_Address,  # Convert bytes to address
    Bytes_To_Binary,  # Convert bytes to binary
    Bytes_To_Mnemonic,  # Convert bytes to mnemonic
    Bytes_To_PrivateKey,  # Convert bytes to privatekey
    Bytes_To_PublicKey,  # Convert bytes to publickey
    Bytes_To_Wif,  # Convert bytes to WIF
    Bytes_To_XPRV,  # Convert bytes to XPRV
    Bytes_To_XPUB,  # Convert bytes to XPUB
    
    # Conversions related to Decimal ------------------------------------------------------------

    Decimal_To_Address,  # Convert decimal to address
    Decimal_To_Binary,  # Convert decimal to binary
    Decimal_To_Bytes,  # Convert decimal to bytes
    Decimal_To_Mnemonic,  # Convert decimal to mnemonic
    Decimal_To_Wif,  # Convert decimal to WIF
    Decimal_To_XPRV,  # Convert decimal to XPRV


    # Generate Random Keys ------------------------------------------------------------------------
    Decimal_To_XPUB,                                                          # Convert decimal to XPUB
    getBinary,                                                                # Generate random Binary With Length 256 (256 bits).
    getBytes,                                                                 # Generate Random Seed (Bytes - Without Repeating).
    getDecimal,                                                               # Generate Random Decimal Number.
    getMnemonic,                                                              # Generate Random Standard Mnemonic BIP39.
    getPrivateKey,                                                            # Generate a private key without repeating.
    getRootKey,                                                               # Generate a root key.

    # Conversions related to Mnemonic ------------------------------------------------------------

    Mnemonic_To_Addr,                                                         # Convert mnemonic to address
    Mnemonic_To_Binary,                                                       # Convert mnemonic to binary
    Mnemonic_To_Bytes,                                                        # Convert mnemonic to bytes
    Mnemonic_To_Decimal,                                                      # Convert mnemonic to decimal
    Mnemonic_To_PrivateKey,                                                   # Convert mnemonic to privatekey
    Mnemonic_To_PublicKey,                                                    # Convert mnemonic to publickey
    Mnemonic_To_Wif,                                                          # Convert mnemonic to WIF
    Mnemonic_To_XPRV,                                                         # Convert mnemonic to XPRV
    Mnemonic_To_XPUB,                                                         # Convert mnemonic to XPUB

    # Conversions related to Passphrase ------------------------------------------------------------

    Passphrase_To_Addr,                                                       # Convert passphrase to address
    Passphrase_To_Bytes,                                                      # Convert passphrase to bytes
    Passphrase_To_Decimal,                                                    # Convert passphrase to decimal representation
    Passphrase_To_PrivateKey,                                                 # Convert passphrase to privatekey
    Passphrase_To_PublicKey,                                                  # Convert passphrase to publickey
    Passphrase_To_RootKey,                                                    # Convert passphrase to rootkey
    Passphrase_To_Wif,                                                        # Convert passphrase to WIF
    Passphrase_To_XPUB,                                                       # Convert passphrase to XPUB

    # Conversions related to Private Keys ------------------------------------------------------------

    PrivateKey_To_Addr,                                                       # Convert private key to address
    PrivateKey_To_Binary,                                                     # Convert private key to binary representation
    PrivateKey_To_Byte,                                                       # Convert private key to bytes
    PrivateKey_To_CompressAddr,                                               # Convert private key to compressed address
    PrivateKey_To_Decimal,                                                    # Convert private key to decimal representation (appears twice, may want to remove one)
    PrivateKey_To_Mnemonic,                                                   # Convert private key to mnemonic
    PrivateKey_To_UncompressAddr,                                             # Convert private key to uncompressed address
    PrivateKey_To_Wif,                                                        # Convert private key to WIF
    PrivateKey_To_XPRV,                                                       # Convert private key to XPRV
    PrivateKey_To_XPUB,                                                       # Convert private key to XPUB

    # Conversions related to WIF ------------------------------------------------------------

    Wif_To_Addr,                                                             # Convert WIF to address
    Wif_To_Binary,                                                           # Convert WIF to binary
    Wif_To_Bytes,                                                            # Convert WIF to bytes
    Wif_To_Decimal,                                                          # Convert WIF to decimal
    Wif_To_Mnemonic,                                                         # Convert WIF to mnemonic
    Wif_To_PrivateKey,                                                       # Convert WIF to privatekey
    Wif_To_PublicKey,                                                        # Convert WIF to publickey
    Wif_To_RootKey,                                                          # Convert WIF to rootkey
    Wif_To_XPRV,                                                             # Convert WIF to XPRV
    Wif_To_XPUB,                                                             # Convert WIF to XPUB
    
    # Conversions related to XPRV ------------------------------------------------------------

    XPRV_To_Address,                                                         # Convert XPRV to address compressed & uncompressed
    XPRV_To_Wif,                                                             # Convert XPRV to WIF compressed & uncompressed
    XPRV_To_XPUB,                                                            # Convert XPRV to XPUB
    XPRV_To_Bytes,                                                           # Convert XPRV to bytes
    XPRV_To_Mnemonic,                                                        # Convert XPRV to mnemonic
    XPRV_To_PrivateKey,                                                      # Convert XPRV to privatekey
    XPRV_To_PublicKey,                                                       # Convert XPRV to publickey compressed & uncompressed
    XPRV_To_Decimal,                                                         # Convert XPRV to decimal
)
