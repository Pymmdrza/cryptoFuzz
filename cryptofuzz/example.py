# example cryptofuzz
import sys
from .Wallet import *

red = "\033[91m"
green = "\033[92m"
yellow = "\033[93m"
magenta = "\033[95m"
cyan = "\033[96m"
white = "\033[97m"
reset = "\033[0m"


def example_privatekey():
    private_key = getPrivateKey()
    wif_compress = PrivateKey_To_Wif(private_key, compress=True)
    wif_Uncompress = PrivateKey_To_Wif(private_key, compress=False)
    publicKey_compress = PrivateKey_To_PublicKey(private_key, compress=True)
    publicKey_uncompress = PrivateKey_To_PublicKey(private_key, compress=False)
    xprv = PrivateKey_To_XPRV(private_key)
    xpub = PrivateKey_To_XPUB(private_key)
    dec = PrivateKey_To_Decimal(private_key)
    compress_address = PrivateKey_To_CompressAddr(private_key)
    uncompress_address = PrivateKey_To_UncompressAddr(private_key)
    print(f"{cyan}Private Key (HEX)    {reset}: {private_key}")
    print(f"{cyan}WIF Compress         {reset}: {wif_compress}")
    print(f"{cyan}WIF Uncompress       {reset}: {wif_Uncompress}")
    print(f"{cyan}Root Key (XPRV)      {reset}: {xprv}")
    print(f"{cyan}XPUB                 {reset}: {xpub}")
    print(f"{cyan}Public Key Compress  {reset}: {publicKey_compress}")
    print(f"{cyan}Public Key Uncompress{reset}: {publicKey_uncompress}")
    print(f"{cyan}Decimal              {reset}: {dec}")
    print(f"{cyan}Compress Address     {reset}: {compress_address}")
    print(f"{cyan}Uncompress Address   {reset}: {uncompress_address}")
    print(f"\n[*] {red}All Converted Data From Private Key (HEX){reset}.")


def example_mnemonic():
    mne = getMnemonic(12)
    wif_compress = Mnemonic_To_Wif(mne, True)
    wif_uncompress = Mnemonic_To_Wif(mne, False)
    public_compress = Mnemonic_To_PublicKey(mnemonic=mne, compress=True)
    public_uncompress = Mnemonic_To_PublicKey(mnemonic=mne, compress=False)
    xprv = Mnemonic_To_XPRV(mnemonic=mne)
    xpub = Mnemonic_To_XPUB(mnemonic=mne)
    dec = Mnemonic_To_Decimal(mnemonic=mne)
    address_compress = Mnemonic_To_Addr(mnemonic=mne, compress=True)
    address_uncompress = Mnemonic_To_Addr(mnemonic=mne, compress=False)
    print(f"{cyan}Mnemonic              {reset}: {mne}")
    print(f"{cyan}WIF Compress          {reset}: {wif_compress}")
    print(f"{cyan}WIF Uncompress        {reset}: {wif_uncompress}")
    print(f"{cyan}Public Key Compress   {reset}: {public_compress}")
    print(f"{cyan}Public Key Uncompress {reset}: {public_uncompress}")
    print(f"{cyan}XPUB                  {reset}: {xpub}")
    print(f"{cyan}XPRV                  {reset}: {xprv}")
    print(f"{cyan}Decimal               {reset}: {dec}")
    print(f"{cyan}Address Compress      {reset}: {address_compress}")
    print(f"{cyan}Address Uncompress    {reset}: {address_uncompress}")
    print(f"[*] {red}All Converted Data From Mnemonic (BIP39){reset}.")


def example_bytes():
    byte = getBytes()
    wif_compress = Bytes_To_Wif(byte, True)
    wif_uncompress = Bytes_To_Wif(byte, False)
    Public_compress = Bytes_To_PublicKey(byte, compress=True)
    Public_uncompress = Bytes_To_PublicKey(byte, compress=False)
    xprv = Bytes_To_XPRV(byte)
    xpub = Bytes_To_XPUB(byte)
    mne = Bytes_To_Mnemonic(byte)
    privatekey = Bytes_To_PrivateKey(byte)
    address_compress = Bytes_To_Address(byte, compress=True)
    address_uncompress = Bytes_To_Address(byte, compress=False)
    print(f"{cyan}Bytes                   {reset}: {byte}"
          f"\n{cyan}WIF Compress          {reset}: {wif_compress}"
          f"\n{cyan}WIF Uncompress        {reset}: {wif_uncompress}"
          f"\n{cyan}Public Key Compress   {reset}: {Public_compress}"
          f"\n{cyan}Public Key Uncompress {reset}: {Public_uncompress}"
          f"\n{cyan}XPUB                  {reset}: {xpub}"
          f"\n{cyan}XPRV                  {reset}: {xprv}"
          f"\n{cyan}Mnemonic              {reset}: {mne}"
          f"\n{cyan}Private Key           {reset}: {privatekey}"
          f"\n{cyan}Address Compress      {reset}: {address_compress}"
          f"\n{cyan}Address Uncompress    {reset}: {address_uncompress}")


def example_binary():
    binary_str = getBinary()
    wif_compress = Binary_To_Wif(binary_str, True)
    wif_uncompress = Binary_To_Wif(binary_str, False)
    PublicKey_compress = Binary_To_PublicKey(binary_str, compress=True)
    PublicKey_uncompress = Binary_To_PublicKey(binary_str, compress=False)
    xprv = Binary_To_XPRV(binary_str)
    xpub = Binary_To_XPUB(binary_str)
    dec = Binary_To_Decimal(binary_str)
    address_compress = Binary_To_Address(binary_str, compress=True)
    address_uncompress = Binary_To_Address(binary_str, compress=False)
    print(f"{cyan}Binary                  {reset}: {binary_str}"
          f"\n{cyan}WIF Compress          {reset}: {wif_compress}"
          f"\n{cyan}WIF Uncompress        {reset}: {wif_uncompress}"
          f"\n{cyan}Public Key Compress   {reset}: {PublicKey_compress}"
          f"\n{cyan}Public Key Uncompress {reset}: {PublicKey_uncompress}"
          f"\n{cyan}XPUB                  {reset}: {xpub}"
          f"\n{cyan}XPRV                  {reset}: {xprv}"
          f"\n{cyan}Decimal               {reset}: {dec}"
          f"\n{cyan}Address Compress      {reset}: {address_compress}"
          f"\n{cyan}Address Uncompress    {reset}: {address_uncompress}")


def example_xprv():
    xprv = getRootKey()
    wif_compress = XPRV_To_Wif(xprv, True)
    wif_uncompress = XPRV_To_Wif(xprv, False)
    Public_compress = XPRV_To_PublicKey(xprv, compress=True)
    Public_uncompress = XPRV_To_PublicKey(xprv, compress=False)
    xpub = XPRV_To_XPUB(xprv)
    Mne = XPRV_To_Mnemonic(xprv)
    privatekey = XPRV_To_PrivateKey(xprv)
    dec = XPRV_To_Decimal(xprv)
    address_compress = XPRV_To_Address(xprv, compress=True)
    address_uncompress = XPRV_To_Address(xprv, compress=False)
    print(f"{cyan}XPRV                    {reset}: {xprv}"
          f"\n{cyan}WIF Compress          {reset}: {wif_compress}"
          f"\n{cyan}WIF Uncompress        {reset}: {wif_uncompress}"
          f"\n{cyan}Public Key Compress   {reset}: {Public_compress}"
          f"\n{cyan}Public Key Uncompress {reset}: {Public_uncompress}"
          f"\n{cyan}XPUB                  {reset}: {xpub}"
          f"\n{cyan}Mnemonic              {reset}: {Mne}"
          f"\n{cyan}Private Key           {reset}: {privatekey}"
          f"\n{cyan}Decimal               {reset}: {dec}"
          f"\n{cyan}Address Compress      {reset}: {address_compress}"
          f"\n{cyan}Address Uncompress    {reset}: {address_uncompress}")


def example_dec():
    dec = getDecimal()
    privatekey = Decimal_To_PrivateKey(dec)
    wif_compress = Decimal_To_Wif(dec, True)
    wif_uncompress = Decimal_To_Wif(dec, False)
    xprv = Decimal_To_XPRV(dec)
    xpub = Decimal_To_XPUB(dec)
    mne = Decimal_To_Mnemonic(dec)
    public_compress = Decimal_To_PublicKey(dec, compress=True)
    public_uncompress = Decimal_To_PublicKey(dec, compress=False)
    address_compress = Decimal_To_Address(dec, compress=True)
    address_uncompress = Decimal_To_Address(dec, compress=False)
    print(f"{cyan}Decimal                 {reset}: {dec}"
          f"\n{cyan}Private Key           {reset}: {privatekey}"
          f"\n{cyan}WIF Compress          {reset}: {wif_compress}"
          f"\n{cyan}WIF Uncompress        {reset}: {wif_uncompress}"
          f"\n{cyan}XPUB                  {reset}: {xpub}"
          f"\n{cyan}XPRV                  {reset}: {xprv}"
          f"\n{cyan}Mnemonic              {reset}: {mne}"
          f"\n{cyan}Public Key Compress   {reset}: {public_compress}"
          f"\n{cyan}Public Key Uncompress {reset}: {public_uncompress}"
          f"\n{cyan}Address Compress      {reset}: {address_compress}"
          f"\n{cyan}Address Uncompress    {reset}: {address_uncompress}"
          f"\n[*] Converted All Data From Decimal.")


def example_wif():
    seed = getBytes()
    wif_compress = Bytes_To_Wif(seed, True)
    wif_uncompress = Bytes_To_Wif(seed, False)
    PublicKey_compress = Wif_To_PublicKey(wif_compress, compress=True)
    PublicKey_uncompress = Wif_To_PublicKey(wif_uncompress, compress=False)
    xprv = Wif_To_XPRV(wif_uncompress)
    xpub = Wif_To_XPUB(wif_uncompress)
    dec = Wif_To_Decimal(wif_uncompress)
    address_compress = Wif_To_Addr(wif_compress, compress=True)
    address_uncompress = Wif_To_Addr(wif_uncompress, compress=False)
    print(f"{cyan}WIF Compress          {reset}: {wif_compress}"
          f"\n{cyan}WIF Uncompress        {reset}: {wif_uncompress}"
          f"\n{cyan}Public Key Compress   {reset}: {PublicKey_compress}"
          f"\n{cyan}Public Key Uncompress {reset}: {PublicKey_uncompress}"
          f"\n{cyan}XPUB                  {reset}: {xpub}"
          f"\n{cyan}XPRV                  {reset}: {xprv}"
          f"\n{cyan}Decimal               {reset}: {dec}"
          f"\n{cyan}Address Compress      {reset}: {address_compress}"
          f"\n{cyan}Address Uncompress    {reset}: {address_uncompress}"
          f"\n[*] Converted All Data From WIF.")


# -------------------------------------------------

def example_pvk_to_btc():
    pvk = getPrivateKey()
    p2pkh = PrivateKey_To_Bitcoin_Addr(pvk, 'p2pkh')
    p2sh = PrivateKey_To_Bitcoin_Addr(pvk, 'p2sh')
    p2wpkh = PrivateKey_To_Bitcoin_Addr(pvk, 'p2wpkh')
    p2wsh = PrivateKey_To_Bitcoin_Addr(pvk, 'p2wsh')
    p2wpkh_p2sh = PrivateKey_To_Bitcoin_Addr(pvk, 'p2wpkh_p2sh')
    p2wsh_p2sh = PrivateKey_To_Bitcoin_Addr(pvk, 'p2wsh_p2sh')
    print(f"{cyan}Private Key           {reset}: {pvk}")
    print(f"{cyan}P2PKH                 {reset}: {p2pkh}")
    print(f"{cyan}P2SH                  {reset}: {p2sh}")
    print(f"{cyan}P2WPKH                {reset}: {p2wpkh}")
    print(f"{cyan}P2WSH                 {reset}: {p2wsh}")
    print(f"{cyan}P2WPKH in P2SH           {reset}: {p2wpkh_p2sh}")
    print(f"{cyan}P2WSH in P2SH            {reset}: {p2wsh_p2sh}")


def example_pvk_to_eth():
    pvk = getPrivateKey()
    eth_Addr = PrivateKey_To_Ethereum_Addr(pvk)
    print(f"{cyan}Private Key           {reset}: {pvk}"
          f"\n{cyan}Address Compress      {reset}: {eth_Addr}")


def example_pvk_to_dash():
    pvk = getPrivateKey()
    dash_Addr = PrivateKey_To_Dash_Addr(pvk)
    print(f"{cyan}Private Key           {reset}: {pvk}"
          f"\n{cyan}Address Compress      {reset}: {dash_Addr}")


def example_pvk_to_ltc():
    pvk = getPrivateKey()
    p2pkh = PrivateKey_To_Litecoin_Addr(pvk, 'p2pkh')
    p2sh = PrivateKey_To_Litecoin_Addr(pvk, 'p2sh')
    p2wpkh = PrivateKey_To_Litecoin_Addr(pvk, 'p2wpkh')
    p2wsh = PrivateKey_To_Litecoin_Addr(pvk, 'p2wsh')
    print(f"{cyan}Private Key           {reset}: {pvk}")
    print(f"{cyan}P2PKH                 {reset}: {p2pkh}")
    print(f"{cyan}P2SH                  {reset}: {p2sh}")
    print(f"{cyan}P2WPKH                {reset}: {p2wpkh}")
    print(f"{cyan}P2WSH                 {reset}: {p2wsh}")
    


def example_pvk_to_digibyte():
    pvk = getPrivateKey()
    digibyte_Addr = PrivateKey_To_DigiByte_Addr(pvk)
    print(f"{cyan}Private Key           {reset}: {pvk}"
          f"\n{cyan}Address Compress      {reset}: {digibyte_Addr}")


def example_pvk_to_dogecoin():
    pvk = getPrivateKey()
    dogecoin_Addr = PrivateKey_To_Dogecoin_Addr(pvk)
    print(f"{cyan}Private Key           {reset}: {pvk}"
          f"\n{cyan}Address Compress      {reset}: {dogecoin_Addr}")


def example_pvk_to_bitcoingold():
    pvk = getPrivateKey()
    bitcoingold_Addr = PrivateKey_To_BitcoinGold_Addr(pvk)
    print(f"{cyan}Private Key           {reset}: {pvk}"
          f"\n{cyan}Address Compress      {reset}: {bitcoingold_Addr}")


def example_pvk_to_qtum():
    pvk = getPrivateKey()
    qtum_Addr = PrivateKey_To_Qtum_Addr(pvk)
    print(f"{cyan}Private Key           {reset}: {pvk}"
          f"\n{cyan}Address Compress      {reset}: {qtum_Addr}")
    

def example_pvk_to_zcash():
    pvk = getPrivateKey()
    zcash_Addr = PrivateKey_To_Zcash_Addr(pvk)
    print(f"{cyan}Private Key           {reset}: {pvk}"
          f"\n{cyan}Address Compress      {reset}: {zcash_Addr}")


def example_pvk_to_rvn():
    pvk = getPrivateKey()
    ravencoin_Addr = PrivateKey_To_Ravencoin_Addr(pvk)
    print(f"{cyan}Private Key           {reset}: {pvk}"
          f"\n{cyan}Address Compress      {reset}: {ravencoin_Addr}")
    

if __name__ == '__main__':
    commands = sys.argv
    if len(commands) > 1:
        methodCommand = sys.argv[1]
        if methodCommand == 'privatekey':
            example_privatekey()
        elif methodCommand == 'mnemonic':
            example_mnemonic()
        elif methodCommand == 'binary':
            example_binary()
        elif methodCommand == 'xprv':
            example_xprv()
        elif methodCommand == 'wif':
            example_wif()
        elif methodCommand == 'decimal':
            example_dec()
        elif methodCommand == 'bytes':
            example_bytes()
        elif methodCommand == 'ethereum':
            example_pvk_to_eth()
        elif methodCommand == 'bitcoin':
            example_pvk_to_btc()
        elif methodCommand == 'dash':
            example_pvk_to_dash()
        elif methodCommand == 'dogecoin':
            example_pvk_to_dogecoin()
        elif methodCommand == 'digibyte':
            example_pvk_to_digibyte()
        elif methodCommand == 'bitcoingold':
            example_pvk_to_bitcoingold()
        elif methodCommand == 'qtum':
            example_pvk_to_qtum()
        elif methodCommand == 'zcash':
            example_pvk_to_zcash()
        elif methodCommand == 'rvn':
            example_pvk_to_rvn()
        else:
            print(f"{red}\n\nInvalid Command!{reset}")