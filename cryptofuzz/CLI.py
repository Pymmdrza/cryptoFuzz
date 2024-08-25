import sys
import argparse
import time
from difflib import get_close_matches
from .Wallet import *

# Define colors for terminal output
red = "\033[91m"
green = "\033[92m"
yellow = "\033[93m"
magenta = "\033[95m"
cyan = "\033[96m"
white = "\033[97m"
grey = "\033[90m"
reset = "\033[0m"
# ------------------------

message_usage = f"""\n
Generate a private key, mnemonic phrase, byte sequence, binary string With Cryptofuzz:\n

    {green}cryptofuzz{reset} <operation> [options]\n

    Operations:\n
        {green}-p,   {reset} {cyan}--privatekey  {reset}  {white} Generate a private key\n{reset}
        {green}-m,   {reset} {cyan}--mnemonic    {reset}  {white} Generate a mnemonic phrase\n{reset}
        {green}-b,   {reset} {cyan}--byte        {reset}  {white} Generate a byte sequence\n{reset}
        {green}-bin, {reset} {cyan}--binary      {reset}  {white} Generate a binary string\n{reset}
        {green}-x,   {reset} {cyan}--xprv        {reset}  {white} Generate a root key (XPRV)\n{reset}
        {green}-d,   {reset} {cyan}--decimal     {reset}  {white} Generate a decimal number\n{reset}
        {green}-w,   {reset} {cyan}--wif         {reset}  {white} Generate a WIF\n{reset}
        {green}-eth, {reset} {cyan}--ethereum    {reset}  {white} Generate an Ethereum address\n{reset}
        {green}-ltc, {reset} {cyan}--litecoin    {reset}  {white} Generate a Litecoin address\n{reset}
        {green}-digi, {reset} {cyan}--digibyte   {reset}  {white} Generate a DigiByte address\n{reset}
        {green}-doge, {reset} {cyan}--dogecoin   {reset}  {white} Generate a Dogecoin address\n{reset}
        {green}-btg, {reset} {cyan}--bitcoingold {reset}  {white} Generate a Bitcoin Gold address\n{reset}
        {green}-qtum,{reset} {cyan}--qtum        {reset}  {white} Generate a Qtum address\n{reset}
        {green}-zec, {reset} {cyan}--zcash       {reset}  {white} Generate a Zcash address\n{reset}
        {green}-rvn, {reset} {cyan}--ravencoin   {reset}  {white} Generate a Ravencoin address\n{reset}
        {green}-ex,  {reset} {cyan}--example     {reset}  {white} Display example usages of different commands\n {reset}
        {green}-gen, {reset} {cyan}--generate    {reset}  {white} Generate example usages of different commands\n{reset}

    """


# ------------------------

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
          f"")


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
          f"")


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
    print(f"{cyan}P2WPKH in P2SH        {reset}: {p2wpkh_p2sh}")
    print(f"{cyan}P2WSH in P2SH         {reset}: {p2wsh_p2sh}")


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


def parse_arguments():
    """Parse command line arguments"""

    parser = argparse.ArgumentParser(
        description="Example Cryptofuzz Operations",
        usage="%(prog)s [options]",
        epilog=message_usage
    )

    parser.add_argument(
        "-p", "--privatekey", action="store_true",
        help="Run example using a generated private key."
    )
    parser.add_argument(
        "-m", "--mnemonic", action="store_true",
        help="Run example using a generated mnemonic phrase."
    )
    parser.add_argument(
        "-b", "--byte", action="store_true",
        help="Run example using a generated byte sequence."
    )
    parser.add_argument(
        "-bin", "--binary", action="store_true",
        help="Run example using a generated binary string."
    )
    parser.add_argument(
        "-x", "--xprv", action="store_true",
        help="Run example using a generated root key (XPRV)."
    )
    parser.add_argument(
        "-d", "--decimal", action="store_true",
        help="Run example using a generated decimal number."
    )
    parser.add_argument(
        "-w", "--wif", action="store_true",
        help="Run example using a generated WIF (Wallet Import Format) key."
    )
    parser.add_argument(
        "-btc", "--bitcoin", action="store_true",
        help="Run example to convert a private key to Bitcoin addresses."
    )
    parser.add_argument(
        "-eth", "--ethereum", action="store_true",
        help="Run example to convert a private key to Ethereum address."
    )
    parser.add_argument(
        "-dash", "--dash", action="store_true",
        help="Run example to convert a private key to Dash address."
    )
    parser.add_argument(
        "-digi", "--digibyte", action="store_true",
        help="Run example to convert a private key to DigiByte address."
    )

    parser.add_argument(
        "-ltc", "--litecoin", action="store_true",
        help="Run example to convert a private key to Litecoin addresses."
    )
    parser.add_argument(
        "-doge", "--dogecoin", action="store_true",
        help="Run example to convert a private key to Dogecoin address."
    )
    parser.add_argument(
        "-btg", "--bitcoingold", action="store_true",
        help="Run example to convert a private key to Bitcoin Gold address."
    )
    parser.add_argument(
        "-qtum", "--qtum", action="store_true",
        help="Run example to convert a private key to Qtum address."
    )
    parser.add_argument(
        "-zcash", "--zcash", action="store_true",
        help="Run example to convert a private key to Zcash address."
    )
    parser.add_argument(
        "-rvn", "--ravencoin", action="store_true",
        help="Run example to convert a private key to Ravencoin address."
    )
    parser.add_argument(
        "-ex", "--example", action="store_true",
        help="Show examples of how to use the program."
    )

    parser.add_argument(
        "-g", "--generate", type=int, default=3,
        help="Generate a Total of N (Private Keys| Mnemonics | Bytes | Binary | Decimal | WIF)."
    )

    args = parser.parse_args()

    return args


# Function to show examples of usage
def show_examples():
    examples = """
Usage Examples:

  Run with private key:
    cryptofuzz --privatekey

  Run with mnemonic:
    cryptofuzz --mnemonic

  Run with byte sequence:
    cryptofuzz --bytes

  Show help:
    cryptofuzz --help
"""
    print(examples)


# Function to handle incorrect commands
def handle_incorrect_command(command):
    possible_commands = [
        "privatekey", "mnemonic", "bytes", "binary", "xprv", "decimal",
        "wif", "bitcoin", "ethereum", "dash", "litecoin", "dogecoin",
        "bitcoingold", "qtum", "zcash", "ravencoin", "example"
    ]

    close_match = get_close_matches(command, possible_commands, n=1, cutoff=0.6)

    if close_match:
        print(f"{yellow}Did you mean '{close_match[0]}'?{reset}")
        print(f"If you want to see the full help, type: cryptofuzz --help\n"
              f"{message_usage}")
    else:
        print(f"{red}Unknown command '{command}'.{reset}")
        print(f"{message_usage}")


def example_generate(genSize, args):
    generated = False
    if args.privatekey:
        for i in range(genSize):
            print(f"Generating Private Key {i + 1}/{genSize}...")
            example_privatekey()
            time.sleep(0.1)
        generated = True
    if args.mnemonic:
        for i in range(genSize):
            print(f"Generating Mnemonic {i + 1}/{genSize}...")
            example_mnemonic()
            time.sleep(0.1)
        generated = True
    if args.byte:
        for i in range(genSize):
            print(f"Generating Byte Sequence {i + 1}/{genSize}...")
            example_bytes()
            time.sleep(0.1)
        generated = True
    if args.binary:
        for i in range(genSize):
            print(f"Generating Binary String {i + 1}/{genSize}...")
            example_binary()
            time.sleep(0.1)
        generated = True
    if args.xprv:
        for i in range(genSize):
            print(f"Generating XPRV {i + 1}/{genSize}...")
            example_xprv()
            time.sleep(0.1)
        generated = True
    if args.decimal:
        for i in range(genSize):
            print(f"Generating Decimal {i + 1}/{genSize}...")
            example_dec()
            time.sleep(0.1)
        generated = True
    if args.wif:
        for i in range(genSize):
            print(f"Generating WIF {i + 1}/{genSize}...")
            example_wif()
            time.sleep(0.1)
        generated = True

    if not generated:
        print(f"{red}No valid arguments provided for generation.{reset}\n"
              f"Batch Generate Example:\n"
              f"{red}{'-' * 43}{reset}\n"
              f"Private Key (Generate {grey}100{reset}) : {green}cryptofuzz --privatekey --generate 100{reset}\n"
              f"Mnemonic (Generate {grey}100{reset}) : {green}cryptofuzz --mnemonic --generate 100{reset}\n"
              f"Bytes (Generate {grey}100{reset}) : {green}cryptofuzz --bytes --generate 100{reset}\n"
              f"Binary (Generate {grey}100{reset}) : {green}cryptofuzz --binary --generate 100{reset}\n"
              f"WIF (Generate {grey}100{reset}) : {green}cryptofuzz --wif --generate 100{reset}\n"
              f"Decimal (Generate {grey}100{reset}) : {green}cryptofuzz --decimal --generate 100{reset}\n"
              f"{red}{'-' * 43}{reset}\n")


# Main function (entry point)
def mainWork():
    if len(sys.argv) > 1:
        args = parse_arguments()

        # Define a dictionary mapping arguments to functions
        command_map = {
            'privatekey': example_privatekey,
            'mnemonic': example_mnemonic,
            'byte': example_bytes,
            'binary': example_binary,
            'xprv': example_xprv,
            'decimal': example_dec,
            'wif': example_wif,
            # -------------------------------
            'bitcoin': example_pvk_to_btc,
            'ethereum': example_pvk_to_eth,
            'dash': example_pvk_to_dash,
            'litecoin': example_pvk_to_ltc,
            'dogecoin': example_pvk_to_dogecoin,
            'digibyte': example_pvk_to_digibyte,
            'bitcoingold': example_pvk_to_bitcoingold,
            'qtum': example_pvk_to_qtum,
            'zcash': example_pvk_to_zcash,
            'ravencoin': example_pvk_to_rvn,
            # -------------------------------
            'generate': None,
            'example': show_examples
        }


        if args.generate > 1:
            example_generate(args.generate, args)
        else:
            for command, func in command_map.items():
                if getattr(args, command):
                    func()
                    break
            else:
                handle_incorrect_command(sys.argv[1])
    else:
        print(f"\n\t{red}No command provided. Use --help to see available options.{reset}\n")
        print(message_usage)


if __name__ == "__main__":
    mainWork()
