import sys

from hdwallet import HDWallet
from hdwallet.symbols import BTC, ETH, LTC, TRX, DASH, DGB, BTG, DOGE, RVN, QTUM


def hex2eth(pvk: str) -> str:
    hd: HDWallet = HDWallet(symbol=ETH)
    hd.from_private_key(private_key=pvk)
    return hd.p2pkh_address()


def hex2trx(pvk: str) -> str:
    hd: HDWallet = HDWallet(symbol=TRX)
    hd.from_private_key(private_key=pvk)
    return hd.p2pkh_address()


def hex2ltc(pvk: str) -> str:
    hd: HDWallet = HDWallet(symbol=LTC)
    hd.from_private_key(private_key=pvk)
    return hd.p2pkh_address()


def hex2dash(pvk: str) -> str:
    hd: HDWallet = HDWallet(symbol=DASH)
    hd.from_private_key(private_key=pvk)
    return hd.p2pkh_address()


def hex2btg(pvk: str) -> str:
    hd: HDWallet = HDWallet(symbol=BTG)
    hd.from_private_key(private_key=pvk)
    return hd.p2pkh_address()


def hex2dgb(pvk: str) -> str:
    hd: HDWallet = HDWallet(symbol=DGB)
    hd.from_private_key(private_key=pvk)
    return hd.p2pkh_address()


def hex2doge(pvk: str) -> str:
    hd: HDWallet = HDWallet(symbol=DOGE)
    hd.from_private_key(private_key=pvk)
    return hd.p2pkh_address()


def hex2rvn(pvk: str) -> str:
    hd: HDWallet = HDWallet(symbol=RVN)
    hd.from_private_key(private_key=pvk)
    return hd.p2pkh_address()


def hex2qtum(pvk: str) -> str:
    hd: HDWallet = HDWallet(symbol=QTUM)
    hd.from_private_key(private_key=pvk)
    return hd.p2pkh_address()


def hex2btc(pvk: str, type: str) -> str:
    """
    Convert a given hexadecimal private key to a Bitcoin address of the specified type.

    Args:
        pvk (str): The hexadecimal private key.
        type (str): The type of Bitcoin address to generate.
            Possible values are "p2pkh", "p2sh", "p2wpkh", "p2wsh", "p2wpkh-p2sh", "p2wsh-p2sh".

    Returns:
        str: The Bitcoin address corresponding to the private key and address type.

    Raises:
        None

    Example:
        >>> hex2btc("0123456789abcdef", "p2pkh")
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"

        >>> hex2btc("0123456789abcdef", "p2sh")
        "3FZbgi29cpjq2GjdwV8eyHuJJnkLtktZc5"

    Note:
        Make sure that the private key is a valid hexadecimal string.
    """
    hd: HDWallet = HDWallet(symbol=BTC)
    hd.from_private_key(private_key=pvk)
    if type == "p2pkh":
        return hd.p2pkh_address()
    elif type == "p2sh":
        return hd.p2sh_address()
    elif type == "p2wpkh":
        return hd.p2wpkh_address()
    elif type == "p2wsh":
        return hd.p2wsh_address()
    elif type == "p2wpkh-p2sh":
        return hd.p2wpkh_in_p2sh_address()
    elif type == "p2wsh-p2sh":
        return hd.p2wsh_in_p2sh_address()
    else:
        err = f"Invalid address type: {type} not supported. Supported types are: p2pkh | p2sh | p2wpkh | p2wsh | p2wpkh-p2sh | p2wsh-p2sh"
        sys.stdout.write(err)

