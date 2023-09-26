import argparse, os, json
from .Wallet import *


red = "\033[91m"
green = "\033[92m"
yellow = "\033[93m"
magenta = "\033[95m"
cyan = "\033[96m"
white = "\033[97m"
reset = "\033[0m"

parser = argparse.ArgumentParser(description="CryptoFuzz CLI")
parser.add_argument("-g", "--generate", action="store_true", help="Generate a new wallet")
parser.add_argument('-t', '--total', type=int, help="Number of wallets to generate")
parser.add_argument('-s', '--save', action="store_true", help="Save All Details OutputFile.txt")

args = parser.parse_args()

FileName_Output = "OutputFile.json"
current_directory = os.getcwd()
filePath = os.path.join(current_directory, FileName_Output)
jsonFile = open(filePath, 'a')
jsonFile.write("[\n")
count = 0
if args.generate:
    if args.total:
        for i in range(args.total):
            pvk = getPrivateKey()
            wif_compress = PrivateKey_To_Wif(pvk, True)
            wif_uncompress = PrivateKey_To_Wif(pvk, False)
            mnemonic_str = PrivateKey_To_Mnemonic(pvk)
            xprv = PrivateKey_To_XPRV(pvk)
            xpub = PrivateKey_To_XPUB(pvk)
            dec = PrivateKey_To_Decimal(pvk)
            bin_ = PrivateKey_To_Binary(pvk)
            caddr = PrivateKey_To_CompressAddr(pvk)
            uaddr = PrivateKey_To_UncompressAddr(pvk)
            bin1 = str(bin_[0:16])
            bin2 = str(bin_[-16:])
            mnStr = mnemonic_str[0:64]
            data_Content = {
                f"Private Key       ": f"{pvk}",
                f"WIF Compress      ": f"{wif_compress}",
                f"WIF UnCompress    ": f"{wif_uncompress}",
                f"Mnemonic          ": f"{mnStr}...",
                f"XPRV              ": f"{xprv}",
                f"XPUB              ": f"{xpub}",
                f"Decimal           ": f"{dec}",
                f"Binary            ": f"{bin1}...{bin2}",
                f"Address Compress  ": f"{caddr}",
                f"Address UnCompress": f"{uaddr}"
            }
            dataContent = {
                "Private Key": pvk,
                "WIF Compress": wif_compress,
                "WIF UnCompress": wif_uncompress,
                "Mnemonic": mnemonic_str,
                "XPRV": xprv,
                "XPUB": xpub,
                "Decimal": dec,
                "Binary": bin_,
                "Address Compress": caddr,
                "Address UnCompress": uaddr
            }
            
            outputstr = json.dumps(data_Content, indent=4)
            print(outputstr)
            if args.save:
                count += 1
                json.dump(dataContent, jsonFile, indent=4)
                if count % args.total == 0:
                    jsonFile.write("\n")
                else:
                    jsonFile.write(",\n")
        jsonFile.write(']\n')
    else:
        print("Number of wallets must be greater than 0")
