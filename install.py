import os
import sys
import subprocess
import platform
from colorthon import Colors

red = Colors.RED
green = Colors.GREEN
yellow = Colors.YELLOW
reset = Colors.RESET


def subInstall(package_name: str):
    if "win" in platform.platform().lower():
        subprocess.check_call([sys.executable, "-m", "pip", "install", package_name])
    elif "linux" in platform.platform().lower():
        subprocess.check_call([sys.executable, "-m", "pip3", "install", package_name])
    elif "mac" in platform.platform().lower():
        subprocess.check_call([sys.executable, "-m", "pip3", "install", package_name])
    else:
        raise ValueError("Unsupported OS")


def install_deps():
    deps = ["ecdsa", "setuptools", "wheel", "hdwallet"]
    for dep in deps:
        print(f" {green}Installing{reset}:{yellow} {dep}{reset}")
        subInstall(dep)

def colorthon():
    if "win" in platform.platform().lower():
        print(f"{red}Installing{reset}:{yellow} Colorthon{reset}")
        subprocess.run(['pip', 'install', 'colorthon'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"{green}Successfully installed{reset}: Colorthon")

    elif "linux" in platform.platform().lower():
        print(f"{red}Installing{reset}:{yellow} Colorthon{reset}")
        subprocess.run(['pip3', 'install', 'colorthon'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"{green}Successfully installed{reset}: Colorthon")

    elif "mac" in platform.platform().lower():
        print(f"{red}Installing{reset}:{yellow} Colorthon{reset}")
        subprocess.run(['pip3', 'install', 'colorthon'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"{green}Successfully installed{reset}: Colorthon")



def main():
    colorthon()
    install_deps()
    print(f"{red}CryptoFuzz{reset} {green}With dependencies have been installed!{reset}")


if __name__ == "__main__":
    main()
