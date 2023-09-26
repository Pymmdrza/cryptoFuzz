import os
import sys
import subprocess
import platform

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

def main():
    install_deps()
    print(f"{red}CryptoFuzz{reset} {green}With dependencies have been installed!{reset}")


if __name__ == "__main__":
    main()
