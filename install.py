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
        print(f" Installing: {dep} ----------------------------------")
        subInstall(dep)

def install_cryptofuzz():
    url = "git+https://github.com/your_username/cryptofuzz.git"
    subprocess.check_call([sys.executable, "-m", "pip", "install", url])


def main():
    install_deps()
    install_cryptofuzz()
    print("cryptofuzz and its dependencies have been installed!")


if __name__ == "__main__":
    main()
