import os
import sys
import platform


def subInstall(package_name: str):
    if "win" in platform.platform().lower():
        os.system(f'python -m pip install {package_name}')
    #   subprocess.check_call([sys.executable, "-m", "pip", "install", package_name])
    elif "linux" in platform.platform().lower():
        os.system(f'python3 -m pip install {package_name}')
    
    # subprocess.check_call([sys.executable, "-m", "pip3", "install", package_name])
    elif "mac" in platform.platform().lower():
        os.system(f'python3 -m pip install {package_name}')
    
    # subprocess.check_call([sys.executable, "-m", "pip3", "install", package_name])
    else:
        raise ValueError("Unsupported OS")


def install_deps():
    deps = ["ecdsa", "setuptools", "wheel", "hdwallet"]
    for dep in deps:
        print(f" Installing: {dep} ----------------------------------")
        subInstall(dep)


def main():
    install_deps()
    print("cryptofuzz and its dependencies have been installed!")


if __name__ == "__main__":
    main()
