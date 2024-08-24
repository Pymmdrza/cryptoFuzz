"""Setup file for CryptoFuzz. Programmer and Owner: Mmdrza.Com / Email: PyMmdrza@gmail.com"""
import re

from setuptools import setup, find_packages
import os

PACK_NAME = "CryptoFuzz"
PACK_DESCRIPTION = "Generated and Converted Keys with any Type Foundation from Private Key [WIF Hexed Mnemonic and Binary Bytes seed] in Python"
PACK_VERSION = "4.0.3"
PACK_LICENSE = "MIT"
PACK_AUTHOR = "Mohammadreza (Mmdrza.Com)"
PACK_EMAIL = "Pymmdrza@gmail.com"
PACK_URL = "https://github.com/Pymmdrza/cryptoFuzz"
PACK_ISSUES = 'https://github.com/Pymmdrza/cryptoFuzz/issues'
PACK_DOCS_URL = 'https://github.com/Pymmdrza/cryptoFuzz'
PACK_TYPE_README = 'text/markdown'
PACK_REQUIRES_INSTALL = [
    'hdwallet>=2.2.1',
    'ecdsa>=0.18.0'
]
PACK_KEYWORD = ["CryptoFuzz", "Wif", "Mnemonic", "Binary", "seed", "Foundation", "Private", "Key", "HEX", "Mnemonic",
                "Binary", "Bytes", "bitcoin", "ethereum", "tron", "dogecoin", "zcash", "digibyte", "bitcoin gold",
                "wallet", "bip32", "bip39", "litecoin", "qtum", "ravencoin", "BTC", "ETH", "TRX", "DOGE", "BTG",
                "LTC", "ZEC", "AXE", "DASH"]
PACK_CLASSIFIERS = ["Development Status :: 5 - Production/Stable",
                    "Intended Audience :: Developers",
                    "Intended Audience :: Information Technology",
                    "Topic :: Security :: Cryptography",
                    "License :: OSI Approved :: MIT License",
                    "Programming Language :: Python :: 3",
                    "Programming Language :: Python :: 3.6",
                    "Programming Language :: Python :: 3.7",
                    "Programming Language :: Python :: 3.8",
                    "Programming Language :: Python :: 3.9",
                    "Programming Language :: Python :: 3.10",
                    "Programming Language :: Python :: 3.11",
                    "Programming Language :: Python :: Implementation :: CPython",
                    "Operating System :: OS Independent"]
PACK_COPYRIGHT = f"Copyright (C) 2024 ~ Mmdrza.Com"
PACK_CURRENT_PATH = os.path.dirname(os.path.realpath(__file__))
PACK_README = "README.md"
PACK_PROJECT_URLS = {
    "Bug Tracker": PACK_ISSUES,
    "Documentation": PACK_DOCS_URL,
    "Source Code": PACK_URL,
    "Website": "https://mmdrza.com"
}
PACK_SCRIPTS_CONSOLE = {
    'console_scripts': [
        'cryptofuzz=cryptofuzz.CLI:mainWork'
    ]
}


def get_version(package):
    """
    Return package version as listed in `__version__` in `init.py`.
    """
    with open(os.path.join(package, '__init__.py'), 'rb') as init_py:
        src = init_py.read().decode('utf-8')
        return re.search("__version__ = ['\"]([^'\"]+)['\"]", src).group(1)


version = get_version('cryptofuzz')

with open(os.path.join(os.path.dirname(__file__), 'README.md'), encoding='utf-8') as readme:
    long_description = readme.read()

setup(
    name=PACK_NAME,
    version=version,
    description=PACK_DESCRIPTION,
    long_description=long_description,
    long_description_content_type=PACK_TYPE_README,
    url=PACK_URL,
    packages=find_packages(),
    project_urls=PACK_PROJECT_URLS,
    classifiers=PACK_CLASSIFIERS,
    entry_points=PACK_SCRIPTS_CONSOLE,
    author=PACK_AUTHOR,
    author_email=PACK_EMAIL,
    license=PACK_LICENSE,
    install_requires=PACK_REQUIRES_INSTALL,
    keywords=PACK_KEYWORD,
    include_package_data=True,
    zip_safe=True
)
