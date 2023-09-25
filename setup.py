"""Setup file for CryptoFuzz. Programmer and Owner: Mmdrza.Com / Email: PyMmdrza@gmail.com"""
import os
import infoLib
from setuptools import setup, find_packages


setup(
    name=infoLib.PACK_NAME,
    description=infoLib.PACK_DESCRIPTION,
    long_description=infoLib.PACK_README,
    long_description_content_type=infoLib.PACK_TYPE_README,
    url=infoLib.PACK_URL,
    packages=find_packages(),
    project_urls=infoLib.PACK_PROJECT_URLS,
    classifiers=infoLib.PACK_CLASSIFIERS,
    python_requires='>=3.6',
    install_requires=infoLib.PACK_REQUIREMENTS,
    entry_points=infoLib.PACK_SCRIPTS_CONSOLE,
    version=infoLib.PACK_VERSION,
    author=infoLib.PACK_AUTHOR,
    author_email=infoLib.PACK_EMAIL,
    license=infoLib.PACK_LICENSE,
    keywords=infoLib.PACK_KEYWORD,
    include_package_data=True,
    zip_safe=True
)

