# Description
"""
setup.py: Python Hive Library setup
Author: HexWay
License: MIT
Copyright 2021, HexWay
"""

# Import
from setuptools import setup, find_packages

# Authorship information
__author__ = "HexWay"
__copyright__ = "Copyright 2021, HexWay"
__credits__ = [""]
__license__ = "MIT"
__version__ = "0.0.1b1"
__maintainer__ = "HexWay"
__email__ = "contact@hexway.io"
__status__ = "Development"

# Setup
with open("README.md", "r") as readme:
    long_description = readme.read()

setup(
    name="hive_library",
    version=__version__,
    author=__author__,
    author_email=__email__,
    description="Python Hive Library",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://hexway.io/",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Education",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Operating System :: MacOS",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Topic :: Education",
        "Topic :: Security",
    ],
    install_requires=[
        "requests",
        "urllib3",
        "dataclasses",
        "marshmallow",
        "PyYAML",
        "prettytable",
    ],
    entry_points={
        "console_scripts": ["hive-cli=hive_library.cli:main"],
    },
    python_requires=">=3.6",
    include_package_data=True,
)
