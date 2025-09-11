#!/usr/bin/env python3
"""
SCS
Setup script for installation
"""

from setuptools import setup, find_packages
import pathlib

# Read the README file
HERE = pathlib.Path(__file__).parent
README = (HERE / "README.md").read_text()

setup(
    name="scs-scanner",
    version="1.0.0",
    description="SCS: A fast and versatile network scanner",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/YourUsername/SCS",
    author="SuvScd",
    author_email="suvs@example.com",
    license="MIT",
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "click>=8.0.0",
        "scapy>=2.5.0", 
        "rich>=13.0.0"
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "black>=23.0.0",
            "mypy>=1.0.0",
            "flake8>=6.0.0",
        ]
    },
    entry_points={
        'console_scripts': [
            'scs=discn.cli:cli',
        ],
    },
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: System :: Networking",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
    ],
    keywords="security networking scanner cybersecurity pentest",
)
