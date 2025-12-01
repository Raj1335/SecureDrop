"""
SecureDrop - Secure P2P File Transfer
Setup configuration for PyPI package
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
readme = Path(__file__).parent / "Readme.md"
long_description = readme.read_text(encoding="utf-8") if readme.exists() else ""

setup(
    name="securedrop-transfer",
    version="1.0.0",
    author="Your Name",
    author_email="your.email@example.com",
    description="Enterprise-grade cryptographic protocol for secure P2P file transfer",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/securedrop",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: End Users/Desktop",
        "Topic :: Security :: Cryptography",
        "Topic :: Communications :: File Sharing",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=[
        "cryptography>=41.0.0",
        "spake2>=0.8",
        "click>=8.1.0",
        "rich>=13.0.0",
        "prompt-toolkit>=3.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "securedrop=securedrop.cli:main",
        ],
    },
    include_package_data=True,
    keywords="security cryptography file-transfer p2p encryption spake2 x25519",
    project_urls={
        "Bug Reports": "https://github.com/yourusername/securedrop/issues",
        "Source": "https://github.com/yourusername/securedrop",
        "Documentation": "https://github.com/yourusername/securedrop#readme",
    },
)