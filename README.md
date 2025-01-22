# 🔐 KAPS - File Vault CLI

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Security](https://img.shields.io/badge/security-AES--256--CBC-green.svg)

## 🚀 Features
- Military-grade encryption (AES-256-CBC)

- Secure key derivation (PBKDF2-HMAC-SHA256)

- Cross-platform support (Windows/Linux/macOS)

- Directory structure preservation

- Random salt & IV generation

## 📦 Installation

You can install the cli using the github repository:

```bash
cargo install --git https://github.com/stescobedo92/kaps
````

or directly from the create.io registry:

```bash
cargo install kaps
````

## 🛠 Usage

```bash
# 🔒 Encrypt directory
kaps encrypt --input <folder_to_encrypt> --output <folder_encrypted> --password "Str0ngP@ss!"
```
```bash
# 🔓 Decrypt directory
kaps decrypt --input <folder_encrypted> --output <folder_to_decrypt> --password "Str0ngP@ss!"
```