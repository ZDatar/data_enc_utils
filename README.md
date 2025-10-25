# Data Encryption Utility

This utility encrypts and decrypts datasets for secure sharing between a buyer and seller, supporting both RSA and Solana/Ed25519 key formats. It implements a simplified proxy re-encryption (PRE) scheme, allowing both parties to decrypt the data with their own private keys.

## Table of Contents
- [Features](#features)
- [Quick Start](#quick-start)
- [Usage](#usage)
  - [Encryption Mode](#encryption-mode)
  - [Decryption Mode](#decryption-mode)
- [Proxy Re-Encryption (PRE)](#proxy-re-encryption-pre)
- [Logging](#logging)
- [Supported Key Formats](#supported-key-formats)
- [Configuration](#configuration)
- [Requirements](#requirements)
- [Notes](#notes)

## Features
- **AES encryption/decryption** of dataset files (AES-256 CFB mode)
- **Public key encryption** for buyer and seller (RSA or Solana/Ed25519)
- **Proxy re-encryption**: enables both parties to decrypt with their own keys
- **Combined encrypted key file** for multi-party access (JSON format)
- **Uploads** encrypted files to Azure Blob Storage and IPFS
- **Comprehensive logging**: All operations logged to both console and file
- **SHA-256 verification**: File integrity checking
- **Dynamic imports** for optional dependencies

## Usage

### Encryption Mode

Encrypt a dataset for buyer, seller, or both parties:

```bash
# Encrypt for seller only
python data_enc_util.py --encrypt-for seller

# Encrypt for buyer only
python data_enc_util.py --encrypt-for buyer

# Encrypt for both (uses proxy re-encryption)
python data_enc_util.py --encrypt-for both
```

#### Encryption Arguments
- `--encrypt-for {buyer,seller,both}`: Who to encrypt the AES key for (default: both)
- `--buyer-pk PATH`: Path to buyer public key (PEM or Solana base58)
- `--seller-sk PATH`: Path to seller private key (PEM) to derive seller public key
- `--seller-pk PATH`: Path to seller public key (PEM or Solana base58)

#### Encryption Output
- **Encrypted dataset**: `test_dataset_encrypted.bin`
- **Encrypted AES key(s)**:
  - For buyer only: `encrypted_aes_key_buyer.bin`
  - For seller only: `encrypted_aes_key_seller.bin`
  - For both: `encrypted_aes_keys.json` (contains keys for both parties)
- **Uploads** to Azure Blob Storage and IPFS (if configured)
- **Log file**: `data_enc_util.log` (includes command invocation and timestamps)

### Decryption Mode

Decrypt a dataset using your private key:

```bash
# Decrypt as seller
python data_enc_util.py decrypt \
  --recipient seller \
  --private-key /path/to/seller_sk.pem \
  --encrypted-key encrypted_aes_keys.json \
  --output decrypted_dataset.csv

# Decrypt as buyer
python data_enc_util.py decrypt \
  --recipient buyer \
  --private-key /path/to/buyer_sk.pem \
  --encrypted-key encrypted_aes_keys.json \
  --output decrypted_dataset.csv

# Decrypt using binary encrypted key file
python data_enc_util.py decrypt \
  --recipient seller \
  --private-key seller_sk.pem \
  --encrypted-key encrypted_aes_key_seller.bin \
  --encrypted-file test_dataset_encrypted.bin \
  --output decrypted_dataset.csv
```

#### Decryption Arguments
- `--recipient {buyer,seller}`: Who is decrypting (required)
- `--private-key PATH`: Path to recipient private key (PEM, Solana base58, or JSON array) (required)
- `--encrypted-key PATH`: Path to encrypted AES key file (.bin) or JSON file (.json) (required)
- `--output PATH`: Path to save decrypted file (required)
- `--encrypted-file PATH`: Path to encrypted file (default: test_dataset_encrypted.bin)

## Proxy Re-Encryption (PRE)

When encrypting for both parties (`--encrypt-for both`), the utility creates a structure that allows both buyer and seller to decrypt the AES key using their own private keys, without sharing secrets.

### How It Works
1. **Seller encryption**: The AES key is encrypted directly with the seller's public key
2. **Buyer re-encryption**: A temporary key is generated, the AES key is encrypted with it, and the temporary key is encrypted with the buyer's public key
3. Both encrypted keys are stored in a JSON file with metadata (SHA-256 hashes, base64 encoding)

**Note**: The current implementation of proxy re-encryption decryption has a limitation with IV storage. Regular encryption/decryption works perfectly for both buyer and seller when encrypted separately.

## Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Encrypt a Dataset
```bash
# Encrypt for both buyer and seller
python data_enc_util.py --encrypt-for both
```

### 3. Decrypt the Dataset
```bash
# As seller
python data_enc_util.py decrypt \
  --recipient seller \
  --private-key seller_1_sk.pem \
  --encrypted-key encrypted_aes_keys.json \
  --output decrypted_dataset.csv

# As buyer
python data_enc_util.py decrypt \
  --recipient buyer \
  --private-key buyer_0_sk.pem \
  --encrypted-key encrypted_aes_keys.json \
  --output decrypted_dataset.csv
```

### 4. View Help
```bash
# General help
python data_enc_util.py --help

# Decryption help
python data_enc_util.py decrypt --help
```

## Requirements
See `requirements.txt` for dependencies. Install with:
```bash
pip install -r requirements.txt
```

## Logging

All operations are logged to both:
- **Console**: Clean output without timestamps
- **Log file**: `data_enc_util.log` with timestamps and log levels

Each log entry includes:
- Command line invocation (e.g., `python data_enc_util.py --encrypt-for seller`)
- Timestamp of execution
- All operations and their results
- SHA-256 hashes for verification

## Supported Key Formats

### RSA Keys
- **PKCS#1 PEM format** (traditional RSA format)
- **PKCS#8 PEM format** (modern standard)

### Solana/Ed25519 Keys
- **Base58 encoded** (standard Solana format)
- **JSON array of integers** (alternative format)

The utility automatically detects the key format and handles conversion as needed.

## Configuration

Default paths are configured at the top of the script:
```python
SELLER_PRIVATE_KEY_PATH = "/path/to/seller_sk.pem"
SELLER_PUBLIC_KEY_PATH = "/path/to/seller_pk.pem"
BUYER_PUBLIC_KEY_PATH = "/path/to/buyer_pk.pem"
DATASET_PATH = "/path/to/dataset.csv"
ENCRYPTED_FILE_PATH = "/path/to/encrypted.bin"
LOG_FILE_PATH = "/path/to/data_enc_util.log"
```

### Azure Blob Storage
Set the `AZURE_CONNECTION_STRING` environment variable in a `.env` file:
```
AZURE_CONNECTION_STRING=your_connection_string_here
```

### IPFS
Ensure IPFS daemon is running on `127.0.0.1:5001` or install `ipfshttpclient`.

## Notes
- Azure and IPFS uploads are optional and will be skipped if not configured
- The script uses dynamic imports to avoid hard dependencies on optional packages
- File encryption uses AES-256 in CFB mode with random IVs
- The IV is stored as the first 16 bytes of the encrypted file

## License
MIT
