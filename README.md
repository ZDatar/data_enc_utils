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
- [Troubleshooting](#troubleshooting)
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
# As seller (use seller's private key)
python data_enc_util.py decrypt \
  --recipient seller \
  --private-key seller_1_sk.pem \
  --encrypted-key encrypted_aes_keys.json \
  --output decrypted_dataset.csv

# As buyer (use buyer's private key)
python data_enc_util.py decrypt \
  --recipient buyer \
  --private-key buyer_0_sk.pem \
  --encrypted-key encrypted_aes_keys.json \
  --output decrypted_dataset.csv
```

**Important**: The `--recipient` and `--private-key` must match:
- If `--recipient buyer`, use the buyer's private key (`buyer_0_sk.pem`)
- If `--recipient seller`, use the seller's private key (`seller_1_sk.pem`)

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

## Troubleshooting

### "Failed to decrypt AES key: Invalid curve secret key" or "An error occurred trying to decrypt the message"
This error occurs when:
1. You use the wrong private key for decryption
2. The public/private key pair is mismatched (public key doesn't correspond to the private key)

**Solution 1 - Verify correct private key**: Make sure the `--recipient` matches the `--private-key`:
```bash
# ❌ WRONG - Using seller's key for buyer
python data_enc_util.py decrypt --recipient buyer --private-key seller_1_sk.pem ...

# ✅ CORRECT - Using buyer's key for buyer
python data_enc_util.py decrypt --recipient buyer --private-key buyer_0_sk.pem ...
```

**Solution 2 - Verify key pair matches**: Ensure the public key was derived from the private key:
```bash
# For Solana/Ed25519 keys, verify the key pair
python3 -c "
import base58
from nacl.signing import SigningKey

with open('buyer_0_sk.pem', 'r') as f:
    sk = base58.b58decode(f.read().strip())
with open('buyer_0_pk.pem', 'r') as f:
    pk_stored = f.read().strip()

signing_key = SigningKey(sk[:32])
pk_derived = base58.b58encode(bytes(signing_key.verify_key)).decode()

print(f'Stored PK:  {pk_stored}')
print(f'Derived PK: {pk_derived}')
print(f'Match: {pk_stored == pk_derived}')
"
```

If the keys don't match, regenerate the public key from the private key or use a matching key pair.

### "Failed to decrypt AES key: Decryption failed"
This usually means:
1. The encrypted key file is corrupted
2. The private key doesn't match the public key used for encryption
3. The key format is incompatible (RSA vs Solana)

**Solution**: 
- Verify the encrypted key file is not corrupted
- Ensure you're using the correct private key that corresponds to the public key used during encryption
- Check the key type matches (RSA keys can't decrypt Solana-encrypted data and vice versa)

### "No encrypted key found for [recipient] in JSON file"
The JSON file doesn't contain an encrypted key for the specified recipient.

**Solution**: 
- Check the encryption was done with `--encrypt-for both` or `--encrypt-for [recipient]`
- Verify the JSON file structure contains the recipient's key

### Azure/IPFS Upload Warnings
These are informational and won't prevent encryption/decryption from working.

**Solution**: 
- For Azure: Set `AZURE_CONNECTION_STRING` in `.env` file
- For IPFS: Start IPFS daemon with `ipfs daemon` or install `ipfshttpclient`

## Notes
- Azure and IPFS uploads are optional and will be skipped if not configured
- The script uses dynamic imports to avoid hard dependencies on optional packages
- File encryption uses AES-256 in CFB mode with random IVs
- The IV is stored as the first 16 bytes of the encrypted file
- **Always use the correct private key**: buyer's private key for buyer, seller's private key for seller

## License
MIT
