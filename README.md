# Data Encryption Utility

This utility encrypts a dataset for secure sharing between a buyer and seller, supporting both RSA and Solana/Ed25519 key formats. It also implements a simplified proxy re-encryption (PRE) scheme, allowing both parties to decrypt the data with their own private keys.

## Features
- AES encryption of dataset files
- Public key encryption for buyer and seller (RSA or Solana)
- Proxy re-encryption: enables both parties to decrypt with their own keys
- Combined encrypted key file for multi-party access
- Uploads encrypted files to Azure Blob Storage and IPFS
- Dynamic imports for optional dependencies

## Usage

### Encrypt for Buyer, Seller, or Both
```bash
python data_enc_util.py --encrypt-for buyer
python data_enc_util.py --encrypt-for seller
python data_enc_util.py --encrypt-for both
```

### Arguments
- `--buyer-pk`: Path to buyer public key (PEM or Solana base58)
- `--seller-sk`: Path to seller private key (PEM)
- `--seller-pk`: Path to seller public key (PEM or Solana base58)

### Output
- Encrypted dataset: `test_dataset_encrypted.bin`
- Encrypted AES key(s):
  - For buyer: `encrypted_aes_key_buyer.bin`
  - For seller: `encrypted_aes_key_seller.bin`
  - For both: `encrypted_aes_keys.json`
- Uploads to Azure and IPFS (if configured)

## Proxy Re-Encryption (PRE)
When encrypting for both, the utility creates a structure that allows both buyer and seller to decrypt the AES key using their own private keys, without sharing secrets.

## Requirements
See `requirements.txt` for dependencies. Install with:
```bash
pip install -r requirements.txt
```

## Notes
- Keys can be RSA (PEM) or Solana/Ed25519 (base58)
- Azure and IPFS uploads require configuration and running services
- For decryption helpers, see future updates

## License
MIT
