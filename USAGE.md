# Usage Guide

## Help Information

### General Help
```bash
$ python data_enc_util.py --help
```

Output:
```
Data Encryption/Decryption Utility
================================================================================

MODES:
  Encryption (default):  python data_enc_util.py [options]
  Decryption:           python data_enc_util.py decrypt [options]

For mode-specific help:
  python data_enc_util.py --help          # Encryption help
  python data_enc_util.py decrypt --help  # Decryption help

================================================================================

usage: data_enc_util.py [-h] [--encrypt-for {buyer,seller,both}]
                        [--buyer-pk PATH] [--seller-sk PATH]
                        [--seller-pk PATH]

Encrypt dataset and AES key for recipients using RSA or Solana/Ed25519 keys

options:
  -h, --help            show this help message and exit
  --encrypt-for {buyer,seller,both}
                        Who to encrypt the AES key for. "both" uses proxy re-
                        encryption (default: both)
  --buyer-pk PATH       Path to buyer public key in PEM or Solana base58
                        format (default: /home/azureuser/zdatar/data_enc_utils
                        /buyer_0_pk.pem)
  --seller-sk PATH      Path to seller private key in PEM format to derive
                        seller public key (default: /home/azureuser/zdatar/dat
                        a_enc_utils/seller_1_sk.pem)
  --seller-pk PATH      Path to seller public key (PEM or Solana base58). If
                        provided, used instead of deriving from --seller-sk

Examples:
  python data_enc_util.py --encrypt-for seller
  python data_enc_util.py --encrypt-for buyer
  python data_enc_util.py --encrypt-for both

For decryption, use: python data_enc_util.py decrypt --help
```

### Decryption Help
```bash
$ python data_enc_util.py decrypt --help
```

Output:
```
usage: data_enc_util.py decrypt [-h] --recipient {buyer,seller}
                                --private-key PATH
                                [--encrypted-file PATH]
                                --encrypted-key PATH --output PATH

Decrypt dataset using encrypted AES key and recipient private key

options:
  -h, --help            show this help message and exit
  --recipient {buyer,seller}
                        Who is decrypting (buyer or seller) - required
  --private-key PATH    Path to recipient private key in PEM, Solana base58,
                        or JSON array format - required
  --encrypted-file PATH
                        Path to encrypted dataset file (default:
                        /home/azureuser/zdatar/data_enc_utils/test_dataset_en
                        crypted.bin)
  --encrypted-key PATH  Path to encrypted AES key file (.bin) or JSON file
                        (.json) with encrypted keys - required
  --output PATH         Path to save decrypted file - required

Examples:
  # Decrypt as seller using JSON key file
  python data_enc_util.py decrypt --recipient seller \
    --private-key seller_sk.pem \
    --encrypted-key encrypted_aes_keys.json \
    --output decrypted_dataset.csv

  # Decrypt as buyer using binary key file
  python data_enc_util.py decrypt --recipient buyer \
    --private-key buyer_sk.pem \
    --encrypted-key encrypted_aes_key_buyer.bin \
    --encrypted-file test_dataset_encrypted.bin \
    --output decrypted_dataset.csv
```

## Common Use Cases

### 1. Encrypt for Both Parties (Recommended)
```bash
python data_enc_util.py --encrypt-for both
```

This creates:
- `test_dataset_encrypted.bin` - The encrypted dataset
- `encrypted_aes_keys.json` - Contains encrypted keys for both buyer and seller

### 2. Encrypt for Seller Only
```bash
python data_enc_util.py --encrypt-for seller
```

This creates:
- `test_dataset_encrypted.bin` - The encrypted dataset
- `encrypted_aes_key_seller.bin` - Encrypted key for seller

### 3. Encrypt for Buyer Only
```bash
python data_enc_util.py --encrypt-for buyer
```

This creates:
- `test_dataset_encrypted.bin` - The encrypted dataset
- `encrypted_aes_key_buyer.bin` - Encrypted key for buyer

### 4. Decrypt as Seller
```bash
python data_enc_util.py decrypt \
  --recipient seller \
  --private-key /path/to/seller_1_sk.pem \
  --encrypted-key encrypted_aes_keys.json \
  --output decrypted_dataset.csv
```

### 5. Decrypt as Buyer
```bash
python data_enc_util.py decrypt \
  --recipient buyer \
  --private-key /path/to/buyer_0_sk.pem \
  --encrypted-key encrypted_aes_keys.json \
  --output decrypted_dataset.csv
```

### 6. Custom Key Paths
```bash
# Encryption with custom paths
python data_enc_util.py \
  --encrypt-for both \
  --buyer-pk /custom/path/buyer_public.pem \
  --seller-sk /custom/path/seller_private.pem

# Decryption with custom paths
python data_enc_util.py decrypt \
  --recipient seller \
  --private-key /custom/path/seller_private.pem \
  --encrypted-file /custom/path/encrypted_data.bin \
  --encrypted-key /custom/path/encrypted_keys.json \
  --output /custom/path/decrypted_data.csv
```

## Log File

All operations are logged to `data_enc_util.log` with timestamps:

```
2025-10-25 10:07:30 - INFO - ================================================================================
2025-10-25 10:07:30 - INFO - Script invoked: python data_enc_util.py --encrypt-for seller
2025-10-25 10:07:30 - INFO - Timestamp: 2025-10-25 10:07:30
2025-10-25 10:07:30 - INFO - ================================================================================
2025-10-25 10:07:31 - INFO - ✅ Encrypted file saved to /home/azureuser/zdatar/data_enc_utils/test_dataset_encrypted.bin
2025-10-25 10:07:31 - WARNING - ⚠️ AZURE_CONNECTION_STRING not set; skipped Azure upload.
2025-10-25 10:07:31 - WARNING - ⚠️ ipfshttpclient failed: ...
2025-10-25 10:07:32 - INFO - 
🔐 Re-Encryption & Upload Summary:
2025-10-25 10:07:32 - INFO - • Encrypted file: /home/azureuser/zdatar/data_enc_utils/test_dataset_encrypted.bin
2025-10-25 10:07:32 - INFO - • IPFS CID: None
2025-10-25 10:07:32 - INFO - • Azure URL: None
2025-10-25 10:07:32 - INFO - • Encrypted file SHA-256: abc123...
```

## Error Handling

The script provides clear error messages:

```bash
# Missing required argument
$ python data_enc_util.py decrypt --recipient seller
usage: data_enc_util.py decrypt [-h] --recipient {buyer,seller}
                                --private-key PATH
                                [--encrypted-file PATH]
                                --encrypted-key PATH --output PATH
data_enc_util.py decrypt: error: the following arguments are required: --private-key, --encrypted-key, --output

# Invalid key file
$ python data_enc_util.py decrypt --recipient seller --private-key invalid.pem --encrypted-key keys.json --output out.csv
================================================================================
Script invoked: python data_enc_util.py decrypt --recipient seller --private-key invalid.pem --encrypted-key keys.json --output out.csv
Timestamp: 2025-10-25 10:07:30
================================================================================
❌ Failed to load private key from invalid.pem: [Errno 2] No such file or directory: 'invalid.pem'
```
