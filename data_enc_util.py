#!/usr/bin/env python3
"""
Data Encryption/Decryption Utility

This utility provides secure encryption and decryption of datasets for sharing
between buyers and sellers using RSA or Solana/Ed25519 key formats.

Features:
    - AES-256 encryption/decryption in CFB mode
    - RSA and Solana/Ed25519 public key encryption
    - Proxy re-encryption for multi-party access
    - Azure Blob Storage and IPFS upload support
    - Comprehensive logging to console and file
    - SHA-256 file integrity verification

Usage:
    Encryption:
        python data_enc_util.py --encrypt-for both
        python data_enc_util.py --encrypt-for seller
        python data_enc_util.py --encrypt-for buyer
    
    Decryption:
        python data_enc_util.py decrypt --recipient seller \\
            --private-key seller_sk.pem \\
            --encrypted-key encrypted_aes_keys.json \\
            --output decrypted_dataset.csv
    
    Help:
        python data_enc_util.py --help
        python data_enc_util.py decrypt --help

Author: ZDatar Team
License: MIT
"""
import os
import sys
import base64
import hashlib
import json
import mimetypes
import argparse
import logging
import secrets
from datetime import datetime
from typing import Any, Dict, Optional, Union, List, Mapping, Sequence, Tuple, cast

import importlib
import requests
from dotenv import load_dotenv
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from typing import TYPE_CHECKING

# Avoid static imports of optional third-party libraries so linters/type
# checkers running in environments without those packages installed do not
# emit a large number of unresolved-import/unknown-type diagnostics. We use
# importlib.import_module at runtime where the functionality is required.

if TYPE_CHECKING:
    # Allow type checkers to see the real modules when available in the
    # development environment. These imports are only for typing; at runtime
    # we import dynamically to avoid hard dependency.
    import rsa  # type: ignore
    from azure.storage.blob import BlobServiceClient  # type: ignore
    from nacl.signing import SigningKey as NaClSigningKey  # type: ignore
else:  # pragma: no cover - typing fallback
    NaClSigningKey = Any  # type: ignore


SolanaSecretSource = Union[bytes, bytearray, memoryview, NaClSigningKey]

# === CONFIGURATION ===
# Default file paths - can be overridden via command-line arguments
SELLER_PRIVATE_KEY_PATH = "/home/azureuser/zdatar/data_enc_utils/seller_1_sk.pem"
SELLER_PUBLIC_KEY_PATH = "/home/azureuser/zdatar/data_enc_utils/seller_1_pk.pem"
BUYER_PUBLIC_KEY_PATH = "/home/azureuser/zdatar/data_enc_utils/buyer_0_pk.pem"
DATASET_PATH = "/home/azureuser/zdatar/data_enc_utils/test_dataset.csv"
ENCRYPTED_FILE_PATH = "/home/azureuser/zdatar/data_enc_utils/test_dataset_encrypted.bin"
ENCRYPTED_AES_KEY_BUYER_PATH = "/home/azureuser/zdatar/data_enc_utils/encrypted_aes_key_buyer.bin"
ENCRYPTED_AES_KEY_SELLER_PATH = "/home/azureuser/zdatar/data_enc_utils/encrypted_aes_key_seller.bin"
ENCRYPTED_AES_KEYS_COMBINED_PATH = "/home/azureuser/zdatar/data_enc_utils/encrypted_aes_keys.json"
ENCRYPTED_AES_KEY_BUYER_ENVELOPE_PATH = "/home/azureuser/zdatar/data_enc_utils/encrypted_aes_key_buyer.json"
ENCRYPTED_AES_KEY_SELLER_ENVELOPE_PATH = "/home/azureuser/zdatar/data_enc_utils/encrypted_aes_key_seller.json"
MULTI_RECIPIENT_INFO = b"ZDatar AES key envelope v1"

load_dotenv()
AZURE_CONNECTION_STRING = os.getenv("AZURE_CONNECTION_STRING")
AZURE_CONTAINER_NAME = "zdatar-data"

# Logging configuration
LOG_FILE_PATH = "/home/azureuser/zdatar/data_enc_utils/data_enc_util.log"

def setup_logging():
    """Configure logging to output to both console and file."""
    # Create logger
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    
    # Remove any existing handlers
    logger.handlers = []
    
    # Create formatters
    file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    console_formatter = logging.Formatter('%(message)s')
    
    # File handler
    file_handler = logging.FileHandler(LOG_FILE_PATH, mode='a', encoding='utf-8')
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(file_formatter)
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(console_formatter)
    
    # Add handlers to logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger


def generate_aes_key() -> bytes:
    return os.urandom(32)


def encrypt_file_with_aes(input_path: str, output_path: str, aes_key: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
        f_out.write(iv)
        while chunk := f_in.read(4096):
            f_out.write(encryptor.update(chunk))
        f_out.write(encryptor.finalize())
    logging.info(f"✅ Encrypted file saved to {output_path}")
    return iv


def decrypt_file_with_aes(input_path: str, output_path: str, aes_key: bytes) -> None:
    """Decrypt a file that was encrypted with encrypt_file_with_aes.
    
    The encrypted file has the IV as the first 16 bytes, followed by the encrypted data.
    """
    with open(input_path, 'rb') as f_in:
        iv = f_in.read(16)
        if len(iv) != 16:
            raise ValueError(f"Invalid encrypted file: expected 16-byte IV, got {len(iv)} bytes")
        
        cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        with open(output_path, 'wb') as f_out:
            while chunk := f_in.read(4096):
                f_out.write(decryptor.update(chunk))
            f_out.write(decryptor.finalize())
    
    logging.info(f"✅ Decrypted file saved to {output_path}")


# ---------- Multi-recipient Hybrid Encryption Helpers ----------

def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data_b64: str) -> bytes:
    return base64.b64decode(data_b64.encode("ascii"))


def hkdf_sha256(ikm: bytes, salt: Optional[bytes], info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def load_x25519_sk(sk_bytes: bytes) -> X25519PrivateKey:
    return X25519PrivateKey.from_private_bytes(sk_bytes)


def load_x25519_pk(pk_bytes: bytes) -> X25519PublicKey:
    return X25519PublicKey.from_public_bytes(pk_bytes)


def solana_to_x25519_keypair(solana_privkey_bytes: bytes) -> Tuple[bytes, bytes]:
    """
    Convert a 32-byte seed or 64-byte Solana (Ed25519) private key to an X25519 key pair.
    Returns a tuple of (x25519_private_key_bytes, x25519_public_key_bytes).
    """
    if len(solana_privkey_bytes) == 64:
        seed = solana_privkey_bytes[:32]
    elif len(solana_privkey_bytes) == 32:
        seed = solana_privkey_bytes
    else:
        raise ValueError("Solana private key must be 32 or 64 bytes")

    _nacl_signing = importlib.import_module('nacl.signing')  # type: ignore
    SigningKey = getattr(_nacl_signing, 'SigningKey')  # type: ignore
    ed_sk = SigningKey(seed)
    ed_pk = ed_sk.verify_key
    x_sk = ed_sk.to_curve25519_private_key()
    x_pk = ed_pk.to_curve25519_public_key()
    return cast(bytes, x_sk.encode()), cast(bytes, x_pk.encode())


def solana_pub_to_x25519_pub(solana_pubkey_bytes: bytes) -> bytes:
    _nacl_signing = importlib.import_module('nacl.signing')  # type: ignore
    VerifyKey = getattr(_nacl_signing, 'VerifyKey')  # type: ignore
    ed_pk = VerifyKey(solana_pubkey_bytes)
    x_pk = ed_pk.to_curve25519_public_key()
    return cast(bytes, x_pk.encode())


def solana_private_to_x25519_private_bytes(private_key: Any) -> bytes:
    """
    Accepts the Solana private key formats returned by load_rsa_private_key and
    converts them into raw X25519 private key bytes.
    """
    candidate: Optional[bytes] = None

    if isinstance(private_key, tuple) and len(private_key) >= 2:
        maybe_bytes = private_key[1]
        if isinstance(maybe_bytes, (bytes, bytearray, memoryview)):
            candidate = bytes(maybe_bytes)
    elif isinstance(private_key, (bytes, bytearray, memoryview)):
        candidate = bytes(private_key)
    else:
        try:
            _nacl_signing = importlib.import_module('nacl.signing')  # type: ignore
            SigningKey = getattr(_nacl_signing, 'SigningKey')  # type: ignore
            if isinstance(private_key, SigningKey):
                candidate = bytes(private_key)
        except Exception:
            candidate = None

    if candidate is None:
        raise ValueError("Unsupported Solana private key format for X25519 conversion")

    return solana_to_x25519_keypair(candidate)[0]


def encrypt_multi(
    message: bytes,
    recipients: Sequence[Mapping[str, Union[str, bytes]]],
    *,
    aead_alg: str = "AESGCM-256",
    kem: str = "X25519-HKDF-SHA256",
    info: bytes = MULTI_RECIPIENT_INFO,
    kid_field: str = "kid",
    aad_extra: Optional[bytes] = None,
) -> str:
    """
    Multi-recipient hybrid encryption: encrypt `message` once and wrap the data key
    separately for each recipient using X25519 + HKDF + AES-GCM.
    """
    if not recipients:
        raise ValueError("At least one recipient is required for multi-recipient encryption")

    data_key = secrets.token_bytes(32)  # 256-bit AES key
    nonce_data = secrets.token_bytes(12)  # AES-GCM nonce

    recipients_entries: List[Dict[str, str]] = []
    for recipient in recipients:
        kid_value = recipient.get(kid_field)
        if not isinstance(kid_value, str):
            raise TypeError(f"Recipient field '{kid_field}' must be a string, got {type(kid_value)!r}")
        pk_value = recipient.get("pk")
        if not isinstance(pk_value, (bytes, bytearray)):
            raise TypeError("Recipient 'pk' must be bytes")

        kid = kid_value
        pk_r = load_x25519_pk(bytes(pk_value))
        eph_sk = X25519PrivateKey.generate()
        eph_pk = eph_sk.public_key()

        shared = eph_sk.exchange(pk_r)
        context = (
            b"kw-context|" + info +
            b"|aead=" + aead_alg.encode() +
            b"|kem=" + kem.encode() +
            b"|kid=" + kid.encode()
        )
        wrap_key = hkdf_sha256(shared, salt=None, info=context, length=32)

        aes_kw = AESGCM(wrap_key)
        nonce_kw = secrets.token_bytes(12)
        aad_kw = b"kw-aad|" + kid.encode() + b"|" + eph_pk.public_bytes_raw()
        wrapped = aes_kw.encrypt(nonce_kw, data_key, aad_kw)

        recipients_entries.append({
            kid_field: kid,
            "kem": kem,
            "eph_pub": b64e(eph_pk.public_bytes_raw()),
            "nonce": b64e(nonce_kw),
            "kw": b64e(wrapped),
        })

    header: Dict[str, Union[str, List[Dict[str, str]]]] = {
        "ver": "1",
        "aead": aead_alg,
        "nonce": b64e(nonce_data),
        "recipients": recipients_entries,
    }
    if aad_extra:
        header["aad_ext"] = b64e(aad_extra)

    aad_header = json.dumps(header, separators=(",", ":"), sort_keys=True).encode()
    ciphertext = AESGCM(data_key).encrypt(nonce_data, message, aad_header)
    header["ciphertext"] = b64e(ciphertext)
    return json.dumps(header, separators=(",", ":"), sort_keys=True)


def decrypt_multi_envelope(
    envelope_json: str,
    sk_bytes: bytes,
    *,
    info: bytes = MULTI_RECIPIENT_INFO,
    expected_kid: Optional[str] = None,
) -> bytes:
    """
    Attempt to decrypt the multi-recipient envelope using the provided X25519 private key.
    """
    envelope = cast(Dict[str, Any], json.loads(envelope_json))
    nonce_data = b64d(cast(str, envelope["nonce"]))
    ciphertext = b64d(cast(str, envelope["ciphertext"]))

    recipients_list = cast(Sequence[Dict[str, Any]], envelope["recipients"])
    if expected_kid:
        ordered = [r for r in recipients_list if r.get("kid") == expected_kid]
        if not ordered:
            ordered = list(recipients_list)
    else:
        ordered = list(recipients_list)

    header_copy: Dict[str, Any] = dict(envelope)
    del header_copy["ciphertext"]
    aad_header = json.dumps(header_copy, separators=(",", ":"), sort_keys=True).encode()

    sk = load_x25519_sk(sk_bytes)
    last_err: Optional[Exception] = None
    for entry in ordered:
        try:
            eph_pub = load_x25519_pk(b64d(cast(str, entry["eph_pub"])))
            nonce_kw = b64d(cast(str, entry["nonce"]))
            wrapped = b64d(cast(str, entry["kw"]))
            kid = cast(str, entry.get("kid", ""))

            shared = sk.exchange(eph_pub)
            context = (
                b"kw-context|" + info +
                b"|aead=" + cast(str, envelope["aead"]).encode() +
                b"|kem=" + cast(str, entry.get("kem", "X25519-HKDF-SHA256")).encode() +
                b"|kid=" + kid.encode()
            )
            wrap_key = hkdf_sha256(shared, salt=None, info=context, length=32)
            aad_kw = b"kw-aad|" + kid.encode() + b"|" + eph_pub.public_bytes_raw()
            data_key = AESGCM(wrap_key).decrypt(nonce_kw, wrapped, aad_kw)
            return AESGCM(data_key).decrypt(nonce_data, ciphertext, aad_header)
        except Exception as exc:
            last_err = exc
            continue

    raise Exception(f"Unable to decrypt envelope for provided key. Last error: {last_err!r}")


def build_solana_recipient_entries(label_to_public: Mapping[str, Union[str, bytes]]) -> List[Dict[str, Union[str, bytes]]]:
    """
    Convert a mapping of label -> Solana public key (base58 string or raw bytes)
    into recipient entries accepted by encrypt_multi.
    """
    _base58 = None
    try:
        _base58 = importlib.import_module('base58')  # type: ignore
    except Exception:
        # Only raise if we actually need to decode base58 strings below
        _base58 = None

    entries: List[Dict[str, Union[str, bytes]]] = []
    for label, value in label_to_public.items():
        if isinstance(value, str):
            if _base58 is None:
                raise RuntimeError("base58 package is required for Solana recipients")
            decoded = getattr(_base58, 'b58decode')(value)  # type: ignore
            if not isinstance(decoded, (bytes, bytearray)):
                raise ValueError(f"Decoded Solana public key for {label} is not bytes")
            raw_pub = bytes(decoded)
        elif isinstance(value, (bytes, bytearray, memoryview)):
            raw_pub = bytes(value)
        else:
            raise TypeError(f"Unsupported Solana public key type for {label}: {type(value)!r}")

        if len(raw_pub) != 32:
            raise ValueError(f"Solana public key for {label} must be 32 bytes, got {len(raw_pub)} bytes")

        entries.append({"kid": label, "pk": solana_pub_to_x25519_pub(raw_pub)})
    return entries


def is_multi_recipient_envelope(obj: Any) -> bool:
    return (
        isinstance(obj, Mapping)
        and "ciphertext" in obj
        and "recipients" in obj
        and "nonce" in obj
        and "aead" in obj
    )


def load_rsa_private_key(path: str) -> Any:
    """Load an RSA private key from a file.
    
    Supports multiple formats:
    - PKCS#1 PEM format (rsa library)
    - PKCS#8 PEM format (cryptography library)
    - Solana/Ed25519 keys (base58 or JSON array)
    """
    data = open(path, 'rb').read()
    
    # Try rsa.PrivateKey.load_pkcs1
    try:
        _rsa = importlib.import_module('rsa')
        return getattr(_rsa.PrivateKey, 'load_pkcs1')(data)  # type: ignore
    except Exception:
        pass
    
    # Try to load as PEM RSA private key using cryptography
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa as crypto_rsa
    try:
        priv = serialization.load_pem_private_key(data, password=None, backend=default_backend())
        if isinstance(priv, crypto_rsa.RSAPrivateKey):
            # Convert to rsa library format for consistency
            numbers = priv.private_numbers()
            _rsa = importlib.import_module('rsa')
            return _rsa.PrivateKey(
                numbers.public_numbers.n,
                numbers.public_numbers.e,
                numbers.d,
                numbers.p,
                numbers.q
            )  # type: ignore
    except Exception:
        pass
    
    # Try Solana/Ed25519 format (base58 or JSON array)
    try:
        text = data.decode('utf-8').strip()
    except Exception:
        text = ''
    
    if text:
        raw: bytes = b''
        # try base58
        try:
            _base58 = importlib.import_module('base58')  # type: ignore
            decoded = getattr(_base58, 'b58decode')(text)  # type: ignore
            raw = decoded  # type: ignore
        except Exception:
            pass
        
        # try JSON array of ints
        if not raw:
            try:
                arr_obj = json.loads(text)
                if isinstance(arr_obj, list):
                    arr_items = cast(Sequence[object], arr_obj)
                    int_items: List[int] = []
                    invalid_item = False
                    for item_obj in arr_items:
                        if not isinstance(item_obj, int):
                            invalid_item = True
                            break
                        int_items.append(int(item_obj))
                    if not invalid_item:
                        raw = bytes(int_items)
            except Exception:
                pass
        
        # If we have 32 or 64 bytes, treat as Ed25519 secret
        if isinstance(raw, (bytes, bytearray)) and len(raw) in (32, 64):
            try:
                _nacl_signing = importlib.import_module('nacl.signing')  # type: ignore
            except Exception as e:
                raise RuntimeError("PyNaCl is required to load Ed25519 private keys: " + str(e))
            
            SigningKey = getattr(_nacl_signing, 'SigningKey')  # type: ignore
            
            if len(raw) == 64:
                seed = bytes(raw[:32])
            else:
                seed = bytes(raw)
            
            # Return a tuple: (SigningKey, full_64_byte_key)
            # The full 64-byte key is needed for Curve25519 conversion
            signing_key = SigningKey(seed)
            if len(raw) == 64:
                return (signing_key, bytes(raw))
            else:
                # If only 32 bytes, construct the full 64-byte key
                return (signing_key, bytes(signing_key))
    
    raise ValueError(f"Unable to load private key from {path}")


def load_rsa_public_key(path: str) -> Any:
    data = open(path, 'rb').read()
    try:
        _rsa = importlib.import_module('rsa')
        return getattr(_rsa.PublicKey, 'load_pkcs1')(data)  # type: ignore
    except Exception:
        pass
    try:
        _rsa = importlib.import_module('rsa')
        return getattr(_rsa.PublicKey, 'load_pkcs1_openssl_pem')(data)  # type: ignore
    except Exception:
        pass
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa as crypto_rsa
    pub = serialization.load_pem_public_key(data, backend=default_backend())
    # Only RSA public keys expose .public_numbers() with .n and .e fields
    if isinstance(pub, crypto_rsa.RSAPublicKey):
        numbers = pub.public_numbers()
        # numbers.n and numbers.e are ints
        _rsa = importlib.import_module('rsa')
        return _rsa.PublicKey(numbers.n, numbers.e)  # type: ignore
    raise ValueError("Unsupported public key type: expected RSA public key")


def is_solana_base58_key(data: bytes) -> bool:
    s = data.decode('utf-8', errors='ignore').strip()
    if len(s) in (43, 44):
        try:
            _base58 = importlib.import_module('base58')  # type: ignore
            decoded = getattr(_base58, 'b58decode')(s)  # type: ignore
            # decoded should be bytes; narrow the type for the type checker
            if not isinstance(decoded, (bytes, bytearray)):
                return False
            return len(decoded) == 32
        except Exception:
            return False
    return False


def decrypt_aes_key_with_solana(encrypted_key: bytes, private_key: Any) -> bytes:
    """Decrypt an AES key using a Solana/Ed25519 private key.
    
    Args:
        encrypted_key: The encrypted AES key bytes
        private_key: A tuple of (SigningKey, full_64_byte_key) or just the 64-byte key
    
    Returns:
        The decrypted AES key
    """
    try:
        _nacl_public = importlib.import_module('nacl.public')  # type: ignore
        from nacl.bindings import crypto_sign_ed25519_sk_to_curve25519  # type: ignore
    except Exception as e:
        raise RuntimeError('PyNaCl (nacl) is required for Solana/Ed25519 operations: ' + str(e))
    
    SealedBox = getattr(_nacl_public, 'SealedBox')  # type: ignore
    PrivateKey = getattr(_nacl_public, 'PrivateKey')  # type: ignore
    
    secret_key_source: SolanaSecretSource

    # Extract the 64-byte key from the tuple if needed
    if isinstance(private_key, tuple):
        secret_key_source = cast(SolanaSecretSource, private_key[1])
    else:
        secret_key_source = cast(SolanaSecretSource, private_key)

    secret_key_bytes: bytes = bytes(secret_key_source)
    
    try:
        # Convert Ed25519 secret key (64 bytes) to Curve25519 private key (32 bytes)
        curve25519_private_key_bytes = crypto_sign_ed25519_sk_to_curve25519(secret_key_bytes)
        
        # Create a Curve25519 PrivateKey for decryption
        encryption_private_key = PrivateKey(curve25519_private_key_bytes)
        
        # Decrypt using SealedBox
        box = SealedBox(encryption_private_key)  # type: ignore
        return cast(bytes, box.decrypt(encrypted_key))  # type: ignore
    except Exception as e:
        raise ValueError(f"Failed to decrypt with Solana key: {e}. The key format or encrypted data may be incompatible.")


def encrypt_aes_key_with_solana(aes_key: bytes, sol_base58_str: str) -> bytes:
    _base58 = importlib.import_module('base58')  # type: ignore
    pub_raw = getattr(_base58, 'b58decode')(sol_base58_str)  # type: ignore
    # ensure bytes for the NaCl API
    if not isinstance(pub_raw, (bytes, bytearray)):
        raise ValueError("Invalid Solana public key (not decodable to bytes)")
    # Import PyNaCl dynamically; raise informative error if unavailable at runtime
    try:
        _nacl_public = importlib.import_module('nacl.public')  # type: ignore
        from nacl.bindings import crypto_sign_ed25519_pk_to_curve25519  # type: ignore
    except Exception as e:
        raise RuntimeError('PyNaCl (nacl) is required for Solana/Ed25519 operations: ' + str(e))
    
    SealedBox = getattr(_nacl_public, 'SealedBox')  # type: ignore
    NaClPublicKey = getattr(_nacl_public, 'PublicKey')  # type: ignore
    
    # Convert Ed25519 public key (32 bytes) to Curve25519 public key (32 bytes)
    curve25519_public_key_bytes = crypto_sign_ed25519_pk_to_curve25519(bytes(pub_raw))
    
    box = SealedBox(NaClPublicKey(curve25519_public_key_bytes))  # type: ignore
    return cast(bytes, box.encrypt(aes_key))  # type: ignore


def decrypt_aes_key_with_rsa(encrypted_key: bytes, private_key: Any) -> bytes:
    """Decrypt an AES key using an RSA private key.
    
    Args:
        encrypted_key: The encrypted AES key bytes
        private_key: An rsa.PrivateKey object
    
    Returns:
        The decrypted AES key
    """
    _rsa = importlib.import_module('rsa')
    return cast(bytes, getattr(_rsa, 'decrypt')(encrypted_key, private_key))  # type: ignore


def decrypt_for_recipient(encrypted_key: bytes, private_key: Any, is_solana: bool = False) -> bytes:
    """Decrypt an AES key that was encrypted for a recipient.
    
    Handles both regular encryption and proxy re-encryption.
    
    Args:
        encrypted_key: The encrypted AES key bytes
        private_key: The recipient's private key (RSA, Solana, or tuple)
        is_solana: True if the private key is a Solana/Ed25519 key
    
    Returns:
        The decrypted AES key
    """
    # Check if this is a proxy re-encryption (starts with 'PRE:')
    if encrypted_key.startswith(b'PRE:'):
        # Extract the components: marker + temp_key_length + encrypted_temp + IV + encrypted_original
        data = encrypted_key[4:]  # Skip 'PRE:' marker
        temp_key_len = int.from_bytes(data[:4], 'big')
        encrypted_temp = data[4:4+temp_key_len]
        iv = data[4+temp_key_len:4+temp_key_len+16]  # Extract 16-byte IV
        encrypted_original = data[4+temp_key_len+16:]  # Rest is encrypted AES key
        
        # Decrypt the temporary key with the recipient's private key
        if is_solana or isinstance(private_key, tuple):
            temp_key = decrypt_aes_key_with_solana(encrypted_temp, private_key)
        else:
            temp_key = decrypt_aes_key_with_rsa(encrypted_temp, private_key)
        
        # Decrypt the original AES key with the temporary key using the extracted IV
        cipher = Cipher(algorithms.AES(temp_key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        aes_key = decryptor.update(encrypted_original) + decryptor.finalize()
        return aes_key
    else:
        # Regular encryption
        if is_solana or isinstance(private_key, tuple):
            return decrypt_aes_key_with_solana(encrypted_key, private_key)
        else:
            return decrypt_aes_key_with_rsa(encrypted_key, private_key)


def encrypt_for_recipient(aes_key: bytes, recipient_pk: Union[str, Any], is_re_encryption: bool = False) -> bytes:
    # For re-encryption, we create a temporary AES key and encrypt both the original key and temporary key
    if is_re_encryption:
        temp_key = os.urandom(32)  # Generate temporary key for re-encryption
        # Encrypt the original AES key with temp key
        iv = os.urandom(16)  # Generate IV and store it
        cipher = Cipher(algorithms.AES(temp_key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_original = encryptor.update(aes_key) + encryptor.finalize()
        # Now encrypt temp key for recipient
        if isinstance(recipient_pk, str):
            encrypted_temp = encrypt_aes_key_with_solana(temp_key, recipient_pk)
        else:
            _rsa = importlib.import_module('rsa')
            encrypted_temp = getattr(_rsa, 'encrypt')(temp_key, recipient_pk)  # type: ignore
        # Combine: marker + temp_key_length + encrypted_temp + IV + encrypted_original
        return b'PRE:' + len(encrypted_temp).to_bytes(4, 'big') + encrypted_temp + iv + encrypted_original
    else:
        if isinstance(recipient_pk, str):
            return encrypt_aes_key_with_solana(aes_key, recipient_pk)
        _rsa = importlib.import_module('rsa')
        return getattr(_rsa, 'encrypt')(aes_key, recipient_pk)  # type: ignore


def derive_rsa_public_from_private(private_path: str) -> Any:
    data = open(private_path, 'rb').read()
    # Try rsa.PrivateKey.load_pkcs1
    try:
        _rsa = importlib.import_module('rsa')
        priv = getattr(_rsa.PrivateKey, 'load_pkcs1')(data)  # type: ignore
        return _rsa.PublicKey(priv.n, priv.e)  # type: ignore
    except Exception:
        pass

    # Try to load as PEM RSA private key first using cryptography
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa as crypto_rsa
    try:
        priv = serialization.load_pem_private_key(data, password=None, backend=default_backend())
        # ensure it's an RSA private key
        if isinstance(priv, crypto_rsa.RSAPrivateKey):
            pub = priv.public_key()
            numbers = pub.public_numbers()
            _rsa = importlib.import_module('rsa')
            return _rsa.PublicKey(numbers.n, numbers.e)  # type: ignore
    except Exception:
        # not a PEM RSA private key; fall through to other formats
        pass

    # Some key files (Solana/Ed25519) store the secret as base58 or as a JSON array of ints.
    # Try to parse base58 first, then JSON array fallback.
    try:
        # attempt base58 decode of ascii content
        text = data.decode('utf-8').strip()
    except Exception:
        text = ''

    if text:
        raw: bytes = b''
        # try base58
        try:
            _base58 = importlib.import_module('base58')  # type: ignore
            decoded = getattr(_base58, 'b58decode')(text)  # type: ignore
            raw = decoded  # type: ignore
        except Exception:
            raw = raw

        # try JSON array of ints
            if not raw:
                try:
                    arr = json.loads(text)
                    if isinstance(arr, list):
                        arr_list = cast(List[Any], arr)
                        if all(isinstance(x, int) for x in arr_list):
                            # cast to list[int] for the bytes() constructor to be happy with type checkers
                            raw = bytes(cast(List[int], arr_list))
                except Exception:
                    pass

        # If we have 32 or 64 bytes, treat as Ed25519 secret (seed or seed+pub)
        if isinstance(raw, (bytes, bytearray)) and len(raw) in (32, 64):
            try:
                _nacl_signing = importlib.import_module('nacl.signing')  # type: ignore
                _nacl_encoding = importlib.import_module('nacl.encoding')  # type: ignore
            except Exception as e:
                raise RuntimeError("PyNaCl is required to derive Ed25519 public keys from non-PEM private keys: " + str(e))

            SigningKey = getattr(_nacl_signing, 'SigningKey')  # type: ignore
            RawEncoder = getattr(_nacl_encoding, 'RawEncoder')  # type: ignore

            if len(raw) == 64:
                seed = bytes(raw[:32])
            else:
                seed = bytes(raw)
            signing_key = SigningKey(seed)
            verify_key = signing_key.verify_key
            pub_raw = verify_key.encode(RawEncoder)
            # return the Solana-style base58 public key string
            try:
                _base58 = importlib.import_module('base58')  # type: ignore
                return getattr(_base58, 'b58encode')(pub_raw).decode('utf-8')
            except Exception:
                # fallback: return raw bytes (caller accepts str for solana-style keys)
                return pub_raw

    raise ValueError("Unable to derive public key from the provided private key file")


def upload_to_azure(file_path: str) -> Optional[str]:
    if not AZURE_CONNECTION_STRING:
        logging.warning("⚠️ AZURE_CONNECTION_STRING not set; skipped Azure upload.")
        return None
    _blob = importlib.import_module('azure.storage.blob')
    BlobServiceClient = getattr(_blob, 'BlobServiceClient')
    blob_service = BlobServiceClient.from_connection_string(AZURE_CONNECTION_STRING)  # type: ignore
    blob_client = blob_service.get_blob_client(container=AZURE_CONTAINER_NAME, blob=os.path.basename(file_path))  # type: ignore
    with open(file_path, "rb") as data:
        blob_client.upload_blob(data, overwrite=True)  # type: ignore
    url = f"https://{getattr(blob_service, 'account_name')}.blob.core.windows.net/{AZURE_CONTAINER_NAME}/{os.path.basename(file_path)}"
    logging.info(f"✅ Uploaded to Azure Blob: {url}")
    return url


def upload_to_ipfs(file_path: str) -> Optional[str]:
    try:
        _ipfsclient = importlib.import_module('ipfshttpclient')  # type: ignore
        client = getattr(_ipfsclient, 'connect')('/ip4/127.0.0.1/tcp/5001')  # type: ignore
        # client.add may return different shapes depending on ipfshttpclient version
        # use getattr so type checkers don't require the real package at analysis time
        result_raw = getattr(client, 'add')(file_path)  # type: ignore
        if isinstance(result_raw, Sequence):
            # result is a sequence-like; pick last element
            result_seq = cast(Sequence[Any], result_raw)
            obj: Any = result_seq[-1]
        else:
            obj = result_raw
        cid: Optional[str] = None
        if isinstance(obj, Mapping):
            # obj behaves like a dict
            m = cast(Mapping[str, Any], obj)
            maybe = m.get('Hash')
            if isinstance(maybe, str):
                cid = maybe
        else:
            # try attribute access more safely for objects returned by some clients
            attr = getattr(cast(object, obj), 'Hash', None)
            if isinstance(attr, str):
                cid = attr
        logging.info(f"✅ Uploaded to IPFS: {cid}")
        return cid
    except Exception as e:
        logging.warning(f"⚠️ ipfshttpclient failed: {e}")

    try:
        url = 'http://127.0.0.1:5001/api/v0/add'
        with open(file_path, 'rb') as f:
            files = {'file': (os.path.basename(file_path), f, mimetypes.guess_type(file_path)[0] or 'application/octet-stream')}
            resp = requests.post(url, files=files, timeout=10)
        resp.raise_for_status()
        last_line = resp.text.strip().split('\n')[-1]
        obj = json.loads(last_line)
        cid = obj.get('Hash')
        logging.info(f"✅ Uploaded to IPFS (HTTP API): {cid}")
        return cid
    except Exception as e:
        logging.warning(f"⚠️ HTTP IPFS upload fallback failed: {e}")
        return None


def make_encrypted_keys_json(paths: Dict[str, str]) -> str:
    out: Dict[str, Any] = {"recipients": {}}
    for label, path in paths.items():
        try:
            b = open(path, 'rb').read()
        except Exception as e:
            out['recipients'][label] = {"error": str(e)}
            continue
        out['recipients'][label] = {
            'file': path,
            'encryptedKey': base64.b64encode(b).decode('utf-8'),
            'format': 'base64',
            'sha256': hashlib.sha256(b).hexdigest(),
            'sha256_base64': base64.b64encode(hashlib.sha256(b).digest()).decode('utf-8'),
        }
    return json.dumps(out, indent=2)


def make_encrypted_keys_json_from_bytes(items: Dict[str, bytes]) -> str:
    """Create the same JSON structure as make_encrypted_keys_json but from in-memory bytes.

    items: mapping from label -> encrypted bytes
    """
    out: Dict[str, Any] = {"recipients": {}}
    for label, b in items.items():
        out['recipients'][label] = {
            'file': None,
            'encryptedKey': base64.b64encode(b).decode('utf-8'),
            'format': 'base64',
            'sha256': hashlib.sha256(b).hexdigest(),
            'sha256_base64': base64.b64encode(hashlib.sha256(b).digest()).decode('utf-8'),
        }
    return json.dumps(out, indent=2)


def compute_file_sha256(path: str) -> Optional[str]:
    """Compute SHA-256 hex digest for a file in a streaming manner.

    Returns hex digest string or None if file can't be read.
    """
    try:
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        logging.warning(f"⚠️ Could not compute SHA-256 for {path}: {e}")
        return None


def main(argv: Optional[List[str]] = None) -> None:
    # Setup logging first
    setup_logging()
    
    # Log the command line invocation
    if argv is None:
        cmd_line = ' '.join(sys.argv)
    else:
        cmd_line = f"python {sys.argv[0]} {' '.join(argv)}"
    
    logging.info("="*80)
    logging.info(f"Script invoked: {cmd_line}")
    logging.info(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logging.info("="*80)
    
    parser = argparse.ArgumentParser(
        description='Encrypt dataset and AES key for recipients using RSA or Solana/Ed25519 keys',
        epilog='Examples:\n'
               '  python data_enc_util.py --encrypt-for seller\n'
               '  python data_enc_util.py --encrypt-for buyer\n'
               '  python data_enc_util.py --encrypt-for both\n'
               '\n'
               'For decryption, use: python data_enc_util.py decrypt --help',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        '--encrypt-for', 
        choices=['buyer', 'seller', 'both'], 
        default='both',
        help='Who to encrypt the AES key for. "both" uses proxy re-encryption (default: both)'
    )
    parser.add_argument(
        '--buyer-pk', 
        default=BUYER_PUBLIC_KEY_PATH,
        metavar='PATH',
        help=f'Path to buyer public key in PEM or Solana base58 format (default: {BUYER_PUBLIC_KEY_PATH})'
    )
    parser.add_argument(
        '--seller-sk', 
        default=SELLER_PRIVATE_KEY_PATH,
        metavar='PATH',
        help=f'Path to seller private key in PEM format to derive seller public key (default: {SELLER_PRIVATE_KEY_PATH})'
    )
    parser.add_argument(
        '--seller-pk', 
        default=None,
        metavar='PATH',
        help='Path to seller public key (PEM or Solana base58). If provided, used instead of deriving from --seller-sk'
    )
    args = parser.parse_args(argv)

    buyer_pk: Optional[Union[str, Any]] = None
    if args.encrypt_for in ('buyer', 'both'):
        buyer_pk_path = args.buyer_pk
        try:
            raw = open(buyer_pk_path, 'rb').read()
        except Exception as e:
            logging.error(f"❌ Unable to read buyer public key file '{buyer_pk_path}': {e}")
            return

        if is_solana_base58_key(raw):
            buyer_pk = raw.decode('utf-8').strip()
        else:
            try:
                buyer_pk = load_rsa_public_key(buyer_pk_path)
            except Exception as e:
                logging.error(f"❌ Error loading buyer public key: {e}")
                return

    seller_pk: Optional[Union[str, Any]] = None
    if args.encrypt_for in ('seller', 'both'):
        # Decide which public-key path to use: explicit CLI arg wins, otherwise default
        seller_pk_path = args.seller_pk if args.seller_pk else SELLER_PUBLIC_KEY_PATH

        # If a public key file already exists, load and use it.
        if os.path.exists(seller_pk_path):
            try:
                raw = open(seller_pk_path, 'rb').read()
                if is_solana_base58_key(raw):
                    seller_pk = raw.decode('utf-8').strip()
                else:
                    seller_pk = load_rsa_public_key(seller_pk_path)
            except Exception as e:
                logging.error(f"❌ Error loading seller public key from {seller_pk_path}: {e}")
                return
        else:
            # Derive public key from seller private key and save it to the chosen path.
            try:
                derived = derive_rsa_public_from_private(args.seller_sk)
            except Exception as e:
                logging.error(f"❌ Error deriving seller public key from {args.seller_sk}: {e}")
                return

            # Persist the derived public key to file in a best-effort format:
            # - If it's a Solana/base58 string, write text
            # - If it's raw bytes, write bytes
            # - Otherwise try to serialize as PEM using rsa.PublicKey.save_pkcs1 if available
            try:
                if isinstance(derived, str):
                    # Solana-style base58 string
                    with open(seller_pk_path, 'w', encoding='utf-8') as f:
                        f.write(derived)
                    seller_pk = derived
                elif isinstance(derived, (bytes, bytearray)):
                    with open(seller_pk_path, 'wb') as f:
                        f.write(bytes(derived))
                    seller_pk = bytes(derived)
                else:
                    # Try to call a save method on the object (rsa.PublicKey has save_pkcs1)
                    try:
                        if hasattr(derived, 'save_pkcs1'):
                            pem = derived.save_pkcs1()  # type: ignore
                        else:
                            # fallback: try rsa module helper
                            _rsa = importlib.import_module('rsa')
                            pem = getattr(_rsa.PublicKey, 'save_pkcs1')(derived)  # type: ignore
                        with open(seller_pk_path, 'wb') as f:
                            f.write(pem)
                        seller_pk = derived
                    except Exception:
                        # As a last resort, try to write numeric components as JSON [n,e]
                        try:
                            n = getattr(derived, 'n')
                            e = getattr(derived, 'e')
                            with open(seller_pk_path, 'w', encoding='utf-8') as f:
                                f.write(json.dumps([int(n), int(e)]))
                            seller_pk = derived
                        except Exception as e:
                            logging.error(f"❌ Unable to serialize derived public key to {seller_pk_path}: {e}")
                            return
            except Exception as e:
                logging.error(f"❌ Failed saving derived seller public key to {seller_pk_path}: {e}")
                return

    aes_key = generate_aes_key()
    encrypt_file_with_aes(DATASET_PATH, ENCRYPTED_FILE_PATH, aes_key)

    requested_labels: List[str] = []
    if args.encrypt_for in ('buyer', 'both'):
        requested_labels.append('buyer')
    if args.encrypt_for in ('seller', 'both'):
        requested_labels.append('seller')

    solana_pk_map: Dict[str, Union[str, bytes]] = {}
    rsa_pk_map: Dict[str, Any] = {}
    for label in requested_labels:
        pk_value = buyer_pk if label == 'buyer' else seller_pk
        if pk_value is None:
            logging.error(f"❌ {label.capitalize()} public key not available; cannot encrypt AES key")
            return
        if isinstance(pk_value, str):
            solana_pk_map[label] = pk_value
        elif isinstance(pk_value, (bytes, bytearray, memoryview)) and len(pk_value) == 32:
            solana_pk_map[label] = bytes(pk_value)
        else:
            rsa_pk_map[label] = pk_value

    out_paths: Dict[str, str] = {}
    aad_context = os.path.basename(ENCRYPTED_FILE_PATH).encode('utf-8')

    # Solana recipients via multi-recipient hybrid encryption
    if solana_pk_map:
        try:
            if len(solana_pk_map) > 1:
                solana_entries = build_solana_recipient_entries(solana_pk_map)
                solana_envelope = encrypt_multi(
                    aes_key,
                    solana_entries,
                    info=MULTI_RECIPIENT_INFO,
                    aad_extra=aad_context,
                )
                with open(ENCRYPTED_AES_KEYS_COMBINED_PATH, 'w', encoding='utf-8') as f:
                    f.write(solana_envelope)
                out_paths['solana_multi_recipient'] = ENCRYPTED_AES_KEYS_COMBINED_PATH
                logging.info(
                    f"✅ Encrypted AES key for Solana recipients using multi-recipient envelope: {ENCRYPTED_AES_KEYS_COMBINED_PATH}"
                )
            else:
                label, value = next(iter(solana_pk_map.items()))
                solana_entry = build_solana_recipient_entries({label: value})
                solana_envelope = encrypt_multi(
                    aes_key,
                    solana_entry,
                    info=MULTI_RECIPIENT_INFO,
                    aad_extra=aad_context,
                )
                target_path = (
                    ENCRYPTED_AES_KEY_BUYER_ENVELOPE_PATH
                    if label == 'buyer'
                    else ENCRYPTED_AES_KEY_SELLER_ENVELOPE_PATH
                )
                with open(target_path, 'w', encoding='utf-8') as f:
                    f.write(solana_envelope)
                out_paths[f"{label}_solana_envelope"] = target_path
                logging.info(
                    f"✅ Encrypted AES key for {label} using Solana multi-recipient envelope: {target_path}"
                )
        except Exception as exc:
            logging.error(f"❌ Failed to create multi-recipient envelope for Solana recipients: {exc}")
            return

    # RSA recipients (legacy path)
    rsa_labels = set(rsa_pk_map.keys())
    if rsa_labels:
        if rsa_labels == {'buyer', 'seller'} and args.encrypt_for == 'both' and not solana_pk_map:
            try:
                seller_cipher = encrypt_for_recipient(aes_key, rsa_pk_map['seller'])
                buyer_cipher = encrypt_for_recipient(aes_key, rsa_pk_map['buyer'], is_re_encryption=True)
            except Exception as exc:
                logging.error(f"❌ Failed to encrypt AES key for RSA recipients: {exc}")
                return
            combined_json = make_encrypted_keys_json_from_bytes({'seller': seller_cipher, 'buyer': buyer_cipher})
            try:
                with open(ENCRYPTED_AES_KEYS_COMBINED_PATH, 'w', encoding='utf-8') as f:
                    f.write(combined_json)
            except Exception as exc:
                logging.error(f"❌ Failed to write combined RSA encrypted keys to {ENCRYPTED_AES_KEYS_COMBINED_PATH}: {exc}")
                return
            out_paths['rsa_combined'] = ENCRYPTED_AES_KEYS_COMBINED_PATH
            logging.info(
                f"✅ Encrypted AES key for buyer and seller using RSA proxy re-encryption: {ENCRYPTED_AES_KEYS_COMBINED_PATH}"
            )
        else:
            for label, pk_value in rsa_pk_map.items():
                try:
                    cipher = encrypt_for_recipient(aes_key, pk_value)
                except Exception as exc:
                    logging.error(f"❌ Failed to encrypt AES key for {label}: {exc}")
                    return
                target_path = ENCRYPTED_AES_KEY_BUYER_PATH if label == 'buyer' else ENCRYPTED_AES_KEY_SELLER_PATH
                try:
                    with open(target_path, 'wb') as f:
                        f.write(cipher)
                except Exception as exc:
                    logging.error(f"❌ Failed to write encrypted key for {label} to {target_path}: {exc}")
                    return
                out_paths[f"{label}_rsa"] = target_path
                logging.info(f"✅ Encrypted AES key for {label} using RSA and saved to {target_path}")

    ipfs_cid = upload_to_ipfs(ENCRYPTED_FILE_PATH)
    azure_url = upload_to_azure(ENCRYPTED_FILE_PATH)

    logging.info("\n🔐 Re-Encryption & Upload Summary:")
    logging.info(f"• Encrypted file: {ENCRYPTED_FILE_PATH}")
    logging.info(f"• IPFS CID: {ipfs_cid}")
    logging.info(f"• Azure URL: {azure_url}")
    # Also print SHA-256 hash of the encrypted file for verification
    file_hash = compute_file_sha256(ENCRYPTED_FILE_PATH)
    if file_hash:
        logging.info(f"• Encrypted file SHA-256: {file_hash}")

    logging.info("\n📋 Encrypted AES Key(s) as JSON:")
    logging.info(make_encrypted_keys_json(out_paths))


def main_decrypt(argv: Optional[List[str]] = None) -> None:
    """Main function for decrypting files."""
    # Setup logging first
    setup_logging()
    
    # Log the command line invocation
    if argv is None:
        cmd_line = ' '.join(sys.argv)
    else:
        cmd_line = f"python {sys.argv[0]} {' '.join(argv)}"
    
    logging.info("="*80)
    logging.info(f"Script invoked: {cmd_line}")
    logging.info(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logging.info("="*80)
    
    parser = argparse.ArgumentParser(
        description='Decrypt dataset using encrypted AES key and recipient private key',
        epilog='Examples:\n'
               '  # Decrypt as seller using JSON key file\n'
               '  python data_enc_util.py decrypt --recipient seller \\\n'
               '    --private-key seller_sk.pem \\\n'
               '    --encrypted-key encrypted_aes_keys.json \\\n'
               '    --output decrypted_dataset.csv\n'
               '\n'
               '  # Decrypt as buyer using binary key file\n'
               '  python data_enc_util.py decrypt --recipient buyer \\\n'
               '    --private-key buyer_sk.pem \\\n'
               '    --encrypted-key encrypted_aes_key_buyer.bin \\\n'
               '    --encrypted-file test_dataset_encrypted.bin \\\n'
               '    --output decrypted_dataset.csv',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        '--recipient', 
        choices=['buyer', 'seller'], 
        required=True,
        help='Who is decrypting (buyer or seller) - required'
    )
    parser.add_argument(
        '--private-key', 
        required=True,
        metavar='PATH',
        help='Path to recipient private key in PEM, Solana base58, or JSON array format - required'
    )
    parser.add_argument(
        '--encrypted-file', 
        default=ENCRYPTED_FILE_PATH,
        metavar='PATH',
        help=f'Path to encrypted dataset file (default: {ENCRYPTED_FILE_PATH})'
    )
    parser.add_argument(
        '--encrypted-key', 
        required=True,
        metavar='PATH',
        help='Path to encrypted AES key file (.bin) or JSON file (.json) with encrypted keys - required'
    )
    parser.add_argument(
        '--output', 
        required=True,
        metavar='PATH',
        help='Path to save decrypted file - required'
    )
    args = parser.parse_args(argv)
    
    # Load the private key
    try:
        private_key = load_rsa_private_key(args.private_key)
        logging.info(f"✅ Loaded private key from {args.private_key}")
    except Exception as e:
        logging.error(f"❌ Failed to load private key from {args.private_key}: {e}")
        return
    
    # Determine if this is a Solana key
    is_solana = False
    if isinstance(private_key, tuple):
        # It's a Solana key (SigningKey, full_key) tuple
        is_solana = True
    else:
        try:
            _nacl_signing = importlib.import_module('nacl.signing')
            SigningKeyClass = getattr(_nacl_signing, 'SigningKey')
            # Check if private_key is an instance of SigningKey
            is_solana = isinstance(private_key, SigningKeyClass)
        except Exception:
            pass
    
    logging.info(f"Key type detected: {'Solana/Ed25519' if is_solana else 'RSA'}")
    
    # Load the encrypted AES key
    encrypted_aes_key: Optional[bytes] = None
    aes_key: Optional[bytes] = None
    
    # Check if the encrypted key file is a JSON file
    if args.encrypted_key.endswith('.json'):
        try:
            with open(args.encrypted_key, 'r', encoding='utf-8') as f:
                raw_json = f.read()
            data = json.loads(raw_json)
        except Exception as e:
            logging.error(f"❌ Failed to load encrypted key from JSON {args.encrypted_key}: {e}")
            return
        
        if is_multi_recipient_envelope(data):
            if not is_solana:
                logging.error("❌ Multi-recipient envelope requires a Solana/Ed25519 private key")
                return
            try:
                x25519_sk = solana_private_to_x25519_private_bytes(private_key)
                aes_key = decrypt_multi_envelope(raw_json, x25519_sk, expected_kid=args.recipient)
                logging.info("✅ Decrypted AES key from multi-recipient envelope")
            except Exception as e:
                logging.error(f"❌ Failed to decrypt multi-recipient envelope: {e}")
                return
        elif 'recipients' in data and args.recipient in data['recipients']:
            recipient_data = data['recipients'][args.recipient]
            if 'error' in recipient_data:
                logging.error(f"❌ Encrypted key for {args.recipient} has error: {recipient_data['error']}")
                return

            encrypted_key_b64 = recipient_data.get('encryptedKey')
            if encrypted_key_b64:
                encrypted_aes_key = base64.b64decode(encrypted_key_b64)
                logging.info(f"✅ Loaded encrypted AES key for {args.recipient} from JSON")
            else:
                logging.error(f"❌ No encryptedKey field found for {args.recipient}")
                return
        else:
            logging.error(f"❌ Unrecognized JSON encrypted key format: {args.encrypted_key}")
            return
    else:
        # Load as binary file
        try:
            with open(args.encrypted_key, 'rb') as f:
                encrypted_aes_key = f.read()
            logging.info(f"✅ Loaded encrypted AES key from {args.encrypted_key}")
        except Exception as e:
            logging.error(f"❌ Failed to load encrypted key from {args.encrypted_key}: {e}")
            return
    
    # Decrypt the AES key
    if aes_key is None:
        if encrypted_aes_key is None:
            logging.error("❌ Encrypted AES key payload not loaded; cannot proceed with decryption")
            return
        try:
            aes_key = decrypt_for_recipient(encrypted_aes_key, private_key, is_solana)
            logging.info("✅ Decrypted AES key successfully")
        except NotImplementedError as e:
            logging.error(f"❌ {e}")
            return
        except Exception as e:
            logging.error(f"❌ Failed to decrypt AES key: {e}")
            logging.error(f"\nPossible causes:")
            logging.error(f"  1. Wrong private key - Make sure you're using the {args.recipient}'s private key")
            logging.error(f"  2. Key format mismatch - The encrypted key may have been encrypted with a different key type")
            logging.error(f"  3. Corrupted encrypted key file")
            logging.error(f"\nYou specified --recipient {args.recipient}, so you need the {args.recipient}'s private key.")
            return
    
    # Decrypt the file
    try:
        decrypt_file_with_aes(args.encrypted_file, args.output, aes_key)
        logging.info(f"✅ Successfully decrypted file to {args.output}")
    except Exception as e:
        logging.error(f"❌ Failed to decrypt file: {e}")
        return
    
    # Compute and display SHA-256 of decrypted file
    file_hash = compute_file_sha256(args.output)
    if file_hash:
        logging.info(f"• Decrypted file SHA-256: {file_hash}")
    
    logging.info("\n🔓 Decryption Summary:")
    logging.info(f"• Encrypted file: {args.encrypted_file}")
    logging.info(f"• Decrypted file: {args.output}")
    logging.info(f"• Recipient: {args.recipient}")


if __name__ == '__main__':
    # Check if the first argument is 'decrypt' to determine mode
    if len(sys.argv) > 1 and sys.argv[1] == 'decrypt':
        # Remove 'decrypt' from argv and call decrypt function
        main_decrypt(sys.argv[2:])
    elif len(sys.argv) > 1 and sys.argv[1] in ['-h', '--help']:
        # Show general help
        print("Data Encryption/Decryption Utility")
        print("="*80)
        print()
        print("MODES:")
        print("  Encryption (default):  python data_enc_util.py [options]")
        print("  Decryption:           python data_enc_util.py decrypt [options]")
        print()
        print("For mode-specific help:")
        print("  python data_enc_util.py --help          # Encryption help")
        print("  python data_enc_util.py decrypt --help  # Decryption help")
        print()
        print("="*80)
        print()
        # Show encryption help by default
        main(['--help'])
    else:
        # Default to encryption mode
        main()
