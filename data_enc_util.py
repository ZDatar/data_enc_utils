#!/usr/bin/env python3
import os
import base64
import hashlib
import json
import mimetypes
import argparse
from typing import Any, Dict, Optional, Union, List, Mapping, Sequence, cast

import importlib
import requests
from dotenv import load_dotenv
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
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

# === CONFIG ===
SELLER_PRIVATE_KEY_PATH = "/home/azureuser/zdatar/test-script/seller_1_sk.pem"
BUYER_PUBLIC_KEY_PATH = "/home/azureuser/zdatar/test-script/buyer_0_pk.pem"
DATASET_PATH = "/home/azureuser/zdatar/test-script/test_dataset.csv"
ENCRYPTED_FILE_PATH = "/home/azureuser/zdatar/test-script/test_dataset_encrypted.bin"
ENCRYPTED_AES_KEY_BUYER_PATH = "/home/azureuser/zdatar/test-script/encrypted_aes_key_buyer.bin"
ENCRYPTED_AES_KEY_SELLER_PATH = "/home/azureuser/zdatar/test-script/encrypted_aes_key_seller.bin"

load_dotenv()
AZURE_CONNECTION_STRING = os.getenv("AZURE_CONNECTION_STRING")
AZURE_CONTAINER_NAME = "zdatar-data"


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
    print(f"✅ Encrypted file saved to {output_path}")
    return iv


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


def encrypt_aes_key_with_solana(aes_key: bytes, sol_base58_str: str) -> bytes:
    _base58 = importlib.import_module('base58')  # type: ignore
    pub_raw = getattr(_base58, 'b58decode')(sol_base58_str)  # type: ignore
    # ensure bytes for the NaCl API
    if not isinstance(pub_raw, (bytes, bytearray)):
        raise ValueError("Invalid Solana public key (not decodable to bytes)")
    # Import PyNaCl dynamically; raise informative error if unavailable at runtime
    try:
        _nacl_public = importlib.import_module('nacl.public')  # type: ignore
    except Exception as e:
        raise RuntimeError('PyNaCl (nacl) is required for Solana/Ed25519 operations: ' + str(e))
    SealedBox = getattr(_nacl_public, 'SealedBox')  # type: ignore
    NaClPublicKey = getattr(_nacl_public, 'PublicKey')  # type: ignore
    box = SealedBox(NaClPublicKey(bytes(pub_raw)))  # type: ignore
    return cast(bytes, box.encrypt(aes_key))  # type: ignore


def encrypt_for_recipient(aes_key: bytes, recipient_pk: Union[str, Any]) -> bytes:
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
        print("⚠️ AZURE_CONNECTION_STRING not set; skipped Azure upload.")
        return None
    _blob = importlib.import_module('azure.storage.blob')
    BlobServiceClient = getattr(_blob, 'BlobServiceClient')
    blob_service = BlobServiceClient.from_connection_string(AZURE_CONNECTION_STRING)  # type: ignore
    blob_client = blob_service.get_blob_client(container=AZURE_CONTAINER_NAME, blob=os.path.basename(file_path))  # type: ignore
    with open(file_path, "rb") as data:
        blob_client.upload_blob(data, overwrite=True)  # type: ignore
    url = f"https://{getattr(blob_service, 'account_name')}.blob.core.windows.net/{AZURE_CONTAINER_NAME}/{os.path.basename(file_path)}"
    print(f"✅ Uploaded to Azure Blob: {url}")
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
        print(f"✅ Uploaded to IPFS: {cid}")
        return cid
    except Exception as e:
        print(f"⚠️ ipfshttpclient failed: {e}")

    try:
        url = 'http://127.0.0.1:5001/api/v0/add'
        with open(file_path, 'rb') as f:
            files = {'file': (os.path.basename(file_path), f, mimetypes.guess_type(file_path)[0] or 'application/octet-stream')}
            resp = requests.post(url, files=files, timeout=10)
        resp.raise_for_status()
        last_line = resp.text.strip().split('\n')[-1]
        obj = json.loads(last_line)
        cid = obj.get('Hash')
        print(f"✅ Uploaded to IPFS (HTTP API): {cid}")
        return cid
    except Exception as e:
        print(f"⚠️ HTTP IPFS upload fallback failed: {e}")
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


def main(argv: Optional[List[str]] = None) -> None:
    parser = argparse.ArgumentParser(description='Encrypt dataset and AES key for recipients')
    parser.add_argument('--encrypt-for', choices=['buyer', 'seller', 'both'], default='both', help='Who to encrypt the AES key for')
    parser.add_argument('--buyer-pk', default=BUYER_PUBLIC_KEY_PATH, help='Path to buyer public key (PEM or Solana base58)')
    parser.add_argument('--seller-sk', default=SELLER_PRIVATE_KEY_PATH, help='Path to seller private key (PEM) to derive seller public key')
    parser.add_argument('--seller-pk', default=None, help='Path to seller public key (PEM). If provided, used instead of deriving from seller-sk')
    args = parser.parse_args(argv)

    buyer_pk: Optional[Union[str, Any]] = None
    if args.encrypt_for in ('buyer', 'both'):
        buyer_pk_path = args.buyer_pk
        try:
            raw = open(buyer_pk_path, 'rb').read()
        except Exception as e:
            print(f"❌ Unable to read buyer public key file '{buyer_pk_path}': {e}")
            return

        if is_solana_base58_key(raw):
            buyer_pk = raw.decode('utf-8').strip()
        else:
            try:
                buyer_pk = load_rsa_public_key(buyer_pk_path)
            except Exception as e:
                print(f"❌ Error loading buyer public key: {e}")
                return

    seller_pk: Optional[Union[str, Any]] = None
    if args.encrypt_for in ('seller', 'both'):
        # Prefer explicit seller public key path if provided
        if args.seller_pk:
            try:
                raw = open(args.seller_pk, 'rb').read()
                if is_solana_base58_key(raw):
                    seller_pk = raw.decode('utf-8').strip()
                else:
                    seller_pk = load_rsa_public_key(args.seller_pk)
            except Exception as e:
                print(f"❌ Error loading seller public key from {args.seller_pk}: {e}")
                return
        else:
            try:
                seller_pk = derive_rsa_public_from_private(args.seller_sk)
            except Exception as e:
                print(f"❌ Error deriving seller public key from {args.seller_sk}: {e}")
                return

    aes_key = generate_aes_key()
    encrypt_file_with_aes(DATASET_PATH, ENCRYPTED_FILE_PATH, aes_key)

    out_paths: Dict[str, str] = {}
    if args.encrypt_for in ('buyer', 'both'):
        if buyer_pk is None:
            print("❌ Buyer public key not loaded; cannot encrypt AES key for buyer")
            return
        c = encrypt_for_recipient(aes_key, buyer_pk)
        with open(ENCRYPTED_AES_KEY_BUYER_PATH, 'wb') as f:
            f.write(c)
        out_paths['buyer'] = ENCRYPTED_AES_KEY_BUYER_PATH

    if args.encrypt_for in ('seller', 'both'):
        if seller_pk is None:
            print("❌ Seller public key not available; cannot encrypt AES key for seller")
            return
        c = encrypt_for_recipient(aes_key, seller_pk)
        with open(ENCRYPTED_AES_KEY_SELLER_PATH, 'wb') as f:
            f.write(c)
        out_paths['seller'] = ENCRYPTED_AES_KEY_SELLER_PATH

    ipfs_cid = upload_to_ipfs(ENCRYPTED_FILE_PATH)
    azure_url = upload_to_azure(ENCRYPTED_FILE_PATH)

    print("\n🔐 Re-Encryption & Upload Summary:")
    print(f"• Encrypted file: {ENCRYPTED_FILE_PATH}")
    print(f"• IPFS CID: {ipfs_cid}")
    print(f"• Azure URL: {azure_url}")

    print("\n📋 Encrypted AES Key(s) as JSON:")
    print(make_encrypted_keys_json(out_paths))


if __name__ == '__main__':
    main()