# multi_recipient_hpke_like.py
# Requires: pip install cryptography

import base64
import json
import secrets
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Union, cast
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from nacl import signing

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58decode(s: str) -> bytes:
    """
    Decode a base58 string (Bitcoin alphabet) to bytes.
    """
    num = 0
    for ch in s.strip():
        num *= 58
        try:
            num += BASE58_ALPHABET.index(ch)
        except ValueError as exc:
            raise ValueError(f"Invalid Base58 character {ch!r}") from exc

    if num == 0:
        decoded = b""
    else:
        decoded = num.to_bytes((num.bit_length() + 7) // 8, "big")

    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + decoded

# ---------- Helpers (encoding / KDF) ----------

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def hkdf_sha256(ikm: bytes, salt: Optional[bytes], info: bytes, length: int = 32) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=length, salt=salt, info=info
    ).derive(ikm)

# ---------- Keys ----------

def generate_x25519_keypair() -> Tuple[bytes, bytes]:
    """
    Returns (sk_bytes, pk_bytes)
    """
    sk = X25519PrivateKey.generate()
    pk = sk.public_key()
    return (sk.private_bytes_raw(), pk.public_bytes_raw())

def load_sk(sk_bytes: bytes) -> X25519PrivateKey:
    return X25519PrivateKey.from_private_bytes(sk_bytes)

def load_pk(pk_bytes: bytes) -> X25519PublicKey:
    return X25519PublicKey.from_public_bytes(pk_bytes)

# ---------- Core: Multi-Recipient Encrypt / Decrypt ----------

def encrypt_multi(
    m: bytes,
    recipients: Sequence[Mapping[str, Union[str, bytes]]],
    *,
    aead_alg: str = "AESGCM-256",
    kem: str = "X25519-HKDF-SHA256",
    info: bytes = b"ZDatar multi-recipient envelope v1",
    kid_field: str = "kid",
    aad_extra: Optional[bytes] = None,
) -> str:
    """
    recipients: list of { "kid": str, "pk": bytes } entries (pk is raw 32B X25519)
    Returns: JSON string envelope
    """
    # 1) Data key + nonce for the big ciphertext (DEM)
    K_data = secrets.token_bytes(32)  # 256-bit data-encryption key
    N_data = secrets.token_bytes(12)  # AES-GCM nonce

    # 2) For each recipient, derive a key-wrap key via ECDH + HKDF and wrap K_data
    recipients_entries: List[Dict[str, str]] = []
    for r in recipients:
        kid_value = r.get(kid_field)
        if not isinstance(kid_value, str):
            raise TypeError(f"Recipient field '{kid_field}' must be a string, got {type(kid_value)!r}")
        kid = kid_value

        pk_value = r.get("pk")
        if not isinstance(pk_value, (bytes, bytearray)):
            raise TypeError("Recipient 'pk' must be bytes")
        pk_r = load_pk(bytes(pk_value))
        eph_sk = X25519PrivateKey.generate()
        eph_pk = eph_sk.public_key()

        # ECDH
        shared = eph_sk.exchange(pk_r)  # 32 bytes

        # Context binds parameters to the wrap key derivation
        context: bytes = (
            b"kw-context|" + info +
            b"|aead=" + aead_alg.encode() +
            b"|kem=" + kem.encode() +
            b"|kid=" + kid.encode()
        )

        K_wrap = hkdf_sha256(shared, salt=None, info=context, length=32)

        # Wrap K_data with AES-GCM under K_wrap
        aes_kw = AESGCM(K_wrap)
        N_kw = secrets.token_bytes(12)
        # Authenticate kid & eph_pub to bind header
        aad_kw = b"kw-aad|" + kid.encode() + b"|" + eph_pk.public_bytes_raw()
        KW = aes_kw.encrypt(N_kw, K_data, aad_kw)

        recipients_entries.append({
            kid_field: kid,
            "kem": kem,
            "eph_pub": b64e(eph_pk.public_bytes_raw()),
            "nonce": b64e(N_kw),
            "kw": b64e(KW),
        })

    # 3) Build header (sans ciphertext) and use it as AAD for the main AEAD
    header: Dict[str, Union[str, List[Dict[str, str]]]] = {
        "ver": "1",
        "aead": aead_alg,
        "nonce": b64e(N_data),
        "recipients": recipients_entries,
    }
    # Optional external AAD
    if aad_extra:
        header["aad_ext"] = b64e(aad_extra)

    aad_header = json.dumps(header, separators=(",", ":"), sort_keys=True).encode()

    # 4) Encrypt the message once with K_data
    aes = AESGCM(K_data)
    C = aes.encrypt(N_data, m, aad_header)

    # 5) Final envelope
    header["ciphertext"] = b64e(C)
    return json.dumps(header, separators=(",", ":"), sort_keys=True)


def decrypt_any(
    envelope_json: str,
    sk_bytes: bytes,
    *,
    info: bytes = b"ZDatar multi-recipient envelope v1",
    kid: Optional[str] = None,           # optional fast-path if you know your kid
) -> bytes:
    """
    Try to decrypt using sk_bytes. If 'kid' is provided, we attempt that recipient first.
    Returns: plaintext m
    Raises: Exception if no recipient entry matches / auth fails
    """
    env = cast(Dict[str, Any], json.loads(envelope_json))
    N_data = b64d(cast(str, env["nonce"]))
    C = b64d(cast(str, env["ciphertext"]))

    recipients_list = cast(Sequence[Dict[str, Any]], env["recipients"])
    # Preferred order: try the hinted kid first (if any), then all
    if kid is None:
        order = list(recipients_list)  # no preference
    else:
        order = [r for r in recipients_list if r.get("kid") == kid]

    # Rebuild AAD for the main ciphertext
    header_sans_ct: Dict[str, Any] = dict(env)
    del header_sans_ct["ciphertext"]
    aad_header = json.dumps(header_sans_ct, separators=(",", ":"), sort_keys=True).encode()

    sk = load_sk(sk_bytes)

    # We'll iterate recipients until one unwrap succeeds
    last_err = None
    for r in order:
        try:
            eph_pub_b64 = cast(str, r["eph_pub"])
            nonce_b64 = cast(str, r["nonce"])
            kw_b64 = cast(str, r["kw"])
            kid_r = cast(str, r.get("kid", ""))

            eph_pub = load_pk(b64d(eph_pub_b64))
            N_kw = b64d(nonce_b64)
            KW = b64d(kw_b64)

            # ECDH (recipient side): shared = sk * eph_pub
            shared = sk.exchange(eph_pub)

            context = (
                b"kw-context|" + info +
                b"|aead=" + env["aead"].encode() +
                b"|kem=" + r.get("kem", "X25519-HKDF-SHA256").encode() +
                b"|kid=" + kid_r.encode()
            )
            K_wrap = hkdf_sha256(shared, salt=None, info=context, length=32)

            aad_kw = b"kw-aad|" + kid_r.encode() + b"|" + eph_pub.public_bytes_raw()
            K_data = AESGCM(K_wrap).decrypt(N_kw, KW, aad_kw)

            # If unwrap worked, decrypt the big ciphertext
            m = AESGCM(K_data).decrypt(N_data, C, aad_header)
            return m
        except Exception as e:
            last_err = e
            continue

    # If we get here, all unwraps failed (wrong key or tampered header)
    raise Exception(f"Unable to decrypt for provided key. Last error: {last_err!r}")

# ---------- Encryption adaptation from Ed25519 (Solana Enc Algo) to X25519 ----------

def load_solana_private_key(path: str) -> bytes:
    """
    Load a Solana private key from either JSON array-of-ints or base58 text file.
    """
    with open(path, "r", encoding="utf-8") as f:
        content = f.read().strip()

    if not content:
        raise ValueError(f"Solana key file {path} is empty")

    # Common Solana CLI format: JSON array of ints.
    try:
        parsed = json.loads(content)
        if isinstance(parsed, list):
            parsed_items = cast(Sequence[object], parsed)
            int_values: List[int] = []
            for entry in parsed_items:
                if not isinstance(entry, int):
                    raise ValueError("Solana private key JSON list must contain only integers")
                int_values.append(int(entry))
            key_bytes = bytes(int_values)
        elif isinstance(parsed, str):
            key_bytes = b58decode(parsed)
        else:
            raise ValueError
    except json.JSONDecodeError:
        # Fallback: assume raw base58-encoded string.
        key_bytes = b58decode(content)
    except ValueError:
        raise ValueError(f"Unsupported Solana key format in {path}")

    if len(key_bytes) not in (32, 64):
        raise ValueError(
            f"Solana private key in {path} must be 32 or 64 bytes, got {len(key_bytes)}"
        )
    return key_bytes

def solana_to_x25519_keypair(solana_privkey_bytes: bytes):
    """
    Convert a 64-byte Ed25519 private key (as used in Solana) to an X25519 key pair.
    Solana keypair file is usually 64 bytes: first 32 are seed, next 32 are pubkey.
    """
    if len(solana_privkey_bytes) == 64:
        seed = solana_privkey_bytes[:32]
    elif len(solana_privkey_bytes) == 32:
        seed = solana_privkey_bytes
    else:
        raise ValueError("Solana private key must be 32 or 64 bytes")

    ed_sk = signing.SigningKey(seed)
    ed_pk = ed_sk.verify_key
    x_sk = ed_sk.to_curve25519_private_key()
    x_pk = ed_pk.to_curve25519_public_key()
    return x_sk.encode(), x_pk.encode()

def solana_pub_to_x25519_pub(solana_pubkey_bytes: bytes):
    """
    Convert a 32-byte Ed25519 public key (Solana) to X25519 public key.
    """
    ed_pk = signing.VerifyKey(solana_pubkey_bytes)
    x_pk = ed_pk.to_curve25519_public_key()
    return x_pk.encode()

# ---------- Demo (run directly) ----------

if __name__ == "__main__":
    # Solana keypair (64 bytes) -> X25519 keypair (32 bytes)
    solana_priv_a = load_solana_private_key("/home/azureuser/zdatar/data_enc_utils/seller_1_sk.pem")
    solana_pub_a = solana_priv_a[32:]        # last 32 bytes are public key
    # Convert to X25519 keypair
    SKa, PKa = solana_to_x25519_keypair(solana_priv_a)

    solana_priv_b = load_solana_private_key("/home/azureuser/zdatar/data_enc_utils/buyer_0_sk.pem")
    solana_pub_b = solana_priv_b[32:]        # last 32 bytes are public key
    # Convert to X25519 keypair
    SKb, PKb = solana_to_x25519_keypair(solana_priv_b)

    # Generate two recipients: A and B
    # SKa, PKa = generate_x25519_keypair()
    # SKb, PKb = generate_x25519_keypair()

    # Message
    m = b"hello ZDatar \xf0\x9f\x92\xbb"

    # Build recipients list
    recipients: List[Dict[str, Union[str, bytes]]] = [
        {"kid": "A", "pk": PKa},
        {"kid": "B", "pk": PKb},
    ]

    # Encrypt once for both A and B
    envelope = encrypt_multi(m, recipients)

    print("ENVELOPE JSON:\n", envelope, "\n")

    # Decrypt as A
    mA = decrypt_any(envelope, SKa, kid="A")
    print("Decrypted by A:", mA)

    # Decrypt as B
    mB = decrypt_any(envelope, SKb, kid="B")
    print("Decrypted by B:", mB)
