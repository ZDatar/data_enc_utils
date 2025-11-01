#!/usr/bin/env python3
"""
ZDatar Dataset Decryption Script

Decrypts datasets encrypted with AES-256-GCM multi-recipient encryption.

Usage:
    python decrypt_dataset.py \\
        --encrypted-file encrypted_dataset.csv.enc \\
        --encrypted-key "base64_encoded_envelope" \\
        --recipient-pubkey "your_solana_public_key_base58" \\
        --recipient-private-key "your_solana_private_key_base58" \\
        --output decrypted_dataset.csv \\
        --format csv

Requirements:
    pip install cryptography base58

Note:
    This script uses deterministic key derivation (double SHA-256) instead of X25519 ECDH.
    Updated to match mobile app implementation that avoids HKDF SecretKey extraction issues.
"""

import argparse
import base64
import json
import sys
from typing import Dict, Any
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import x25519
import hashlib
import base58


class DatasetDecryptor:
    """Decrypt ZDatar datasets encrypted with AES-256-GCM"""
    
    KDF_INFO = b'zdatar:ck-wrap'
    
    def __init__(self, recipient_pubkey: str, recipient_private_key: str):
        """
        Initialize decryptor.
        
        Args:
            recipient_pubkey: Recipient's Solana public key (base58-encoded)
            recipient_private_key: Recipient's Solana private key (base58-encoded, 64 bytes)
        """
        self.recipient_pubkey = recipient_pubkey
        
        # Decode Ed25519 public key from base58 (32 bytes)
        # This is the SAME public key the mobile app uses for encryption
        self.ed25519_public_key = base58.b58decode(recipient_pubkey)
        
        if len(self.ed25519_public_key) != 32:
            raise ValueError(f"Invalid public key length: {len(self.ed25519_public_key)} (expected 32 bytes)")
        
        # Decode private key (we don't actually need it for this deterministic derivation)
        # But we validate it exists and is correct format
        private_key_full = base58.b58decode(recipient_private_key)
        if len(private_key_full) != 64:
            raise ValueError(f"Invalid private key length: {len(private_key_full)} (expected 64 bytes)")
        
        # Derive recipient X25519 PUBLIC KEY using deterministic seed-based derivation
        # This matches the mobile app: SHA-256(Ed25519 pubkey) → seed → X25519 keypair → public key
        # CRITICAL: Uses the PUBLIC KEY from --recipient-pubkey, NOT from the private key file
        self.recipient_x25519_pubkey = self._derive_x25519_from_ed25519(self.ed25519_public_key)
        
        print("🔑 Initialized decryptor with X25519 public key derived from Ed25519 public key")
        print(f"   Ed25519 public key (base58): {self.recipient_pubkey[:20]}...")
        print(f"   Ed25519 public key (hex): {self.ed25519_public_key.hex()[:40]}...")
        print(f"   X25519 public key (hex): {self.recipient_x25519_pubkey.hex()[:40]}...")
    
    @staticmethod
    def _derive_x25519_from_ed25519(ed25519_pubkey: bytes) -> bytes:
        """
        Derive X25519 PUBLIC KEY from Ed25519 public key using SHA-256 seed.
        
        This matches the mobile app's deterministic derivation approach:
        1. SHA-256(Ed25519 public key) → seed
        2. Generate X25519 keypair from seed
        3. Extract X25519 PUBLIC KEY
        
        Args:
            ed25519_pubkey: 32-byte Ed25519 public key
            
        Returns:
            32-byte X25519 public key (derived deterministically)
        """
        if len(ed25519_pubkey) != 32:
            raise ValueError(f"Ed25519 public key must be 32 bytes, got {len(ed25519_pubkey)}")
        
        # Step 1: Hash the Ed25519 public key to create seed
        # This matches: crypto_hash.sha256.convert(ed25519PublicKey)
        seed = hashlib.sha256(ed25519_pubkey).digest()
        print(f"   [DEBUG] Ed25519→X25519 seed (hex): {seed.hex()[:40]}...")
        
        # Step 2: Generate X25519 keypair from seed
        # This matches: x25519Algorithm.newKeyPairFromSeed(x25519Seed)
        x25519_private = x25519.X25519PrivateKey.from_private_bytes(seed)
        
        # Step 3: Extract X25519 public key
        # This matches: publicKey.bytes
        x25519_public = x25519_private.public_key()
        x25519_public_bytes = x25519_public.public_bytes_raw()
        print(f"   [DEBUG] X25519 public key derived (hex): {x25519_public_bytes.hex()[:40]}...")
        
        return x25519_public_bytes
        
    def decrypt_dataset(
        self,
        encrypted_data: bytes,
        encrypted_aes_key_base64: str
    ) -> bytes:
        """
        Decrypt dataset using encrypted AES key envelope.
        
        Args:
            encrypted_data: Encrypted dataset bytes
            encrypted_aes_key_base64: Base64-encoded encryption envelope
            
        Returns:
            Decrypted dataset bytes
        """
        print(f"🔓 Decrypting dataset for recipient: {self.recipient_pubkey[:20]}...")
        
        # Step 1: Decode base64 and parse encryption envelope
        envelope = self._parse_envelope(encrypted_aes_key_base64)
        
        # Step 2: Find matching key wrap for this recipient
        wrap = self._find_recipient_wrap(envelope)
        
        # Step 3: Derive wrapping key using HKDF
        wrapping_key = self._derive_wrapping_key(wrap)
        
        # Step 4: Decrypt wrapped content key
        content_key = self._decrypt_content_key(wrap, wrapping_key)
        
        # Step 5: Decrypt dataset with content key
        decrypted_data = self._decrypt_data(envelope, content_key)
        
        print(f"✅ Successfully decrypted {len(decrypted_data)} bytes")
        return decrypted_data
    
    def _parse_envelope(self, encrypted_aes_key_base64: str) -> Dict[str, Any]:
        """Parse and validate encryption envelope."""
        try:
            # Decode base64
            envelope_json_bytes = base64.b64decode(encrypted_aes_key_base64)
            envelope_json_str = envelope_json_bytes.decode('utf-8')
            
            # Parse JSON
            envelope = json.loads(envelope_json_str)
            
            # Validate structure
            required_fields = ['algo', 'cipher_iv', 'cipher_tag', 'ciphertext', 'wraps']
            for field in required_fields:
                if field not in envelope:
                    raise ValueError(f"Missing required field: {field}")
            
            if envelope['algo'] != 'AES-256-GCM':
                raise ValueError(f"Unsupported algorithm: {envelope['algo']}")
            
            print(f"📦 Parsed envelope with {len(envelope['wraps'])} key wraps")
            return envelope
            
        except Exception as e:
            raise ValueError(f"Failed to parse encryption envelope: {e}")
    
    def _find_recipient_wrap(self, envelope: Dict[str, Any]) -> Dict[str, Any]:
        """Find key wrap for this recipient."""
        for wrap in envelope['wraps']:
            if wrap['recipient_solana_pub58'] == self.recipient_pubkey:
                print("🔑 Found key wrap for recipient")
                return wrap
        
        raise ValueError(
            f"No key wrap found for recipient {self.recipient_pubkey}. "
            f"Available recipients: {[w['recipient_solana_pub58'][:20] + '...' for w in envelope['wraps']]}"
        )
    
    def _derive_wrapping_key(self, wrap: Dict[str, Any]) -> bytes:
        """
        Derive wrapping key using deterministic double SHA-256 hashing.
        
        Uses the same algorithm as mobile app:
        1. Get ephemeral secret from wrap
        2. Combine ephemeral secret + recipient X25519 key
        3. First SHA-256 hash
        4. Second SHA-256 hash with KDF info
        """
        # Get ephemeral secret from wrap (stored in eph_pub field)
        ephemeral_secret = base64.b64decode(wrap['eph_pub'])
        
        if len(ephemeral_secret) != 32:
            raise ValueError(f"Invalid ephemeral secret length: {len(ephemeral_secret)}")
        
        print("🔐 Deriving wrapping key using deterministic SHA-256...")
        print(f"   Ephemeral secret: {len(ephemeral_secret)} bytes")
        print(f"   Ephemeral secret (hex): {ephemeral_secret.hex()[:40]}...")
        print(f"   Recipient X25519 public key: {len(self.recipient_x25519_pubkey)} bytes")
        print(f"   Recipient X25519 pubkey (hex): {self.recipient_x25519_pubkey.hex()[:40]}...")
        
        # Step 1: Combine ephemeral secret and recipient X25519 public key
        combined_material = ephemeral_secret + self.recipient_x25519_pubkey
        print(f"   [DEBUG] Combined material length: {len(combined_material)} bytes")
        print(f"   [DEBUG] Combined material (hex): {combined_material.hex()[:80]}...")
        
        # Step 2: First SHA-256 hash
        first_hash = hashlib.sha256(combined_material).digest()
        print(f"   First hash: {len(first_hash)} bytes")
        print(f"   [DEBUG] First hash (hex): {first_hash.hex()}")
        
        # Step 3: Build KDF info string (same as mobile app)
        info_string = f"{self.KDF_INFO.decode('utf-8')}:{self.recipient_pubkey[:8]}"
        kdf_info = info_string.encode('utf-8')
        print(f"   Info: {info_string}")
        print(f"   [DEBUG] KDF info (hex): {kdf_info.hex()}")
        
        # Step 4: Second SHA-256 hash with KDF info
        final_material = first_hash + kdf_info
        print(f"   [DEBUG] Final material length: {len(final_material)} bytes")
        print(f"   [DEBUG] Final material (hex): {final_material.hex()[:80]}...")
        wrapping_key = hashlib.sha256(final_material).digest()
        
        print(f"✓ Wrapping key derived: {len(wrapping_key)} bytes")
        print(f"   [DEBUG] Wrapping key (hex): {wrapping_key.hex()}")
        return wrapping_key
    
    def _decrypt_content_key(self, wrap: Dict[str, Any], wrapping_key: bytes) -> bytes:
        """Decrypt wrapped content key using wrapping key."""
        # Get wrapped content key and nonce
        wrapped_ck = base64.b64decode(wrap['wrapped_ck'])
        wrap_nonce = base64.b64decode(wrap['wrap_nonce'])
        
        print("🔓 Decrypting content key...")
        print(f"   Wrapped key: {len(wrapped_ck)} bytes")
        print(f"   [DEBUG] Wrapped key (hex): {wrapped_ck.hex()}")
        print(f"   Nonce: {len(wrap_nonce)} bytes")
        print(f"   [DEBUG] Nonce (hex): {wrap_nonce.hex()}")
        print(f"   [DEBUG] Wrapping key (hex): {wrapping_key.hex()}")
        
        # Decrypt using AES-256-GCM
        aesgcm = AESGCM(wrapping_key)
        content_key = aesgcm.decrypt(wrap_nonce, wrapped_ck, None)
        
        print(f"✓ Content key decrypted: {len(content_key)} bytes")
        return content_key
    
    def _decrypt_data(self, envelope: Dict[str, Any], content_key: bytes) -> bytes:
        """Decrypt dataset using content key."""
        # Get encrypted data, nonce, and tag
        ciphertext = base64.b64decode(envelope['ciphertext'])
        nonce = base64.b64decode(envelope['cipher_iv'])
        tag = base64.b64decode(envelope['cipher_tag'])
        
        print("🔓 Decrypting dataset...")
        print(f"   Ciphertext: {len(ciphertext)} bytes")
        print(f"   Nonce: {len(nonce)} bytes")
        print(f"   Auth tag: {len(tag)} bytes")
        
        # Combine ciphertext and tag (GCM expects them together)
        ciphertext_with_tag = ciphertext + tag
        
        # Decrypt using AES-256-GCM
        aesgcm = AESGCM(content_key)
        decrypted_data = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
        
        print(f"✓ Dataset decrypted: {len(decrypted_data)} bytes")
        return decrypted_data


def detect_format(data: bytes) -> str:
    """Auto-detect data format (CSV or JSON)."""
    try:
        # Try to decode as text
        text = data.decode('utf-8', errors='strict')
        
        # Check for CSV indicators
        if text.startswith('#') or ',' in text.split('\n')[0]:
            return 'csv'
        
        # Check for JSON
        text_stripped = text.strip()
        if text_stripped.startswith('{') or text_stripped.startswith('['):
            try:
                json.loads(text_stripped)
                return 'json'
            except json.JSONDecodeError:
                pass
        
        return 'csv'  # Default to CSV
        
    except UnicodeDecodeError:
        return 'unknown'


def main():
    parser = argparse.ArgumentParser(
        description='Decrypt ZDatar dataset encrypted with AES-256-GCM',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Decrypt using encrypted file and base64 key
  python decrypt_dataset.py \\
      --encrypted-file dataset.csv.enc \\
      --encrypted-key "eyJhbGdvIjoiQUVTLTI1Ni1HQ00iLC4uLg==" \\
      --recipient-pubkey "HZM9WsPvam7CDavWEuRF2qpFbVrHQ8WfD4vPbPuT4TXE" \\
      --recipient-private-key "your_64_byte_private_key_base58" \\
      --output dataset.csv
  
  # Read private key from file
  python decrypt_dataset.py \\
      --encrypted-file dataset.csv.enc \\
      --encrypted-key-file envelope.b64 \\
      --recipient-pubkey "27CACP3VQDC1PVxuT37sk8L7qsQh8zj9Y3v3jH4CU1KF" \\
      --private-key-file ~/.zdatar/seller_private.key \\
      --output dataset.json \\
      --format json
        """
    )
    
    # Input arguments
    parser.add_argument(
        '--encrypted-file',
        required=True,
        help='Path to encrypted dataset file'
    )
    parser.add_argument(
        '--encrypted-key',
        help='Base64-encoded encryption envelope (from backend API)'
    )
    parser.add_argument(
        '--encrypted-key-file',
        help='File containing base64-encoded encryption envelope'
    )
    parser.add_argument(
        '--recipient-pubkey',
        required=True,
        help='Your Solana public key (base58-encoded)'
    )
    parser.add_argument(
        '--recipient-private-key',
        help='Your Solana private key (base58-encoded, 64 bytes)'
    )
    parser.add_argument(
        '--private-key-file',
        help='File containing your Solana private key'
    )
    
    # Output arguments
    parser.add_argument(
        '--output',
        required=True,
        help='Path to output decrypted file'
    )
    parser.add_argument(
        '--format',
        choices=['csv', 'json', 'auto'],
        default='auto',
        help='Output format (default: auto-detect)'
    )
    
    # Parse arguments
    args = parser.parse_args()
    
    # Validate inputs
    if not args.encrypted_key and not args.encrypted_key_file:
        parser.error("Either --encrypted-key or --encrypted-key-file is required")
    
    if not args.recipient_private_key and not args.private_key_file:
        parser.error("Either --recipient-private-key or --private-key-file is required")
    
    try:
        # Read encrypted data
        print(f"📁 Reading encrypted file: {args.encrypted_file}")
        with open(args.encrypted_file, 'rb') as f:
            encrypted_data = f.read()
        print(f"   Loaded {len(encrypted_data)} bytes")
        
        # Read encrypted key
        if args.encrypted_key_file:
            print(f"📁 Reading encrypted key from: {args.encrypted_key_file}")
            with open(args.encrypted_key_file, 'r') as f:
                encrypted_aes_key = f.read().strip()
        else:
            encrypted_aes_key = args.encrypted_key
        
        print(f"   Encrypted key: {len(encrypted_aes_key)} chars")
        
        # Read private key
        if args.private_key_file:
            print(f"🔐 Reading private key from: {args.private_key_file}")
            with open(args.private_key_file, 'r') as f:
                recipient_private_key = f.read().strip()
        else:
            recipient_private_key = args.recipient_private_key
        
        print(f"   Private key: {len(recipient_private_key)} chars (base58)")
        
        # Initialize decryptor
        decryptor = DatasetDecryptor(args.recipient_pubkey, recipient_private_key)
        
        # Decrypt dataset
        print("\n" + "="*80)
        decrypted_data = decryptor.decrypt_dataset(encrypted_data, encrypted_aes_key)
        print("="*80 + "\n")
        
        # Auto-detect format if needed
        output_format = args.format
        if output_format == 'auto':
            output_format = detect_format(decrypted_data)
            print(f"📊 Auto-detected format: {output_format}")
        
        # Write output
        print(f"💾 Writing decrypted data to: {args.output}")
        with open(args.output, 'wb') as f:
            f.write(decrypted_data)
        
        # Show preview
        preview = decrypted_data[:500].decode('utf-8', errors='replace')
        print("\n📄 Preview (first 500 chars):")
        print("-" * 80)
        print(preview)
        if len(decrypted_data) > 500:
            print(f"... ({len(decrypted_data) - 500} more bytes)")
        print("-" * 80)
        
        print(f"\n✅ SUCCESS! Decrypted {len(decrypted_data)} bytes to {args.output}")
        print(f"   Format: {output_format}")
        
    except FileNotFoundError as e:
        print(f"❌ Error: File not found: {e}")
        sys.exit(1)
    except ValueError as e:
        print(f"❌ Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
