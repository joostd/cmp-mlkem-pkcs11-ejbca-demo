#!/usr/bin/env python3
"""
Decrypt a CMP ip response's KEM-enveloped certificate (RFC 9629 CMS-for-ML-KEM)
using a YubiKey-resident ML-KEM private key via YKCS11 for the decapsulation
step, then HKDF-SHA256 + AES-KeyUnwrap + AES-CBC in plain Python for the rest.

Input is the directory written by CmpKemDump.java:
  kemct.bin             - ML-KEM ciphertext (KEMRecipientInfo.kemct)
  wrapped_cek.bin       - AES-wrapped content-encryption key (.encryptedKey)
  kdf_info.der          - DER KemOtherInfo{wrap, kekLength[, ukm]}, the HKDF "info"
  encrypted_content.bin - the encrypted certificate bytes
  metadata.properties   - content_enc_oid / content_enc_iv_hex

Usage:
  cmp_kem_decrypt.py <dump-dir> <cert-out.der> [--pin PIN] [--key-id HEX]
                      [--lib /path/to/libykcs11.dylib]
"""
import argparse
import pathlib

import pkcs11
from pkcs11 import Attribute, KeyType, ObjectClass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap

AES_CBC_OID = "2.16.840.1.101.3.4.1.2"  # aes128-CBC; also covers other AES-*-CBC OIDs below
AES_CBC_OIDS = {
    "2.16.840.1.101.3.4.1.2": 128,
    "2.16.840.1.101.3.4.1.22": 192,
    "2.16.840.1.101.3.4.1.42": 256,
}


def read_metadata(path: pathlib.Path) -> dict:
    props = {}
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        k, v = line.split("=", 1)
        props[k] = v
    return props


def decapsulate_on_device(lib_path: str, pin: str, key_id_hex: str, kemct: bytes, kek_length_bytes: int) -> bytes:
    lib = pkcs11.lib(lib_path)
    token = lib.get_slots(token_present=True)[0].get_token()
    key_id = bytes.fromhex(key_id_hex)

    with token.open(user_pin=pin) as session:
        priv = session.get_key(
            key_type=KeyType.ML_KEM,
            object_class=ObjectClass.PRIVATE_KEY,
            id=key_id,
        )
        # YKCS11's C_DecapsulateKey ignores key_type/key_length/template and always
        # returns the raw, un-KDF'd ML-KEM shared secret (32 bytes) - see ykcs11.c.
        # We ask for GENERIC_SECRET/256 bits to match, but the actual output is raw.
        secret_key = priv.decapsulate_key(
            kemct, KeyType.GENERIC_SECRET, key_length=kek_length_bytes * 8, store=False
        )
        return secret_key[Attribute.VALUE]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dump_dir")
    ap.add_argument("cert_out")
    ap.add_argument("--pin", required=True)
    ap.add_argument("--key-id", default="06", help="CKA_ID hex of the ML-KEM private key (default: 06, PIV slot 0x83)")
    ap.add_argument(
        "--lib",
        default="/Users/joost/gh/yubico/yubico-piv-tool/build/ykcs11/libykcs11.dylib",
    )
    args = ap.parse_args()

    d = pathlib.Path(args.dump_dir)
    kemct = (d / "kemct.bin").read_bytes()
    wrapped_cek = (d / "wrapped_cek.bin").read_bytes()
    kdf_info = (d / "kdf_info.der").read_bytes()
    encrypted_content = (d / "encrypted_content.bin").read_bytes()
    meta = read_metadata(d / "metadata.properties")

    content_enc_oid = meta["content_enc_oid"]
    iv = bytes.fromhex(meta["content_enc_iv_hex"])
    if content_enc_oid not in AES_CBC_OIDS:
        raise SystemExit(f"Unsupported contentEncryptionAlgorithm OID: {content_enc_oid}")
    aes_bits = AES_CBC_OIDS[content_enc_oid]

    kek_length_bytes = int(meta["kek_length"])  # size of the HKDF-derived wrapping key (KEK)

    print(f"Decapsulating {len(kemct)}-byte KEM ciphertext on YubiKey (key id {args.key_id})...")
    shared_secret = decapsulate_on_device(args.lib, args.pin, args.key_id, kemct, kek_length_bytes)
    print(f"Raw shared secret ({len(shared_secret)} bytes): {shared_secret.hex()}")

    print(f"Deriving {kek_length_bytes}-byte KEK via HKDF-SHA256 (RFC 9629 KemOtherInfo as info)...")
    kek = HKDF(
        algorithm=hashes.SHA256(),
        length=kek_length_bytes,
        salt=None,
        info=kdf_info,
    ).derive(shared_secret)
    print(f"KEK: {kek.hex()}")

    print(f"Unwrapping {len(wrapped_cek)}-byte CEK (AES-KeyWrap, RFC 3394)...")
    cek = aes_key_unwrap(kek, wrapped_cek)
    print(f"CEK ({len(cek) * 8}-bit AES): {cek.hex()}")

    print(f"Decrypting {len(encrypted_content)} bytes with AES-{aes_bits}-CBC...")
    decryptor = Cipher(algorithms.AES(cek), modes.CBC(iv)).decryptor()
    padded = decryptor.update(encrypted_content) + decryptor.finalize()
    pad_len = padded[-1]
    cert_der = padded[: -pad_len]

    pathlib.Path(args.cert_out).write_bytes(cert_der)
    print(f"Wrote {len(cert_der)}-byte certificate to {args.cert_out}")


if __name__ == "__main__":
    main()
