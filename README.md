# PQC Lab: EJBCA via Docker Compose

A local Post-Quantum Cryptography (PQC) testing playground built on EJBCA
Community for a quantum-safe PKI.

## Prerequisites

- Docker
- OpenSSL 3.5+ locally, for native ML-KEM key generation (`openssl genpkey -algorithm ML-KEM-768`)
- A JDK locally, only needed for Path B below (genuine CMPv3 KEM proof-of-possession)

## 1. Start the environment

```bash
docker compose up -d
```

On a genuinely fresh volume, EJBCA's `TLS_SETUP_ENABLED=simple` mode (already set
in `docker-compose.yaml`) auto-grants full AdminWeb access with no certificate
import required — confirmed by this line in the startup logs:

```
Adding initial application RoleMember (";PublicAccessAuthenticationToken:TRANSPORT_CONFIDENTIAL;").
```

Just open **https://localhost/ejbca/adminweb/** directly.

> If it ever demands a client certificate instead, the `ejbca_data` volume isn't
> actually fresh (e.g. reused from a prior non-`simple` setup). Fix with:
> `docker compose down -v && docker compose up -d`

ML-KEM needs no extra certificate-profile configuration — the default `ENDUSER`
profile in EJBCA 9.6.3 already permits `ML-KEM-512/768/1024` as key algorithms.

## 2. Path A — RAVERIFIED enrollment (simplest, plain OpenSSL)

This proves ML-KEM certificate issuance works end-to-end, but the
proof-of-possession is only "RA vouches for it" (RAVERIFIED) — not real
cryptographic possession proof. See Path B for that.

**One-time GUI setup** — System Configuration → CMP Configuration → Add:

| Field | Value |
|---|---|
| Name | `mlkem` |
| Operational Mode | **RA Mode** |
| Authentication Module | **HMAC**, shared secret e.g. `changeit123` |
| RA Default CA | `ManagementCA` |
| RA End Entity Profile | `ENDUSER` |
| RA Certificate Profile | `ENDUSER` |
| RA Verify Proof-of-Possession | **Allow** ← easy to miss, required |

Save.

**Enroll from your machine:**

```bash
# Export the CA cert as a trust anchor (one-time)
curl -s "http://localhost/ejbca/publicweb/webdist/certdist?cmd=cacert&caid=<caid>&format=pem" -o ca.p7
openssl pkcs7 -in ca.p7 -print_certs -out ManagementCA_cert.pem

# Generate an ML-KEM key and enroll
openssl genpkey -algorithm ML-KEM-768 -out key.pem
openssl cmp -cmd ir \
  -server http://localhost/ejbca/publicweb/cmp/mlkem \
  -ref <username> -secret pass:changeit123 \
  -newkey key.pem -popo 0 \
  -subject "/CN=<username>" \
  -trusted ManagementCA_cert.pem \
  -unprotected_errors \
  -certout cert.pem
```

Notes:
- `-popo 0` (RAVERIFIED) is required — ML-KEM keys can't sign, so signature POP
  is impossible, and OpenSSL's `cmp` app can't build a genuine RFC 9810
  key-encipherment POP (see Path B for why).
- `-unprotected_errors` is needed because EJBCA sends the final PKIConf message
  unprotected, which OpenSSL otherwise treats as fatal even though it's
  RFC-permitted.
- EJBCA enforces unique public keys per user — each enrollment needs a fresh
  keypair or a different username.

## 3. Path B — genuine CMPv3 KEM-POP enrollment (real possession proof)

The real RFC 9810/9629 mechanism EJBCA implements wraps the issued certificate
in a CMS `EnvelopedData` using `KEMRecipientInfo` (HKDF-SHA256), and requires
the CMP message header to use protocol version 3 (`pvno=3`, i.e. CMP2021).
OpenSSL 3.6.4's `cmp` app hardcodes `pvno=2` for every request with no way to
override it (verified from the OpenSSL source — `ossl_cmp_hdr_init()` in
`crypto/cmp/cmp_hdr.c` always sets `OSSL_CMP_PVNO_2`), so it can never complete
this flow. `CmpKemEnroll.java` in this repo builds the request manually with
plain Bouncy Castle to work around that.

**Create the end entity (CLI):**

```bash
docker exec ejbca-pqc-lab /opt/keyfactor/bin/ejbca.sh ra addendentity \
  --username cmpencert --dn "CN=cmpencert" --caname ManagementCA \
  --type 1 --token USERGENERATED --password foo234 \
  --eeprofile EMPTY --certprofile ENDUSER

docker exec ejbca-pqc-lab /opt/keyfactor/bin/ejbca.sh ra setclearpwd cmpencert foo234
```

The clear-text password is required — CMP's HMAC authentication can't verify
against EJBCA's normally-stored password hash.

**One-time GUI setup** — System Configuration → CMP Configuration → Add:

| Field | Value |
|---|---|
| Name | `cmpclient` |
| Operational Mode | **Client Mode** (default) |
| Authentication Module | **HMAC only** — uncheck `RegTokenPwd` and `DnPartPwd`, both checked by default alongside HMAC |
| Extract Username Component | **CN** (not the default `DN`) |
| CMP Response Additional CA Certificates | clear/uncheck **Use** |

Save.

**Get the Bouncy Castle jars EJBCA itself uses** (same version, for wire compatibility):

```bash
mkdir -p bcjars
docker cp ejbca-pqc-lab:/opt/keyfactor/wildfly-39.0.1.Final/modules/system/layers/base/org/bouncycastle/bcprov/main/bcprov-jdk18on-1.83.jar bcjars/
docker cp ejbca-pqc-lab:/opt/keyfactor/wildfly-39.0.1.Final/modules/system/layers/base/org/bouncycastle/bcpkix/main/bcpkix-jdk18on-1.83.jar bcjars/
docker cp ejbca-pqc-lab:/opt/keyfactor/wildfly-39.0.1.Final/modules/system/layers/base/org/bouncycastle/bcutil/main/bcutil-jdk18on-1.83.jar bcjars/
```

**Compile:**

```bash
CP="bcjars/bcprov-jdk18on-1.83.jar:bcjars/bcutil-jdk18on-1.83.jar:bcjars/bcpkix-jdk18on-1.83.jar"
javac -cp "$CP" CmpKemRequest.java CmpKemExtract.java
```

The tool is split in two, so the actual HTTP transport is a plain `curl` call
you can inspect/modify independently of the crypto:

0. **Generate an ML-KEM keypair** with OpenSSL (verified interoperable with
   BC's `KeyFactory` — the same PKCS8 DER loads fine and derives the matching
   public key):

   ```bash
   openssl genpkey -algorithm ML-KEM-768 -outform DER -out /tmp/key.der
   ```

1. **`CmpKemRequest`** takes that key file, builds the pvno-3 `ir` message
   (keyEncipherment/encrCert POP, HMAC/PBM-protected), and writes it to a file:

   ```bash
   java -cp ".:$CP" CmpKemRequest "cmpencert" "foo234" /tmp/key.der /tmp/request.der
   ```

2. **`curl`** POSTs the raw request and saves the raw response — no BC/Java
   involved in the transport itself:

   ```bash
   curl -s -X POST --data-binary @/tmp/request.der \
     -H "Content-Type: application/pkixcmp" \
     http://localhost/ejbca/publicweb/cmp/cmpclient -o /tmp/response.der
   ```

3. **`CmpKemExtract`** parses the response: on a `PKIStatus` rejection it
   prints the failure reason and exits non-zero; on success it decrypts the
   CMS `EnvelopedData`/`KEMRecipientInfo` envelope with the same key file
   from step 0 and writes the plain certificate:

   ```bash
   java -cp ".:$CP" CmpKemExtract /tmp/response.der /tmp/key.der /tmp/cert.der
   ```

What makes this work where OpenSSL can't:
1. `CmpKemRequest` builds `PKIHeader` with `pvno = PKIHeader.CMP_2021` (3).
2. It builds `POPOPrivKey` with `SubsequentMessage.encrCert`, wrapped in
   `ProofOfPossession.TYPE_KEY_ENCIPHERMENT` — the same POP type OpenSSL
   builds, just under the correct protocol version.
3. It protects the request via `PKMACBuilder` + `JcePKMACValuesCalculator`
   (HMAC/PBM), matching the `cmpclient` alias's authentication.
4. `CmpKemExtract` unwraps the response via
   `CertificateResponse.getCertificate(new JceKEMEnvelopedRecipient(privateKey))`,
   which transparently handles the CMS `EnvelopedData`/`KEMRecipientInfo`/HKDF-SHA256
   decapsulation.

**Before every rerun against the same username**, reset its status — EJBCA
marks an end entity `GENERATED` after issuance (even after some failed
attempts, since state can advance before a final rejection) and refuses to
reissue without this:

```bash
docker exec ejbca-pqc-lab /opt/keyfactor/bin/ejbca.sh ra setendentitystatus cmpencert 10
```

The clear-text password survives status resets, so `setclearpwd` doesn't need
to be repeated — only `setendentitystatus`.

## 4. Path C — hardware-backed ML-KEM: key never leaves a YubiKey

Same CMPv3 KEM-POP flow as Path B, except the ML-KEM private key is generated
and stays on a YubiKey (via [Yubico's PIV PKCS#11 module,
`ykcs11`](https://github.com/Yubico/yubico-piv-tool), which implements the
PKCS#11 v3.2 KEM extension — `C_EncapsulateKey`/`C_DecapsulateKey`). The
decapsulation of EJBCA's response happens **on the device**; only the request
side (`CmpKemRequest`, needing just the public key) and the CMS/ASN.1 parsing
of the response use Java/Bouncy Castle. A separate Python tool does the
HKDF/unwrap/decrypt math using the raw shared secret the YubiKey returns.

Requires a YubiKey with an ML-KEM key already provisioned in a PIV slot, e.g.:

```bash
yubico-piv-tool -a generate -A ML-KEM-768 -s 83 -K DER -o pubkey.der
```

**1. Build the request from the device's public key** (same tool as Path B,
just pointed at a public key file instead of one derived from a private key):

```bash
java -cp ".:$CP" CmpKemRequest "cmpencert" "foo234" pubkey.der /tmp/request.der
```

**2. POST it with curl**, same as Path B:

```bash
curl -s -X POST --data-binary @/tmp/request.der \
  -H "Content-Type: application/pkixcmp" \
  http://localhost/ejbca/publicweb/cmp/cmpclient -o /tmp/response.der
```

**3. `CmpKemDump`** parses the response's `KEMRecipientInfo` /
`EncryptedContentInfo` (RFC 9629, CMS for ML-KEM) and writes out the raw
pieces needed for decryption — **without attempting decryption itself**:

```bash
javac -cp "$CP" CmpKemDump.java
java -cp ".:$CP" CmpKemDump /tmp/response.der /tmp/kemdump
```

This writes `kemct.bin` (KEM ciphertext), `wrapped_cek.bin` (AES-wrapped
content-encryption key), `kdf_info.der` (the DER-encoded `KemOtherInfo{wrap,
kekLength}` structure that is HKDF's `info` input per RFC 9629),
`encrypted_content.bin`, and `metadata.properties` (content-encryption OID +
IV, KEK length).

**4. `cmp_kem_decrypt.py`** does the rest in Python, using
[`python-pkcs11`](https://github.com/pyauth/python-pkcs11) (>=0.10.0, which
added ML-KEM/KEM support) against `ykcs11` for the actual decapsulation, and
the `cryptography` package for HKDF-SHA256, AES-KeyUnwrap (RFC 3394), and
AES-CBC:

```bash
python3 -m venv venv && venv/bin/pip install -r requirements.txt
venv/bin/python cmp_kem_decrypt.py /tmp/kemdump /tmp/cert.der \
  --pin <your PIV PIN> --key-id 06 \
  --lib /path/to/libykcs11.dylib
```

`--key-id` is the PKCS#11 `CKA_ID` of the private key object, *not* the PIV
slot tag — YKCS11 maps PIV slots to sequential `CKA_ID`s (`9a`→`01`,
`9c`→`02`, `9d`→`03`, `9e`→`04`, then the retired slots `82..95`→`05..18`
sequentially, so `83`→`06`). If unsure, enumerate the token's ML-KEM private
key objects and try each `CKA_ID` against a real ciphertext, or check which
one's decapsulated secret matches a known-good software encapsulation.

What's notable here, from actually reading `ykcs11`'s source
(`C_DecapsulateKey` in `ykcs11.c`): it's a thin wrapper around plain
`C_Decrypt` with `CKM_ML_KEM` — no `CK_ML_KEM_PARAMS`, no on-device KDF. It
returns the **raw, unprocessed 32-byte ML-KEM shared secret**, which is
exactly what's needed to apply RFC 9629's HKDF construction ourselves and get
byte-for-byte the same KEK EJBCA derived.

This was verified two ways against a real, physical YubiKey: a round-trip
self-test (encapsulate in software with OpenSSL against the device's public
key, decapsulate on the device, confirm the shared secrets match), and the
full pipeline above against a live EJBCA response, confirmed by
`openssl verify` against `ManagementCA`.
