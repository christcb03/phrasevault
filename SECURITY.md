# Security Policy

## Threat Model

PhraseVault follows Kerckhoffs's principle: the system is secure even if
everything except your passphrase is public knowledge. The algorithm,
schema, and all source code are intentionally open for audit.

**Your passphrase is the only secret.** It is never stored, logged, or
transmitted. It derives both the storage address (BLAKE3) and the
encryption key (Argon2id) — two completely different outputs from the
same input.

## What is protected

- **Content**: encrypted with XSalsa20-Poly1305 (PyNaCl SecretBox).
  Without the passphrase you cannot decrypt or even locate entries.
- **Ordering**: the Argon2id salt includes the timestamp, making entry
  order cryptographically unforgeable.
- **Chain integrity**: each entry address includes the previous address,
  so inserting or reordering entries breaks every subsequent address.
- **Transfer bundles (.pvx)**: each bundle carries a SHA-256 integrity
  hash and a pi-checkpoint; tampered bundles are rejected on import.

## What is NOT protected

- **Metadata timing**: an observer watching your database file can see
  when entries are written, but not what they contain.
- **Existence**: the database file itself is not hidden. Only its
  contents are encrypted.
- **Passphrase strength**: a weak passphrase (fewer than 4 random words)
  undermines everything. The minimum enforced by the library is 4 words.

## Cryptographic primitives

| Purpose         | Primitive              | Parameters                           |
|-----------------|------------------------|--------------------------------------|
| Address derive  | BLAKE3                 | domain tag `phrasevault:address:v1:` |
| Key derive      | Argon2id               | 64 MB memory, 3 iterations, p=4      |
| Encryption      | XSalsa20-Poly1305      | 24-byte random nonce per entry       |
| Chain link      | BLAKE3                 | domain tag `phrasevault:chain:v1:`   |
| Forest sign     | BLAKE3                 | domain tag `phrasevault:forest:v1:`  |

## Responsible Disclosure

If you find a security issue, please email christcb@yahoo.com with
the subject line `[phrasevault security]` before opening a public issue.
Allow reasonable time for a fix before public disclosure.
