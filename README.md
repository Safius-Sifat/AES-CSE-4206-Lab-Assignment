# AES-128 Algorithm Implementation

This repository contains a collaborative Python implementation of the AES-128 block cipher.

## Project Structure
```
AES-Algorithm/
│
├── aes/
│   ├── __init__.py
│   ├── gf_arithmetic.py       # GF(2^8) multiplication
│   ├── aes_tables.py          # S-Box and inverse S-Box
│   ├── key_expansion.py       # Key schedule
│   ├── encryption.py          # Encryption of a single block
│   └── decryption.py          # Decryption of a single block
│
├── tests/
│   ├── test_key_expansion.py
│   ├── test_encryption.py
│   └── test_decryption.py
│
├── main.py                    # Interactive CLI and FIPS 197 demo
├── requirements.txt
├── .gitignore
└── README.md
```

## API Contract
All functions work with **bytes** objects and use the same interface:
| Module | Function | Signature |
|--------|----------|-----------|
| `gf_arithmetic.py` | `gf_multiply` | `gf_multiply(a: int, b: int) -> int` |
| `aes_tables.py` | `sub_byte` | `sub_byte(value: int) -> int` |
| `aes_tables.py` | `inv_sub_byte` | `inv_sub_byte(value: int) -> int` |
| `key_expansion.py` | `key_expansion` | `key_expansion(key: bytes) -> list[bytes]` |
| `encryption.py` | `encrypt_block` | `encrypt_block(plaintext: bytes, round_keys: list[bytes]) -> bytes` |
| `decryption.py` | `decrypt_block` | `decrypt_block(ciphertext: bytes, round_keys: list[bytes]) -> bytes` |

All functions raise `ValueError` for invalid input sizes or types.

## Usage
Run the interactive CLI:
```bash
python main.py
```

Run the FIPS 197 traced demonstration directly:
```bash
python main.py --demo
```

## Testing
Run the test suite with:
```bash
python -m pip install -r requirements.txt
python -m pytest -v
```

Reference vectors: [FIPS 197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf)
and [SP 800-38A](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf).
