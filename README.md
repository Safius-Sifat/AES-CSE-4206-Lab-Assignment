# AES-128 Algorithm Implementation

This repository contains a collaborative Python implementation of the AES-128 block cipher.

## Project Structure
```
AES-Algorithm/
│
├── aes/
│   ├── __init__.py
│   ├── gf_arithmetic.py       # GF(2^8) multiplication
│   ├── aes_tables.py          # S‑Box and inverse S‑Box
│   ├── key_expansion.py       # Key schedule
│   ├── encryption.py          # Encryption of a single block
│   └── decryption.py          # Planned: Member 3
│
├── tests/
│   ├── test_key_expansion.py  # Planned: Member 1
│   ├── test_encryption.py
│   └── test_decryption.py     # Planned: Member 3
│
├── main.py                    # Example usage / entry point
├── requirements.txt
├── .gitignore
├── README.md
└── CONTRIBUTING.md            # Planned
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

All functions raise `ValueError` for invalid input sizes.

## Testing
Run the test suite with:
```bash
python -m pip install -r requirements.txt
python -m pytest
```

## Contributing
Please work on a feature branch, push regularly, and open a Pull Request when your feature is ready.

## Member 2 status: encryption complete

`encrypt_block(plaintext, round_keys)` accepts a 16-byte plaintext and eleven
16-byte round keys (K0-K10), and returns a 16-byte ciphertext. It implements
column-major state conversion, AddRoundKey, SubBytes, ShiftRows, and MixColumns,
with no MixColumns in round 10. An optional `trace_callback(round, stage, state)`
receives independent state snapshots for demonstrations.

Encryption uses the shared `aes_tables.sub_byte` and `gf_arithmetic.gf_multiply`
functions. The duplicate temporary `aes_support.py` is no longer needed.

Run `python main.py` for a traced example using fixed reference round keys.
The expected ciphertext is `69c4e0d86a7b0430d8cdb78070b4c55a`.
Run `python -m pytest -q` for known-answer vectors, intermediate round states,
input validation, and callback isolation checks.

Reference vectors: [FIPS 197](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf)
and [SP 800-38A](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf).

Integration remains pending: Member 1's `key_expansion` and the inverse S-box
are placeholders on this branch, and Member 3's decryption module is not present.
Replace the demo's fixed round keys with `key_expansion(key)` when that work lands.
These are separate from Member 2's supplied-round-key encryption interface.
