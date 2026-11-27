"""Interactive CLI and demo entry point for AES-128 encryption and decryption."""

import sys

from aes.decryption import decrypt_block
from aes.encryption import encrypt_block
from aes.key_expansion import key_expansion


def print_state(round_number: int, stage: str, state: list[list[int]]) -> None:
    """Print intermediate state after each AES transformation."""
    print(f"\nRound {round_number} - {stage}")
    for row in state:
        print(" ".join(f"{value:02X}" for value in row))


def run_demo() -> None:
    """Run the FIPS 197 Appendix B encryption and decryption demonstration."""
    key = bytes.fromhex("000102030405060708090A0B0C0D0E0F")
    plaintext = bytes.fromhex("00112233445566778899AABBCCDDEEFF")

    round_keys = key_expansion(key)

    print("=" * 50)
    print("AES-128 FIPS 197 DEMO")
    print("=" * 50)
    print(f"\nSecret Key: {key.hex().upper()}")
    print(f"Plaintext:  {plaintext.hex().upper()}")

    ciphertext = encrypt_block(plaintext, round_keys, trace_callback=print_state)
    recovered = decrypt_block(ciphertext, round_keys)

    print("\n" + "=" * 50)
    print("FINAL RESULT")
    print("=" * 50)
    print(f"Ciphertext:          {ciphertext.hex().upper()}")
    print("Expected Ciphertext: 69C4E0D86A7B0430D8CDB78070B4C55A")
    print(f"Decrypted Plaintext: {recovered.hex().upper()}")
    print(f"Round-trip match:    {recovered == plaintext}")


def main() -> None:
    """Run the AES-128 CLI."""
    if "--demo" in sys.argv:
        run_demo()
        return

    print("=" * 45)
    print("       AES-128 ENCRYPTION & DECRYPTION")
    print("=" * 45)

    try:
        print("\n1. Encryption")
        print("2. Decryption")
        print("3. Run FIPS 197 Demo")

        choice = input("\nChoose operation (1/2/3): ").strip()

        if choice == "3":
            run_demo()
            return

        if choice not in {"1", "2"}:
            print("\nInvalid choice!")
            return

        key_hex = input("\nEnter 128-bit Secret Key (HEX): ").strip()
        key = bytes.fromhex(key_hex)
        if len(key) != 16:
            raise ValueError("Secret key must be 16 bytes (32 hex characters)")

        round_keys = key_expansion(key)

        if choice == "1":
            plaintext_hex = input("\nEnter Plaintext (HEX): ").strip()
            plaintext = bytes.fromhex(plaintext_hex)
            if len(plaintext) != 16:
                raise ValueError("Plaintext must be exactly 16 bytes")

            ciphertext = encrypt_block(plaintext, round_keys)
            print("\nEncrypted Ciphertext:")
            print(ciphertext.hex().upper())
        else:
            ciphertext_hex = input("\nEnter Ciphertext (HEX): ").strip()
            ciphertext = bytes.fromhex(ciphertext_hex)
            if len(ciphertext) != 16:
                raise ValueError("Ciphertext must be exactly 16 bytes")

            plaintext = decrypt_block(ciphertext, round_keys)
            print("\nRecovered Original Plaintext:")
            print(plaintext.hex().upper())

    except ValueError as error:
        print("\nError:", error)


if __name__ == "__main__":
    main()
