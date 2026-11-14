
from aes.key_expansion import key_expansion
from aes.encryption import encrypt_block
from aes.decryption import decrypt_block


def main():

    print("=" * 45)
    print("       AES-128 ENCRYPTION & DECRYPTION")
    print("=" * 45)

    try:

        # Get secret key
        key_hex = input("\nEnter 128-bit Secret Key (HEX): ").strip()

        key = bytes.fromhex(key_hex)

        if len(key) != 16:
            raise ValueError("Secret key must be 16 bytes (32 hex characters)")

        # Generate round keys
        round_keys = key_expansion(key)

        print("\n1. Encryption")
        print("2. Decryption")

        choice = input("\nChoose operation (1/2): ").strip()

        if choice == "1":

            plaintext_hex = input(
                "\nEnter Plaintext (HEX): "
            ).strip()

            plaintext = bytes.fromhex(plaintext_hex)

            if len(plaintext) != 16:
                raise ValueError("Plaintext must be exactly 16 bytes")

            ciphertext = encrypt_block(
                plaintext,
                round_keys
            )

            print("\nEncrypted Ciphertext:")
            print(ciphertext.hex().upper())

        elif choice == "2":

            ciphertext_hex = input(
                "\nEnter Ciphertext (HEX): "
            ).strip()

            ciphertext = bytes.fromhex(ciphertext_hex)

            if len(ciphertext) != 16:
                raise ValueError("Ciphertext must be exactly 16 bytes")

            plaintext = decrypt_block(
                ciphertext,
                round_keys
            )

            print("\nRecovered Original Plaintext:")
            print(plaintext.hex().upper())

        else:

            print("\nInvalid choice!")

    except ValueError as error:

        print("\nError:", error)


if __name__ == "__main__":
    main()
