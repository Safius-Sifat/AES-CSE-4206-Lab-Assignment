from aes.encryption import encrypt_block

# Standard AES-128 round keys
# Temporary keys for testing Member 2's encryption.
# Later these will come from Member 1.

ROUND_KEYS_HEX = [
    "000102030405060708090A0B0C0D0E0F",
    "D6AA74FDD2AF72FADAA678F1D6AB76FE",
    "B692CF0B643DBDF1BE9BC5006830B3FE",
    "B6FF744ED2C2C9BF6C590CBF0469BF41",
    "47F7F7BC95353E03F96C32BCFD058DFD",
    "3CAAA3E8A99F9DEB50F3AF57ADF622AA",
    "5E390F7DF7A69296A7553DC10AA31F6B",
    "14F9701AE35FE28C440ADF4D4EA9C026",
    "47438735A41C65B9E016BAF4AEBF7AD2",
    "549932D1F08557681093ED9CBE2C974E",
    "13111D7FE3944A17F307A78B4D2B30C5",
]

round_keys = [bytes.fromhex(key) for key in ROUND_KEYS_HEX]


def print_state(round_number, stage, state):
    """Print intermediate state after each AES transformation."""

    print(f"\nRound {round_number} - {stage}")

    for row in state:
        print(" ".join(f"{value:02X}" for value in row))


def main():

    plaintext = bytes.fromhex(
        "00112233445566778899AABBCCDDEEFF"
    )

    print("=" * 50)
    print("AES-128 ENCRYPTION")
    print("=" * 50)

    print("\nOriginal Plaintext:")
    print(plaintext.hex().upper())

    print("\nSecret Key:")
    print(ROUND_KEYS_HEX[0])

    print("\nStarting Encryption...")

    ciphertext = encrypt_block(
        plaintext,
        round_keys,
        trace_callback=print_state
    )

    print("\n" + "=" * 50)
    print("FINAL ENCRYPTION RESULT")
    print("=" * 50)

    print("\nPlaintext:")
    print(plaintext.hex().upper())

    print("\nCiphertext:")
    print(ciphertext.hex().upper())

    print("\nExpected Ciphertext:")
    print("69C4E0D86A7B0430D8CDB78070B4C55A")


if __name__ == "__main__":
    main()
