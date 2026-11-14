def encrypt_block(plaintext: bytes, round_keys: list[bytes]) -> bytes:
    """Encrypt one 16-byte block using AES-128.

    Args:
        plaintext (bytes): 16-byte plaintext block.
        round_keys (list[bytes]): List of 11 round keys.
    Returns:
        bytes: 16-byte ciphertext block.
    """
    if len(plaintext) != 16:
        raise ValueError("Plaintext must be 16 bytes")
    if len(round_keys) != 11 or any(len(k) != 16 for k in round_keys):
        raise ValueError("Round keys must be a list of 11 16-byte keys")
    raise NotImplementedError
