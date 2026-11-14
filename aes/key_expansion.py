def key_expansion(key: bytes) -> list[bytes]:
    """Generate the 11 round keys for AES-128.

    Args:
        key (bytes): 16-byte initial key.
    Returns:
        list[bytes]: List of 11 round keys, each 16 bytes.
    """
    if len(key) != 16:
        raise ValueError("AES-128 key must be 16 bytes")
    raise NotImplementedError
