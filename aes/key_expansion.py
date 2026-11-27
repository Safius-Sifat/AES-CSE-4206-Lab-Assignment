from .aes_tables import sub_byte

RCON = (
    0x00, 0x01, 0x02, 0x04,
    0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36
)

def rot_word(word):
    return word[1:] + word[:1]

def sub_word(word):
    return [sub_byte(b) for b in word]

def key_expansion(key: bytes) -> list[bytes]:
    """Generate the 11 round keys for AES-128.

    Args:
        key (bytes): 16-byte initial key.
    Returns:
        list[bytes]: List of 11 round keys, each 16 bytes.
    """
    if not isinstance(key, bytes) or len(key) != 16:
        raise ValueError("AES-128 key must be 16 bytes")

    words = [
        list(key[i:i + 4])
        for i in range(0, 16, 4)
    ]

    for i in range(4, 44):
        temp = words[i - 1].copy()

        if i % 4 == 0:
            temp = rot_word(temp)
            temp = sub_word(temp)
            temp[0] ^= RCON[i // 4]

        new_word = [
            words[i - 4][j] ^ temp[j]
            for j in range(4)
        ]

        words.append(new_word)

    round_keys = []

    for i in range(0, 44, 4):
        round_key = bytes(
            b
            for word in words[i:i + 4]
            for b in word
        )
        round_keys.append(round_key)

    return round_keys