from collections.abc import Callable
from .aes_tables import sub_byte
from .gf_arithmetic import gf_multiply

State = list[list[int]]
TraceCallback = Callable[[int, str, State], None]


# ==========================================
# 1. STATE MATRIX VALIDATION
# ==========================================

def _check_state(state: State) -> None:
    """Ensure the state is a valid 4x4 byte matrix."""

    if len(state) != 4 or any(len(row) != 4 for row in state):
        raise ValueError("State must be a 4x4 matrix")

    for row in state:
        for value in row:
            if not isinstance(value, int) or not 0 <= value <= 255:
                raise ValueError("Every state element must be a byte")


# ==========================================
# 2. PLAINTEXT TO STATE MATRIX
# ==========================================

def bytes_to_state(block: bytes) -> State:
    """Convert 16 plaintext bytes into the AES 4x4 State Matrix."""

    if not isinstance(block, bytes) or len(block) != 16:
        raise ValueError("AES block must be exactly 16 bytes")

    return [
        [block[4 * col + row] for col in range(4)]
        for row in range(4)
    ]


def state_to_bytes(state: State) -> bytes:
    """Convert a 4x4 AES State Matrix back into 16 bytes."""

    _check_state(state)

    return bytes(
        state[row][col]
        for col in range(4)
        for row in range(4)
    )


# ==========================================
# 3. ADD ROUND KEY
# ==========================================

def add_round_key(state: State, round_key: bytes) -> State:
    """XOR every state byte with its corresponding round-key byte."""

    _check_state(state)
    key_state = bytes_to_state(round_key)

    return [
        [
            state[row][col] ^ key_state[row][col]
            for col in range(4)
        ]
        for row in range(4)
    ]


# ==========================================
# 4. SUB BYTES
# ==========================================

def sub_bytes(state: State) -> State:
    """Replace every state byte using the AES S-Box."""

    _check_state(state)

    return [
        [sub_byte(value) for value in row]
        for row in state
    ]


# ==========================================
# 5. SHIFT ROWS
# ==========================================

def shift_rows(state: State) -> State:
    """
    Perform cyclic left shifts.

    Row 0: shift 0 bytes
    Row 1: shift 1 byte
    Row 2: shift 2 bytes
    Row 3: shift 3 bytes
    """

    _check_state(state)

    return [
        row[r:] + row[:r]
        for r, row in enumerate(state)
    ]


# ==========================================
# 6. MIX COLUMNS
# ==========================================

def mix_columns(state: State) -> State:
    """Perform AES MixColumns using GF(2^8) multiplication."""

    _check_state(state)

    # Standard AES MixColumns transformation matrix
    matrix = (
        (2, 3, 1, 1),
        (1, 2, 3, 1),
        (1, 1, 2, 3),
        (3, 1, 1, 2),
    )

    result = [[0] * 4 for _ in range(4)]

    for col in range(4):
        for row in range(4):

            result[row][col] = (
                gf_multiply(matrix[row][0], state[0][col])
                ^ gf_multiply(matrix[row][1], state[1][col])
                ^ gf_multiply(matrix[row][2], state[2][col])
                ^ gf_multiply(matrix[row][3], state[3][col])
            )

    return result


# ==========================================
# 7. COMPLETE AES-128 ENCRYPTION
# ==========================================

def encrypt_block(
    plaintext: bytes,
    round_keys: list[bytes],
    trace_callback: TraceCallback | None = None,
) -> bytes:
    """
    Encrypt one 128-bit plaintext block using 11 AES round keys.

    Round 0: AddRoundKey
    Rounds 1-9: SubBytes, ShiftRows, MixColumns, AddRoundKey
    Round 10: SubBytes, ShiftRows, AddRoundKey
    """

    # Validate plaintext
    if not isinstance(plaintext, bytes) or len(plaintext) != 16:
        raise ValueError("Plaintext must be exactly 16 bytes")

    # Validate round keys
    if len(round_keys) != 11 or any(
        not isinstance(key, bytes) or len(key) != 16
        for key in round_keys
    ):
        raise ValueError(
            "AES-128 requires exactly 11 round keys of 16 bytes each"
        )

    # Step 1: Convert plaintext into State Matrix
    state = bytes_to_state(plaintext)

    # Optional callback for observing encryption steps
    def trace(round_number: int, stage: str) -> None:
        if trace_callback is not None:
            state_copy = [row[:] for row in state]
            trace_callback(round_number, stage, state_copy)

    # Step 2: Initial AddRoundKey (K0)
    state = add_round_key(state, round_keys[0])
    trace(0, "AddRoundKey")

    # Step 3: Main rounds (1-9)
    for round_number in range(1, 10):

        state = sub_bytes(state)
        trace(round_number, "SubBytes")

        state = shift_rows(state)
        trace(round_number, "ShiftRows")

        state = mix_columns(state)
        trace(round_number, "MixColumns")

        state = add_round_key(state, round_keys[round_number])
        trace(round_number, "AddRoundKey")

    # Step 4: Final round (Round 10)
    # IMPORTANT: No MixColumns in the final round!

    state = sub_bytes(state)
    trace(10, "SubBytes")

    state = shift_rows(state)
    trace(10, "ShiftRows")

    state = add_round_key(state, round_keys[10])
    trace(10, "AddRoundKey")

    # Step 5: Convert State Matrix into ciphertext
    ciphertext = state_to_bytes(state)

    return ciphertext
