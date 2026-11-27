"""AES-128 known-answer and interface tests (FIPS 197 examples)."""

import pytest

from aes.encryption import bytes_to_state, encrypt_block, state_to_bytes
from main import round_keys


PLAINTEXT = bytes.fromhex("00112233445566778899aabbccddeeff")
CIPHERTEXT = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")


@pytest.mark.parametrize("plaintext, ciphertext", [
    ("3243f6a8885a308d313198a2e0370734", "3925841d02dc09fbdc118597196a0b32"),
    ("6bc1bee22e409f96e93d7e117393172a", "3ad77bb40d7a3660a89ecaf32466ef97"),
    ("ae2d8a571e03ac9c9eb76fac45af8e51", "f5d3d58503b9699de785895a96fdbaaf"),
    ("30c81c46a35ce411e5fbc1191a0a52ef", "43b1cd7f598ece23881b00e3ed030688"),
    ("f69f2445df4f9b17ad2b417be66c3710", "7b0c785e27e8ad3f8223207104725dd4"),
])
def test_additional_nist_vectors(plaintext, ciphertext):
    # FIPS 197 Appendix A.1 round keys; Appendix B and SP 800-38A F.1 inputs.
    keys = [bytes.fromhex(value) for value in (
        "2b7e151628aed2a6abf7158809cf4f3c",
        "a0fafe1788542cb123a339392a6c7605",
        "f2c295f27a96b9435935807a7359f67f",
        "3d80477d4716fe3e1e237e446d7a883b",
        "ef44a541a8525b7fb671253bdb0bad00",
        "d4d1c6f87c839d87caf2b8bc11f915bc",
        "6d88a37a110b3efddbf98641ca0093fd",
        "4e54f70e5f5fc9f384a64fb24ea6dc4f",
        "ead27321b58dbad2312bf5607f8d292f",
        "ac7766f319fadc2128d12941575c006e",
        "d014f9a8c9ee2589e13f0cc8b6630ca6",
    )]
    assert encrypt_block(bytes.fromhex(plaintext), keys).hex() == ciphertext


def test_known_answer():
    assert encrypt_block(PLAINTEXT, round_keys) == CIPHERTEXT


def test_column_major_state():
    state = bytes_to_state(PLAINTEXT)
    assert state == [
        [0x00, 0x44, 0x88, 0xcc],
        [0x11, 0x55, 0x99, 0xdd],
        [0x22, 0x66, 0xaa, 0xee],
        [0x33, 0x77, 0xbb, 0xff],
    ]
    assert state_to_bytes(state) == PLAINTEXT


def test_round_trace_and_intermediate_values():
    events = []
    encrypt_block(PLAINTEXT, round_keys, lambda r, s, v: events.append((r, s, state_to_bytes(v).hex())))
    assert [(r, s) for r, s, _ in events] == (
        [(0, "AddRoundKey")]
        + [(r, s) for r in range(1, 10) for s in ("SubBytes", "ShiftRows", "MixColumns", "AddRoundKey")]
        + [(10, s) for s in ("SubBytes", "ShiftRows", "AddRoundKey")]
    )
    assert [v for _, _, v in events[:5]] == [
        "00102030405060708090a0b0c0d0e0f0",
        "63cab7040953d051cd60e0e7ba70e18c",
        "6353e08c0960e104cd70b751bacad0e7",
        "5f72641557f5bc92f7be3b291db9f91a",
        "89d810e8855ace682d1843d8cb128fe4",
    ]
    assert events[-1][2] == CIPHERTEXT.hex()


def test_callback_cannot_mutate_encryption_or_keys():
    original_keys = round_keys.copy()

    def mutate_trace(round_number, stage, state):
        state[0][0] = 0
        state.clear()

    assert encrypt_block(PLAINTEXT, round_keys, mutate_trace) == CIPHERTEXT
    assert round_keys == original_keys


@pytest.mark.parametrize("plaintext", [b"", bytes(15), bytes(17), "x" * 16, bytearray(16)])
def test_invalid_plaintext(plaintext):
    with pytest.raises(ValueError):
        encrypt_block(plaintext, round_keys)


@pytest.mark.parametrize("keys", [[], round_keys[:10], round_keys + [bytes(16)],
                                  [bytes(15)] * 11, [bytes(17)] * 11, ["x" * 16] * 11])
def test_invalid_round_keys(keys):
    with pytest.raises(ValueError):
        encrypt_block(PLAINTEXT, keys)
