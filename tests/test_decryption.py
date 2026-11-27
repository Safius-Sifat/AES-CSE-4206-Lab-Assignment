"""AES-128 decryption, inverse S-Box, and round-trip integration tests."""

import pytest

from aes.aes_tables import inv_sub_byte, sub_byte
from aes.decryption import decrypt_block
from aes.encryption import encrypt_block
from aes.key_expansion import key_expansion


def test_inv_sub_byte_inverts_sub_byte():
    for value in range(256):
        assert inv_sub_byte(sub_byte(value)) == value
        assert sub_byte(inv_sub_byte(value)) == value


@pytest.mark.parametrize("bad_value", [-1, 256])
def test_inv_sub_byte_out_of_range(bad_value):
    with pytest.raises(ValueError):
        inv_sub_byte(bad_value)


def test_fips_197_appendix_b_decryption():
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    ciphertext = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    expected_plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")

    round_keys = key_expansion(key)
    assert decrypt_block(ciphertext, round_keys) == expected_plaintext


@pytest.mark.parametrize("key_hex, plaintext_hex, ciphertext_hex", [
    (
        "2b7e151628aed2a6abf7158809cf4f3c",
        "3243f6a8885a308d313198a2e0370734",
        "3925841d02dc09fbdc118597196a0b32",
    ),
    (
        "2b7e151628aed2a6abf7158809cf4f3c",
        "6bc1bee22e409f96e93d7e117393172a",
        "3ad77bb40d7a3660a89ecaf32466ef97",
    ),
    (
        "2b7e151628aed2a6abf7158809cf4f3c",
        "ae2d8a571e03ac9c9eb76fac45af8e51",
        "f5d3d58503b9699de785895a96fdbaaf",
    ),
    (
        "2b7e151628aed2a6abf7158809cf4f3c",
        "30c81c46a35ce411e5fbc1191a0a52ef",
        "43b1cd7f598ece23881b00e3ed030688",
    ),
    (
        "2b7e151628aed2a6abf7158809cf4f3c",
        "f69f2445df4f9b17ad2b417be66c3710",
        "7b0c785e27e8ad3f8223207104725dd4",
    ),
])
def test_nist_decryption_and_round_trip(key_hex, plaintext_hex, ciphertext_hex):
    round_keys = key_expansion(bytes.fromhex(key_hex))
    plaintext = bytes.fromhex(plaintext_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)

    assert encrypt_block(plaintext, round_keys) == ciphertext
    assert decrypt_block(ciphertext, round_keys) == plaintext


@pytest.mark.parametrize("bad_block", [b"", bytes(15), bytes(17), "x" * 16, bytearray(16)])
def test_invalid_ciphertext(bad_block):
    round_keys = key_expansion(bytes(16))
    with pytest.raises(ValueError):
        decrypt_block(bad_block, round_keys)


@pytest.mark.parametrize("bad_keys", [
    [],
    [bytes(16)] * 10,
    [bytes(16)] * 12,
    [bytes(15)] * 11,
    ["x" * 16] * 11,
])
def test_invalid_round_keys_decryption(bad_keys):
    with pytest.raises(ValueError):
        decrypt_block(bytes(16), bad_keys)
