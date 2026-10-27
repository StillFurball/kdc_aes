from aes import AES
from decrypt import decrypt
from encrypt import encrypt
from gcm import AuthenticationError

h = bytes.fromhex

AES_VECTORS = [
    ("000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"),
    ("000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191"),
    ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "8ea2b7ca516745bfeafc49904b496089"),
]

GCM_KEY = "feffe9928665731c6d6a8f9467308308"
GCM_NONCE = "cafebabefacedbaddecaf888"
GCM_PLAINTEXT = (
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
    "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255"
)
GCM_CIPHERTEXT = (
    "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
    "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985"
)
GCM_AAD = "feedfacedeadbeeffeedfacedeadbeefabaddad2"

GCM_VECTORS = [
    ("00" * 16, "00" * 12, "", "", "", "58e2fccefa7e3061367f1d57a4e7455a"),
    ("00" * 16, "00" * 12, "00" * 16, "", "0388dace60b6a392f328c2b971b2fe78", "ab6e47d42cec13bdf53a67b21257bddf"),
    (GCM_KEY, GCM_NONCE, GCM_PLAINTEXT, "", GCM_CIPHERTEXT, "4d5c2af327cd64a62cf35abd2ba6fab4"),
    (GCM_KEY, GCM_NONCE, GCM_PLAINTEXT[:120], GCM_AAD, GCM_CIPHERTEXT[:120], "5bc94fbc3221a5db94fae95ae7121a47"),
]


def test_aes_block():
    for key, expected in AES_VECTORS:
        result = AES(h(key)).encrypt_block(h("00112233445566778899aabbccddeeff"))
        assert result.hex() == expected, key
    print("AES-128/192/256 block (FIPS-197): OK")


def test_gcm():
    for key, nonce, plaintext, aad, expected_ct, expected_tag in GCM_VECTORS:
        ciphertext, tag = encrypt(h(key), h(nonce), h(plaintext), h(aad))
        assert ciphertext.hex() == expected_ct
        assert tag.hex() == expected_tag
        assert decrypt(h(key), h(nonce), ciphertext, tag, h(aad)) == h(plaintext)
    print("AES-GCM encrypt/decrypt (NIST GCM spec): OK")


def test_tampering_detected():
    key, nonce = b"sixteen byte key", b"twelve bytes"
    ciphertext, tag = encrypt(key, nonce, b"attack at dawn")
    tampered = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
    for args in [(key, nonce, tampered, tag), (b"another key 16 b", nonce, ciphertext, tag)]:
        try:
            decrypt(*args)
        except AuthenticationError:
            continue
        raise AssertionError("tampering was not detected")
    print("Tampered ciphertext / wrong key rejected: OK")


if __name__ == "__main__":
    test_aes_block()
    test_gcm()
    test_tampering_detected()
