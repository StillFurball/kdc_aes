from aes import AES
from gcm import AuthenticationError, compute_tag, gctr, inc32, initial_counter, tags_equal


def decrypt(key, nonce, ciphertext, tag, aad=b""):
    cipher = AES(key)
    j0 = initial_counter(nonce)
    expected_tag = compute_tag(cipher, j0, aad, ciphertext)
    if not tags_equal(expected_tag, tag):
        raise AuthenticationError("authentication tag mismatch")
    return gctr(cipher, inc32(j0), ciphertext)
