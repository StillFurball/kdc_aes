from aes import AES
from gcm import compute_tag, gctr, inc32, initial_counter


def encrypt(key, nonce, plaintext, aad=b""):
    cipher = AES(key)
    j0 = initial_counter(nonce)
    ciphertext = gctr(cipher, inc32(j0), plaintext)
    tag = compute_tag(cipher, j0, aad, ciphertext)
    return ciphertext, tag
