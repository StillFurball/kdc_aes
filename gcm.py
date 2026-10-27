R = 0xE1 << 120


class AuthenticationError(Exception):
    pass


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def gf_mult(x, y):
    z = 0
    v = y
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ R
        else:
            v >>= 1
    return z


def ghash(h, data):
    y = 0
    for i in range(0, len(data), 16):
        y = gf_mult(y ^ int.from_bytes(data[i:i + 16], "big"), h)
    return y.to_bytes(16, "big")


def inc32(block):
    counter = (int.from_bytes(block[12:], "big") + 1) % (1 << 32)
    return block[:12] + counter.to_bytes(4, "big")


def gctr(cipher, counter_block, data):
    output = b""
    for i in range(0, len(data), 16):
        keystream = cipher.encrypt_block(counter_block)
        output += xor_bytes(data[i:i + 16], keystream)
        counter_block = inc32(counter_block)
    return output


def pad16(data):
    return data + b"\x00" * (-len(data) % 16)


def hash_subkey(cipher):
    return int.from_bytes(cipher.encrypt_block(bytes(16)), "big")


def initial_counter(nonce):
    if len(nonce) != 12:
        raise ValueError("GCM nonce must be 12 bytes")
    return nonce + b"\x00\x00\x00\x01"


def compute_tag(cipher, j0, aad, ciphertext):
    lengths = (8 * len(aad)).to_bytes(8, "big") + (8 * len(ciphertext)).to_bytes(8, "big")
    s = ghash(hash_subkey(cipher), pad16(aad) + pad16(ciphertext) + lengths)
    return xor_bytes(s, cipher.encrypt_block(j0))


def tags_equal(a, b):
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0
