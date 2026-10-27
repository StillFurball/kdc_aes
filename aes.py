from s_box import SBOX, sub_bytes
from mix_column import mix_columns

RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def sub_word(word):
    return [SBOX[b] for b in word]


def rot_word(word):
    return word[1:] + word[:1]


def key_expansion(key):
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must be 16, 24 or 32 bytes")
    nk = len(key) // 4
    rounds = nk + 6
    words = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    for i in range(nk, 4 * (rounds + 1)):
        temp = list(words[i - 1])
        if i % nk == 0:
            temp = sub_word(rot_word(temp))
            temp[0] ^= RCON[i // nk - 1]
        elif nk == 8 and i % nk == 4:
            temp = sub_word(temp)
        words.append([a ^ b for a, b in zip(words[i - nk], temp)])
    return [sum(words[4 * r:4 * r + 4], []) for r in range(rounds + 1)]


def shift_rows(state):
    return [state[r + 4 * ((c + r) % 4)] for c in range(4) for r in range(4)]


def add_round_key(state, round_key):
    return [s ^ k for s, k in zip(state, round_key)]


class AES:
    def __init__(self, key):
        self.round_keys = key_expansion(key)
        self.rounds = len(self.round_keys) - 1

    def encrypt_block(self, block):
        state = add_round_key(list(block), self.round_keys[0])
        for r in range(1, self.rounds):
            state = sub_bytes(state)
            state = shift_rows(state)
            state = mix_columns(state)
            state = add_round_key(state, self.round_keys[r])
        state = sub_bytes(state)
        state = shift_rows(state)
        state = add_round_key(state, self.round_keys[self.rounds])
        return bytes(state)
