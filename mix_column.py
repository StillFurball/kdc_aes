def xtime(a):
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a


def mul2(a):
    return xtime(a)


def mul3(a):
    return xtime(a) ^ a


def mix_single_column(column):
    a0, a1, a2, a3 = column
    return [
        mul2(a0) ^ mul3(a1) ^ a2 ^ a3,
        a0 ^ mul2(a1) ^ mul3(a2) ^ a3,
        a0 ^ a1 ^ mul2(a2) ^ mul3(a3),
        mul3(a0) ^ a1 ^ a2 ^ mul2(a3),
    ]


def mix_columns(state):
    result = []
    for c in range(4):
        result += mix_single_column(state[4 * c:4 * c + 4])
    return result
