def xor(a, b):
    assert len(a) == len(b), "Can't perform xor for two vectors with different length!"
    res = []
    for i in range(len(a)):
        res.append(a[i] ^ b[i])
    return res


def left_shift(src, i):
    return src[i:] + src[:i]
