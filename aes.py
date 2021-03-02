from rule.aes_rule import *
from util import *


def get_input():
    lines = open('input/aes_input', 'r').readlines()
    arr1 = [lines[0].strip()[i:i + 8] for i in range(0, 128, 8)]
    assert len(arr1) == 16, "plaintext should have 16 byte"
    plaintext = [int(x, 2) for x in arr1]
    arr2 = [lines[1].strip()[i:i + 8] for i in range(0, 128, 8)]
    assert len(arr2) == 16, "key should have 16 byte"
    key = [int(x, 2) for x in arr2]
    return plaintext, key


def s_permutation(src, S):
    res = []
    for i in src:
        row = (i & 0xf0) >> 4
        col = i & 0x0f
        res.append(S[16 * row + col])

    return res


def T(src, rcon):
    # 1. 字循环
    res1 = left_shift(src, 1)
    # 2. 字节代换
    res2 = s_permutation(res1, S)
    # 3. 轮常量异或
    res3 = xor(res2, rcon)
    return res3


def generate_subkeys(key):
    W = []
    W.extend([key[i:i + 4] for i in range(0, len(key), 4)])
    for i in range(4, 44):
        if i % 4 == 0:
            W.append(xor(W[i - 4], T(W[i - 1], Rcon[i // 4 - 1])))
        else:
            W.append(xor(W[i - 4], W[i - 1]))
    assert len(W) == 44, "subkeys should hava 44 items"
    return W


def row_shift(src):
    res2 = []
    for i in range(0, 4):
        tmp = []
        for j in range(0, 4):
            tmp.append(src[i + 4 * j])
        res2.extend(left_shift(tmp, i // 4))
    return res2


def xtime(a, count):
    for i in range(0, count):
        if a >> 7 == 1:
            a = (0xff & (a << 1)) ^ 0x1b
        else:
            a = a << 1
    return a


def GF2multi(a, b):
    index_of_1_list = []  # 获得所有位数为1的下标
    count = 0
    while b != 0:
        if b & 0x1 == 1:
            index_of_1_list.append(count)
        count += 1
        b = b >> 1
    xtime_result_list = []
    for i in index_of_1_list:
        xtime_result_list.append(xtime(a, i))

    res = xtime_result_list[0]
    for i in range(1, len(xtime_result_list)):
        res = res ^ xtime_result_list[i]
    return res


def column_mix(src):
    res = []
    for i in range(len(src)):
        row = i % 4
        col = i // 4
        tmp = GF2multi(Matrix[row][0], src[col * 4])
        for j in range(1, 4):
            tmp = tmp ^ GF2multi(Matrix[row][j], src[col * 4 + j])
        res.append(tmp)
    return res


def add_round_key(src, W):
    res = []
    for i in range(0, len(src), 4):
        res.extend(xor(src[i:i + 4], W[i // 4]))
    return res


def iterate(src, W):
    res = 0
    for i in range(0, 10):
        # 1. 字节替换
        res = s_permutation(src, S)
        # 2. 行移位
        res = row_shift(res)
        # 3. 列混合
        if i != 9:
            res = column_mix(res)
        # 4. 轮密钥加
        res = add_round_key(res, W[(i + 1) * 4: (i + 2) * 4])

    return res


def display(ciphertext):
    lines = open('input/aes_input', 'r').readlines()
    print('plaintext:')
    print(lines[0].strip())
    print('key:')
    print(lines[1].strip())
    print('ciphertext:')
    res = []
    for i in ciphertext:
        binstr = bin(i).replace('0b', '')
        res.append('0' * (8 - len(binstr)) + binstr)
    print(''.join(res))


def aes_encipher(plaintext, key):
    # 1. 初始异或
    res1 = xor(plaintext, key)
    # 2. 生成子密钥
    W = generate_subkeys(key)
    # 3. 进行迭代
    res = iterate(res1, W)

    return res


if __name__ == '__main__':
    plaintext, key = get_input()
    ciphertext = aes_encipher(plaintext, key)
    display(ciphertext)
