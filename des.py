from rule.des_rule import *
from util import *


# Press the green button in the gutter to run the script.
def get_input():
    f = open('input/des_input', 'r')
    lines = f.readlines()
    plaintext = list(map(int, list(lines[0].strip())))
    key = list(map(int, list(lines[0].strip())))
    return plaintext, key


def permutation(src, rule):
    # src：置换源向量
    # rule：置换规则向量, rule[i]的值val表示将src[val]移到输出的第i位
    res = []
    for i in rule:
        res.append(src[i - 1])
    return res


def initial_permutation(plaintext, IP):
    res = permutation(plaintext, IP)
    return res[:32], res[32:]


def generate_subkeys(key, PC_1, PC_2, shift):
    res = []
    key_48 = permutation(key, PC_1)
    C = key_48[:28]
    D = key_48[28:]
    for i in range(16):
        C_i = left_shift(C, shift[i])
        D_i = left_shift(D, shift[i])
        key_48 = permutation(C_i + D_i, PC_2)
        res.append(key_48)
        C = C_i
        D = D_i
    return res


def s_match(src, S):
    row = int(str(src[0]) + str(src[5]), 2)
    col = int(''.join([str(i) for i in src[1:5]]), 2)
    target = [int(i) for i in list(bin(S[row * 16 + col])[2:])]
    return [0] * (4 - len(target)) + target


def s_permutation(src, S):
    assert len(src) == 48, "The length of s_permutation input should be 48!"
    fragments = []
    for i in range(0, len(src), 6):
        fragments.append(src[i:i + 6])
    new_fragments = []
    for i in range(len(fragments)):
        fragment = s_match(fragments[i], S[i])
        new_fragments.extend(fragment)
    assert len(new_fragments) == 32, "The length of s_permutation output should be 32, but it's {} now!".format(
        len(new_fragments))
    return new_fragments


def iterative(L0, R0, sub_keys, E, S, P):
    # Ln = R(n - 1)；
    # Rn = L(n - 1)⊕f(Rn - 1, kn - 1)
    L = L0
    R = R0
    for i in range(16):
        L_i = R
        e_res = permutation(R, E)
        s_res = s_permutation(xor(e_res, sub_keys[i]), S)
        p_res = permutation(s_res, P)
        R = xor(L, p_res)
        L = L_i
    return L + R


def des_encipher(plaintext, key):
    # 1. 初始置换
    L0, R0 = initial_permutation(plaintext, IP)
    # 2. 生成子密钥
    sub_keys = generate_subkeys(key, PC_1, PC_2, shift)
    # 3. 进行迭代
    res = iterative(L0, R0, sub_keys, E, S, P)
    # 4. 逆置换
    return permutation(res, R)


def display(ciphertext):
    lines = open('input/des_input', 'r').readlines()
    print('plaintext:')
    print(lines[0].strip())
    print('key:')
    print(lines[1].strip())
    print('ciphertext')
    print(''.join([str(i) for i in ciphertext]))


if __name__ == '__main__':
    plaintext, key = get_input()
    ciphertext = des_encipher(plaintext, key)
    display(ciphertext)
