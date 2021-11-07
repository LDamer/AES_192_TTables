# AES-192 implementation

# AES S-Box
sbox = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82,
        0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
        0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96,
        0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
        0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb,
        0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
        0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff,
        0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32,
        0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
        0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6,
        0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
        0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e,
        0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
        0xb0, 0x54, 0xbb, 0x16]

# AES round constant
rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

######################################
############# code ###################

def precompute_t_tables(t_tables):

    for i in range(256):
        # implementation of the given formula for the T-Tables

        # t_table[0]

        first_row = sbox[i] << 1 if sbox[i] < 128 else sbox[i] << 1 ^ 0x11B

        # if S-Box[i] is greater than 128 the first bit is a 1 and we have to use modulo reduction
        # after multiplying with 2(or shifting by 1 to the left). In this case the modulo reduction is the same as
        # XOR with 0x11B(irreducible polynomial in AES)

        second_row = sbox[i]

        third_row = second_row

        fourth_row = sbox[i] << 1 ^ sbox[i] if sbox[i] < 128 else sbox[i] << 1 ^ sbox[i] ^ 0x11B

        # same as first row.
        # just instead of multiplying by 0x02 we have to multiply by 0x03, which is the same as multiplying by 0x02 and
        # adding the value again to it.(03 * a = 02*a + a = a << 1 ^ a)

        res = 0b0 ^ first_row << 24 ^ second_row << 16 ^ third_row << 8 ^ fourth_row
        t_tables[0][i] = res

        # following is the same as t_table[0], just shorter and using the values calculated for t_tables[0]

        # t_tables[1]

        second_row = first_row
        first_row = fourth_row
        fourth_row = third_row

        res = 0b0 ^ first_row << 24 ^ second_row << 16 ^ third_row << 8 ^ fourth_row
        t_tables[1][i] = res

        # t_tables[2]

        third_row = second_row
        second_row = first_row
        first_row = fourth_row

        res = 0b0 ^ first_row << 24 ^ second_row << 16 ^ third_row << 8 ^ fourth_row
        t_tables[2][i] = res

        # t_tables[3]

        fourth_row = third_row
        third_row = second_row
        second_row = first_row

        res = 0b0 ^ first_row << 24 ^ second_row << 16 ^ third_row << 8 ^ fourth_row
        t_tables[3][i] = res


def add_roundkey(state, roundkey):
    # trivial
    for i in range(16):
        state[i] ^= roundkey[i]


def enc_round(t_tables, state, roundkey):
    res = [0, 0, 0, 0]  # results for C0 - C15 before key-addition-layer and after mix-column-layer
    # res[0] holds 32-bit, describing C0-C3....res[1] holds 32-bit, describing C4-C7 ...

    # C0 - C3 after mix-columns layer with help of T-Tables
    res[0] ^= t_tables[0][state[0]] ^ t_tables[1][state[5]] ^ t_tables[2][state[10]] ^ t_tables[3][state[15]]

    # implementation of given formula

    # C4 - C7
    res[1] ^= t_tables[0][state[4]] ^ t_tables[1][state[9]] ^ t_tables[2][state[14]] ^ t_tables[3][state[3]]

    # C8 - C11
    res[2] ^= t_tables[0][state[8]] ^ t_tables[1][state[13]] ^ t_tables[2][state[2]] ^ t_tables[3][state[7]]

    # C12 - C15
    res[3] ^= t_tables[0][state[12]] ^ t_tables[1][state[1]] ^ t_tables[2][state[6]] ^ t_tables[3][state[11]]

    # ----overwriting state with the values after the mix-column-layer, stored in res----
    # state[0] should be the first byte of res[0]
    # state[1] should be the second byte of res[0]
    # state[2] should be the third byte of res[0]
    # ...
    # state[5] should be the second byte of res[1]
    # ...
    # state[15] should be the last byte of res[3]
    for i in range(16):
        state[i] = (res[i // 4] & 256 - 1 << 24 - (i % 4) * 8) >> (3 - (i % 4)) * 8
        # Bit masking

    # ----add round key to complete AES Round----
    add_roundkey(state, roundkey)


def final_enc_round(state, roundkey, ciphertext):
    # ----Byte-substitution-layer----
    state = [sbox[state[i]] for i in range(16)]

    # ----shift-row-layer-----

    # nothing happens with first row

    # second row
    tmp = state[13]
    state[13] = state[1]
    state[1] = state[5]
    tmp2 = state[9]
    state[9] = tmp
    state[5] = tmp2

    # third row
    tmp = state[2]
    state[2] = state[10]
    state[10] = tmp
    tmp = state[6]
    state[6] = state[14]
    state[14] = tmp

    # fourth row
    tmp = state[3]
    state[3] = state[15]
    tmp2 = state[7]
    state[7] = tmp
    tmp = state[11]
    state[11] = tmp2
    state[15] = tmp

    # ----key-addition-layer----
    add_roundkey(state, roundkey)

    # write the state into the ciphertext variable
    for i in range(16):
        ciphertext[i] = state[i]

    return 0 


def encrypt(t_tables, plaintext, roundkeys, ciphertext):
    # ----key-addition-layer before first round----
    add_roundkey(plaintext, roundkeys[0])

    # round 1 to 11
    for i in range(1, 12):
        enc_round(t_tables, plaintext, roundkeys[i])

    # round 12(last round)
    final_enc_round(plaintext, roundkeys[12], ciphertext)


def key_schedule_192(roundkeys, key):
    # ----inner g-function of AES key-schedule----
    def g(val, r):
        # write val byte wise in list b using bit masking.
        # b = [first byte, second byte, thrid byte, fourth byte]
        b = [sbox[(val & (256 - 1 << (16 - j * 8))) >> (2 - j) * 8] for j in range(0, 3)]
        b.append(sbox[(val & (256 - 1 << 24)) >> 24])
        b[0] ^= r

        # return 32-bit as integer value, prepared for the xor in the key-schedule
        return 0 ^ b[0] << 24 ^ b[1] << 16 ^ b[2] << 8 ^ b[3]

    w = []  # prepare the word list of AES-192-key-schedule

    # compute words 0 - 5 directly from main key using bit masking
    # main key is given as hex list with 24 entries so that one entry holds 8 bit
    for i in range(6):
        # extract the part of the main key(given as list) that is relevant for the current word
        # key_extract then holds a list with 4 entries(4 times 8 bit from main key)
        key_extract = key[i * 4:i * 4 + 4]
        word = 0
        # concatenate the extracted bits from main key to one 32-bit word
        for j in range(4):
            word ^= (key_extract[j] << (24 - j * 8))
        w.append(word)

    # compute words 6 to 51 recursively from words 0-5
    for i in range(6, 52):
        w.append(w[i - 6] ^ g(w[i - 1], rcon[i // 6 - 1]) if i % 6 == 0 else w[i - 6] ^ w[i - 1])

    # extract the 13 round keys from the wordlist
    # put the 16 byte of each round key into a list
    for i in range(13):
        res = [0] * 16  # prepare list with 16 element, for the 16 bytes of each round-key

        # fill the list res with 16 bytes from the 4 added words above stored in rk
        # so put the 128 bits from rk into 16 bytes (16 entries), stored as list in res
        for j in range(16):
            res[j] = (((w[i * 4 + j//4] << (96 - (j//4) * 32))) & (256-1 << 120 - j * 8)) >> 120 - j * 8

        roundkeys[i] = res  # store the list res with 16 entries in the list round-keys





