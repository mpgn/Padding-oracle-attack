#! /usr/bin/python

"""
    Padding Oracle Attack implementation without remote server
    Check the readme for a full cryptographic explanation
    Author: mpgn <martial.puygrenier@gmail.com>
    Date: 2016
"""

import argparse
import re
import sys
import time
from itertools import cycle
from Cryptodome.Cipher import AES

"""
    AES-CBC
    function encrypt, decrypt, pad, unpad)
"""


def pad(s):
    pad_byte = 16 - len(s) % 16
    for i in range(pad_byte):
        s.append(pad_byte)
    return s


def unpad(s):
    exe = re.findall("..", s.hex())
    padding = int(exe[-1], 16)
    exe = exe[::-1]

    if padding == 0 or padding > 16:
        return 0

    for i in range(padding):
        if int(exe[i], 16) != padding:
            return 0
    return s[: -ord(s[len(s) - 1 :])]


def encrypt(msg, iv):
    raw = pad(msg)
    cipher = AES.new(b"V38lKILOJmtpQMHp", AES.MODE_CBC, iv)
    return cipher.encrypt(raw), iv


def decrypt(enc, iv):
    decipher = AES.new(b"V38lKILOJmtpQMHp", AES.MODE_CBC, iv)
    return unpad(decipher.decrypt(enc))


""" The function you want change to adapt the result to your problem """


def test_validity(error):
    if error != 404:
        return 1
    return 0


def call_oracle(up_cipher, iv):
    if decrypt(bytes.fromhex(up_cipher), iv) == 0:
        return 404
    return 200


""" Create custom block for the byte we search"""


def block_search_byte(size_block, i, pos, l):
    hex_char = hex(pos).split("0x")[1]
    return (
        "00" * (size_block - (i + 1))
        + ("0" if len(hex_char) % 2 != 0 else "")
        + hex_char
        + "".join(l)
    )


""" Create custom block for the padding"""


def block_padding(size_block, i):
    l = []
    for t in range(0, i + 1):
        l.append(
            ("0" if len(hex(i + 1).split("0x")[1]) % 2 != 0 else "")
            + (hex(i + 1).split("0x")[1])
        )
    return "00" * (size_block - (i + 1)) + "".join(l)


def split_len(seq, length):
    return [seq[i : i + length] for i in range(0, len(seq), length)]


def hex_xor(s1, s2):
    b = bytearray()
    for c1, c2 in zip(bytes.fromhex(s1), cycle(bytes.fromhex(s2))):
        b.append(c1 ^ c2)
    return b.hex()


def run(cipher, size_block):
    cipher = cipher.upper()
    found = False
    valide_value = []
    result = []
    len_block = size_block * 2
    cipher_block = split_len(cipher, len_block)

    if len(cipher_block) == 1:
        print(
            "[-] Abort there is only one block. I can't influence the IV. Try a longer message."
        )
        sys.exit()

    # for each cipher_block
    for block in reversed(range(1, len(cipher_block))):
        if len(cipher_block[block]) != len_block:
            print("[-] Abort length block doesn't match the size_block")
            break
        print("[+] Search value block : ", block, "\n")
        # for each byte of the block
        for i in range(0, size_block):
            # test each byte max 255
            for ct_pos in range(0, 256):
                # 1 xor 1 = 0 or valide padding need to be checked
                if ct_pos != i + 1 or (
                    len(valide_value) > 0 and int(valide_value[-1], 16) == ct_pos
                ):
                    bk = block_search_byte(size_block, i, ct_pos, valide_value)
                    bp = cipher_block[block - 1]
                    bc = block_padding(size_block, i)

                    tmp = hex_xor(bk, bp)
                    cb = hex_xor(tmp, bc).upper()

                    up_cipher = cb + cipher_block[block]
                    # time.sleep(0.5)

                    # we call the oracle, our god
                    error = call_oracle(up_cipher, iv)

                    if args.verbose == True:
                        exe = re.findall("..", cb)
                        discover = ("").join(exe[size_block - i : size_block])
                        current = ("").join(exe[size_block - i - 1 : size_block - i])
                        find_me = ("").join(exe[: -i - 1])

                        sys.stdout.write(
                            "\r[+] Test [Byte %03i/256 - Block %d ]: \033[31m%s\033[33m%s\033[36m%s\033[0m"
                            % (ct_pos, block, find_me, current, discover)
                        )
                        sys.stdout.flush()

                    if test_validity(error):

                        found = True

                        # data analyse and insert in rigth order
                        value = re.findall("..", bk)
                        valide_value.insert(0, value[size_block - (i + 1)])

                        if args.verbose == True:
                            print("")
                            print("[+] Block M_Byte : %s" % bk)
                            print("[+] Block C_{i-1}: %s" % bp)
                            print("[+] Block Padding: %s" % bc)
                            print("")

                        bytes_found = "".join(valide_value)
                        if (
                            i == 0
                            and int(bytes_found, 16) > size_block
                            and block == len(cipher_block) - 1
                        ):
                            print(
                                "[-] Error decryption failed the padding is > "
                                + str(size_block)
                            )
                            sys.exit()

                        print(
                            "\033[36m" + "\033[1m" + "[+]" + "\033[0m" + " Found",
                            i + 1,
                            "bytes :",
                            bytes_found,
                        )
                        print("")

                        break
            if found == False:
                # lets say padding is 01 for the last block (the padding block)
                if len(cipher_block) - 1 == block and i == 0:
                    value = re.findall("..", bk)
                    valide_value.insert(0, "01")
                    if args.verbose == True:
                        print("")
                        print(
                            "[-] No padding found, but maybe the padding is length 01 :)"
                        )
                        print("[+] Block M_Byte : %s" % bk)
                        print("[+] Block C_{i-1}: %s" % bp)
                        print("[+] Block Padding: %s" % bc)
                        print("")
                        bytes_found = "".join(valide_value)
                else:
                    print("\n[-] Error decryption failed")
                    result.insert(0, "".join(valide_value))
                    hex_r = "".join(result)
                    if len(hex_r) > 0:
                        print("[+] Partial Decrypted value (HEX):", hex_r.upper())
                        padding = int(hex_r[len(hex_r) - 2 : len(hex_r)], 16)
                        print(
                            "[+] Partial Decrypted value (ASCII):",
                            bytes.fromhex(hex_r[0 : -(padding * 2)]).decode(),
                        )
                    sys.exit()
            found = False

        result.insert(0, "".join(valide_value))
        valide_value = []

    print("")
    hex_r = "".join(result)
    print("[+] Decrypted value (HEX):", hex_r.upper())
    padding = int(hex_r[len(hex_r) - 2 : len(hex_r)], 16)
    decoded = bytes.fromhex(hex_r[0 : -(padding * 2)]).decode()
    print("[+] Decrypted value (ASCII):", decoded)

    return decoded


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Exploit of Padding Oracle Attack")
    parser.add_argument("-m", "--message", required=True, help="message to pown")
    parser.add_argument(
        "-v",
        "--verbose",
        help="debug mode, you need a large screen",
        action="store_true",
    )
    args = parser.parse_args()

    print("[+] Encrypt", args.message)
    cipher, iv = encrypt(bytearray(args.message, "UTF-8"), b"1234567812345678")
    print("[+] %s ---> %s" % (args.message, cipher.hex()))
    plaintext = decrypt(cipher, iv)

    run(cipher.hex(), 16)
