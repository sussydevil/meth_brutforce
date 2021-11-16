import datetime
import hashlib
import csv
import hmac
import struct
import sys
import multiprocessing
import time
from ecdsa.curves import SECP256k1
from eth_utils import to_checksum_address, keccak as eth_utils_keccak
from termcolor import colored
import colorama
import os


words_list = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11"]

eth_address = "0x43fD8989f433ea98C988059F5635418106aFE6B3"


class PublicKey:
    def __init__(self, private_key):
        self.point = int.from_bytes(private_key, byteorder='big') * SECP256k1.generator

    def __bytes__(self):
        xstr = self.point.x().to_bytes(32, byteorder='big')
        parity = self.point.y() & 1
        return (2 + parity).to_bytes(1, byteorder='big') + xstr

    def address(self):
        x = self.point.x()
        y = self.point.y()
        s = x.to_bytes(32, 'big') + y.to_bytes(32, 'big')
        return to_checksum_address(eth_utils_keccak(s)[12:])


def mnemonic_to_bip39seed(mnemonic):
    mnemonic = bytes(mnemonic, 'utf8')
    return hashlib.pbkdf2_hmac('sha512', mnemonic, b'mnemonic', 2048)


def bip39seed_to_bip32masternode(seed):
    h = hmac.new(b'Bitcoin seed', seed, hashlib.sha512).digest()
    key, chain_code = h[:32], h[32:]
    return key, chain_code


def derive_bip32childkey(parent_key, parent_chain_code, i):
    k = parent_chain_code
    if (i & 0x80000000) != 0:
        key = b'\x00' + parent_key
    else:
        key = bytes(PublicKey(parent_key))
    d = key + struct.pack('>L', i)
    while True:
        h = hmac.new(k, d, hashlib.sha512).digest()
        key, chain_code = h[:32], h[32:]
        a = int.from_bytes(key, byteorder='big')
        b = int.from_bytes(parent_key, byteorder='big')
        key = (a + b) % SECP256k1.order
        if a < SECP256k1.order and key != 0:
            key = key.to_bytes(32, byteorder='big')
            break
        d = b'\x01' + h[32:] + struct.pack('>L', i)
    return key, chain_code


def mnemonic_to_private_key(mnemonic):
    derivation_path = [2147483692, 2147483708, 2147483648, 0, 0]
    bip39seed = mnemonic_to_bip39seed(mnemonic)
    master_private_key, master_chain_code = bip39seed_to_bip32masternode(bip39seed)
    private_key, chain_code = master_private_key, master_chain_code
    for i in derivation_path:
        private_key, chain_code = derive_bip32childkey(private_key, chain_code, i)
    return private_key


def cls():
    os.system(['clear', 'cls'][os.name == 'nt'])


def processor():
    words_list_len = len(words_list)
    location = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    print("{0} processes will be generated.".format(words_list_len ** 2))
    print("{0} processes will be stopped.".format(words_list_len ** 2 - words_list_len * (words_list_len - 1)))
    time.sleep(5)
    for i in range(words_list_len ** 2):
        print(colored("Process {0} is started at location: {1}.".format(i, location), "green"))
        p = multiprocessing.Process(target=generator_eth, args=(location, words_list_len, i,))
        p.start()
        if location[1] < words_list_len - 1:
            location[1] = location[1] + 1
        else:
            location[0] = location[0] + 1
            location[1] = 0


def generator_eth(location, words_list_len, process_number):
    print(colored('{0} process - generation started!'.format(process_number), 'yellow'))
    i = 0
    o = location[0]
    p = location[1]
    q = location[2]
    r = location[3]
    s = location[4]
    t = location[5]
    u = location[6]
    v = location[7]
    w = location[8]
    x = location[9]
    y = location[10]
    z = location[11]
    while o < words_list_len:
        while p < words_list_len:
            if p == o:
                p += 1
                print(colored("Work is done. Exit.", "yellow"))
                exit()
            while q < words_list_len:
                if q in (p, o):
                    q += 1
                    continue
                while r < words_list_len:
                    if r in (q, p, o):
                        r += 1
                        continue
                    while s < words_list_len:
                        if s in (r, q, p, o):
                            s += 1
                            continue
                        while t < words_list_len:
                            if t in (s, r, q, p, o):
                                t += 1
                                continue
                            while u < words_list_len:
                                if u in (t, s, r, q, p, o):
                                    u += 1
                                    continue
                                while v < words_list_len:
                                    if v in (u, t, s, r, q, p, o):
                                        v += 1
                                        continue
                                    while w < words_list_len:
                                        if w in (v, u, t, s, r, q, p, o):
                                            w += 1
                                            continue
                                        while x < words_list_len:
                                            if x in (w, v, u, t, s, r, q, p, o):
                                                x += 1
                                                continue
                                            while y < words_list_len:
                                                if y in (x, w, v, u, t, s, r, q, p, o):
                                                    y += 1
                                                    continue
                                                while z < words_list_len:
                                                    if z in (y, x, w, v, u, t, s, r, q, p, o):
                                                        z += 1
                                                        continue
                                                    mnemonic = words_list[o] + " " + words_list[p] + " " + \
                                                               words_list[q] + " " + words_list[r] + " " + \
                                                               words_list[s] + " " + words_list[t] + " " + \
                                                               words_list[u] + " " + words_list[v] + " " + \
                                                               words_list[w] + " " + words_list[x] + " " + \
                                                               words_list[y] + " " + words_list[z]
                                                    private_key = mnemonic_to_private_key(mnemonic)
                                                    public_key = PublicKey(private_key)
                                                    if eth_address == public_key.address():
                                                        with open('found_{0}.csv'.format(process_number), 'w') as f:
                                                            writer = csv.writer(f)
                                                            data = [eth_address, mnemonic]
                                                            writer.writerow(data)
                                                            f.close()
                                                        print("Found address: " + eth_address + " " + mnemonic)
                                                        sys.stdout.write("\a")
                                                        time.sleep(1)
                                                    i += 1
                                                    if i % 8192 == 0:
                                                        print(datetime.datetime.now().strftime('%H:%M:%S') + ' - ' +
                                                              colored("{0} addresses generated & checked; {1} process.",
                                                                      'green').format(i, process_number))
                                                    break
                                                y += 1
                                                z = 0
                                            x += 1
                                            y = 0
                                        w += 1
                                        x = 0
                                    v += 1
                                    w = 0
                                u += 1
                                v = 0
                            t += 1
                            u = 0
                        s += 1
                        t = 0
                    r += 1
                    s = 0
                q += 1
                r = 0
            p += 1
            q = 0
            print("Work is done. Exit.")
            exit()
        o += 1
        p = 0

    print(colored('Work is done. Exit.', 'green'))
    exit()


def main():
    cls()
    colorama.init()
    print(colored('Monster ETH bruteforce generator 2021.05.03 is starting...', 'cyan'))
    time.sleep(5)
    cls()
    processor()


if __name__ == '__main__':
    main()
