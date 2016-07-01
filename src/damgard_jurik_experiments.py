import damgard_jurik
import random
from timeit import Timer
import os.path
import json


def get_data(identifier, function):
    if os.path.isfile(identifier + '.json'):
        with open(identifier + '.json', 'r') as data_file:
            return eval(json.load(data_file))
    else:
        data = function()
        with open(identifier + '.json', 'w') as data_file:
            json.dump(str(data), data_file)
        return data


def test_encrypt_decrypt():
    log_ns = range(8, 11 + 1)
    ss = range(1, 6)
    repetitions = 10

    data = {}

    for log_n in log_ns:
        public, private = damgard_jurik.generate_keypair(2 ** log_n, 1)
        for s in ss:
            plaintext = random.getrandbits(public.bits) % public.n
            ciphertext = damgard_jurik.encrypt(public, s, plaintext)
            t = Timer(lambda: damgard_jurik.encrypt(public, s, plaintext))
            to_encrypt = t.timeit(number=repetitions) / repetitions

            t = Timer(lambda: damgard_jurik.decrypt(public, private, s, ciphertext))
            to_decrypt = t.timeit(number=repetitions) / repetitions

            data[(log_n, s)] = (to_encrypt, to_decrypt)
    print data
    return data


def test_modular_exponentiation():
#    log_ns = range(9, 18 + 1)
    for bits in [11136, 15872, 23552, 32768]:
#        public, private = damgard_jurik.generate_keypair(2 ** log_n, 1)
        n = random.getrandbits(bits)
        plaintext = random.getrandbits(bits) % n
        t = Timer(lambda: damgard_jurik.modpow(plaintext, n - 1, n))
        time = t.timeit(number=1)
        print time
#        x = bits ** 2.58
#          if log_n >= 14:
#        print x
#        else:
#            print x, time



def print_encrypt_decrypt_latex():
    encrypt_decrypt_data = get_data('encrypt_decrypt_time', test_encrypt_decrypt)
    log_ns = range(8, 11 + 1)
    ss = range(1, 6)

    for piece in [0, 1]:
        for log_n in log_ns:
            data = []
            for s in ss:
                data.append(encrypt_decrypt_data[(log_n, s)][piece])
            print " & ".join([str.format('{0:.6f}', x) for x in data])
        print "-------"

#print_encrypt_decrypt_latex()
test_modular_exponentiation()
