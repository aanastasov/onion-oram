import math
import random
import primes


def gcd(a, b):
    while a > 0 and b > 0:
        (a, b) = (a % b, b) if a >= b else (a, b % a)
    return a + b


def lcm(a, b):
    return (a / gcd(a, b)) * b


def modpow(base, exponent, modulus):
    """Modular exponent:
         c = b ^ e mod m
       Returns c.
       (http://www.programmish.com/?p=34)"""
    result = 1
    while exponent > 0:
        if exponent & 1 == 1:
            result = (result * base) % modulus
        exponent = exponent >> 1
        base = (base * base) % modulus
    return result


def modinv(a, b):
    b0 = b
    x0, x1 = 0, 1
    if b == 1:
        return 1
    while a > 1:
        q = a / b
        a, b = b, a % b
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += b0
    return x1


def chinese_remainder(mods, remainders):
    prod = reduce(lambda x, y: x * y, mods)
    res = 0
    for i in range(len(mods)):
        p = prod / mods[i]
        res += remainders[i] * modinv(p, mods[i]) * p
    return res % prod


class PublicKey(object):
    def __init__(self, n, s):
        self.n = n
        self.s = s
        self.cache_n_pow = [1, n]
        self.cache_invfact = {}
        self.bits = long(math.ceil(math.log(n, 2)))

    def get_npows(self, i):
        if i < len(self.cache_n_pow):
            return self.cache_n_pow[i]
        while i >= len(self.cache_n_pow):
            self.cache_n_pow.append(self.cache_n_pow[-1] * self.n)
        return self.cache_n_pow[i]

    def get_invfact(self, i, j):
        if (i, j) in self.cache_invfact:
            return self.cache_invfact[(i, j)]
        fact = reduce(lambda x, y: x * y, range(1, i + 1))
        res = modinv(fact, self.get_npows(j))
        self.cache_invfact[(i, j)] = res
        return res


class PrivateKey(object):
    def __init__(self, n, p, q, s):
        self.n = n
        self.p = p
        self.q = q
        self.cache_d = {}

    def get_d(self, s):
        if s in self.cache_d:
            return self.cache_d[s]
        lambda_ = lcm(self.p - 1, self.q - 1)
        self.cache_d[s] = chinese_remainder([self.n ** s, lambda_], [1, 0])
        return self.cache_d[s]


def generate_keypair(bits, s):
    p = primes.generate_prime(bits / 2)
    q = primes.generate_prime(bits / 2)
    n = p * q
    return PublicKey(n, s), PrivateKey(n, p, q, s)


def encrypt(pub, s, plaintext):
    m = plaintext
    g = pub.n + 1

    r = random.getrandbits(pub.bits) % pub.get_npows(s + 1)

    # TODO(aanastasov): This has to be removed, because p and q should be
    # chosen so big that this is impractical: if we can factor n, then we
    # can break the security of the cryptosystem. However, we are keeping
    # it here to ensure that the cryptosystem doesn't give wrong results
    # when testing with small p and q.
    while gcd(r, pub.get_npows(s + 1)) != 1:
        r = random.getrandbits(pub.bits) % pub.get_npows(s + 1)

    g_pow_m = modpow(g, m, pub.get_npows(s + 1))
    r_pow__n_pow_s = modpow(r, pub.get_npows(s), pub.get_npows(s + 1))
    return (g_pow_m * r_pow__n_pow_s) % pub.get_npows(s + 1)


def decrypt(pub, private, s, ciphertext):
    c = ciphertext
    n = pub.n

    def l(u):
        return 0 if u == 0 else (u - 1) / n

    m = 0
    c_pow_d = modpow(c, private.get_d(s), pub.get_npows(s + 1))
    for j in range(1, s + 1):
        new_m = l(c_pow_d % pub.get_npows(j + 1))
        old_m = m
        for k in range(2, j + 1):
            m = (m - 1 + pub.get_npows(j)) % pub.get_npows(j)
            old_m = (old_m * m) % pub.get_npows(j)
            term = (old_m * pub.get_npows(k - 1)) % pub.get_npows(j)
            term = (term * pub.get_invfact(k, j)) % pub.get_npows(j)
            new_m = (new_m - term + pub.get_npows(j)) % pub.get_npows(j)
        m = new_m
    return m


class Payload(object):
    def __init__(self, payload, public_key,
                 plaintext_space, current_space):
        self.payload = payload
        self.public_key = public_key
        self.plaintext_space = plaintext_space
        self.current_space = current_space

    def lift_once(self):
        encrypted = encrypt(self.public_key,
                            self.current_space, self.payload)
        return Payload(encrypted, self.public_key,
                       self.plaintext_space, self.current_space + 1)

    def lift_by(self, k):
        return self if k == 0 else self.lift_once().lift_by(k - 1)

    def drop_once(self, private_key):
        decrypted = decrypt(self.public_key, private_key,
                            self.current_space - 1,
                            self.payload)
        return Payload(decrypted, self.public_key, self.plaintext_space,
                       self.current_space - 1)

    def drop_by(self, k, private_key):
        if k == 0:
            return self
        else:
            return self.drop_once(private_key).drop_by(k - 1,
                                                       private_key)

    def get_plaintext(self, private_key):
        return self.drop_by(self.current_space - self.plaintext_space,
                            private_key)


def homomorphic_add(x, y):
    assert x.public_key == y.public_key
    assert x.plaintext_space == y.plaintext_space
    assert x.current_space == y.current_space
    modulus = x.public_key.get_npows(x.current_space)
    return Payload((x.payload * y.payload) % modulus,
                   x.public_key, x.plaintext_space, x.current_space)


def homomorphic_scalar_multiply(hidden, selector):
    public = hidden.public_key
    modulus_plain = public.get_npows(selector.current_space - 1)
    modulus_cipher = public.get_npows(selector.current_space)
    new_payload = modpow(selector.payload, hidden.payload,
                         modulus_cipher)
    r = random.getrandbits(public.bits) % modulus_cipher
    r = modpow(r, modulus_plain, modulus_cipher)
    new_payload = (new_payload * r) % modulus_cipher
    return Payload(new_payload, hidden.public_key,
                   hidden.plaintext_space, hidden.current_space + 1)


def homomorphic_select(payloads, selectors):
    # all plaintexts must be from the same space
    assert all([payloads[i].plaintext_space == payloads[0].plaintext_space
                for i in range(len(payloads))])

    assert len(payloads) == len(selectors)
    max_onion_layers = max([payload.current_space - payload.plaintext_space
                            for payload in payloads])

#    assert all([s.plaintext_space == payloads[0].current_space
#               for s in selectors])
    assert all([s.current_space - s.plaintext_space == 1
                for s in selectors])

    # lift payloads so that they have the same number of layers
    for i in range(len(payloads)):
        delta = max_onion_layers - (payloads[i].current_space -
                                    payloads[i].plaintext_space)
        payloads[i] = payloads[i].lift_by(delta)
        curr_diff = payloads[i].current_space - payloads[i].plaintext_space
        assert curr_diff == max_onion_layers

    merged = []
    for i in range(len(payloads)):
        merged.append(homomorphic_scalar_multiply(payloads[i], selectors[i]))
    return reduce(lambda x, y: homomorphic_add(x, y), merged)
