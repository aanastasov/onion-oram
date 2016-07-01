import unittest
import random
from damgard_jurik import generate_keypair, encrypt, decrypt, Payload
from damgard_jurik import homomorphic_add, homomorphic_select
from damgard_jurik import homomorphic_scalar_multiply


class TestDamgardJurik(unittest.TestCase):
    def test_homomorphic_select(self):
        base_level = 2
        onion_layers = 6
        public, private = generate_keypair(128, base_level)
        max_onion_layers = onion_layers + base_level

        nums = [6969, 333, 1337, 3512]
        for i in range(len(nums)):
            enc = [Payload(x, public, base_level,
                   base_level).lift_by(onion_layers)
                   for x in nums]
            select = [0] * len(nums)
            select[i] = 1
            selector = []
            for j in range(len(nums)):
                selector.append(Payload(select[j], public,
                                max_onion_layers,
                                max_onion_layers).lift_once())
            res = homomorphic_select(enc, selector)
            self.assertEqual(res.get_plaintext(private).payload, nums[i])

    def test_homomorphic_scalar_multiply_one(self):
        base_level = 2
        onion_level = 4
        public, private = generate_keypair(128, onion_level)
        hidden = Payload(444, public, base_level,
                         base_level).lift_by(onion_level)
        selector = Payload(1, public, onion_level + base_level,
                           onion_level + base_level).lift_by(1)
        res = homomorphic_scalar_multiply(hidden, selector)
        self.assertEqual(res.get_plaintext(private).payload, 444)

    def test_homomorphic_scalar_multiply_zero(self):
        base_level = 3
        onion_level = 4
        public, private = generate_keypair(128, onion_level)
        hidden = Payload(444, public, base_level,
                         base_level).lift_by(onion_level)
        selector = Payload(0, public, onion_level + base_level,
                           onion_level + base_level).lift_by(1)
        res = homomorphic_scalar_multiply(hidden, selector)
        self.assertEqual(res.get_plaintext(private).payload, 0)

    def test_encrypt_decrypt(self):
        public, private = generate_keypair(128, 8)
        for _ in range(10):
            plaintext = random.randint(0, 100000)
            ciphertext = encrypt(public, 8, plaintext)
            deciphered = decrypt(public, private, 8, ciphertext)
            self.assertEqual(deciphered, plaintext)

    def test_homomorphic_operation(self):
        public, private = generate_keypair(128, 8)
        e12851 = encrypt(public, 8, 12851)
        e21585 = encrypt(public, 8, 21585)
        e34436 = e12851 * e21585
        self.assertEquals(34436, decrypt(public,
                          private, 8, e34436))

    def test_homomorphic_payload_add(self):
        pspace = 10
        public, private = generate_keypair(128, pspace)
        a = Payload(12851, public, pspace, pspace).lift_once()
        b = Payload(21585, public, pspace, pspace).lift_once()
        c = homomorphic_add(a, b).get_plaintext(private)
        self.assertEqual(c.payload, 12851 + 21585)

    def test_payload_lift_drop_multiple_times(self):
        pspace = 5
        public, private = generate_keypair(128, pspace)
        for _ in range(4):
            num = random.randint(0, 100000)
            data = Payload(num, public, pspace, pspace)
            self.assertEqual(data.current_space, pspace)
            self.assertEqual(data.plaintext_space, pspace)
            by = random.randint(0, 10)
            encrypted = data.lift_by(by)
            self.assertEqual(encrypted.current_space, pspace + by)
            self.assertEqual(encrypted.plaintext_space, pspace)
            decrypted = encrypted.drop_by(by, private)
            self.assertEqual(decrypted.current_space, pspace)
            self.assertEqual(decrypted.plaintext_space, pspace)
            self.assertEqual(decrypted.payload, num)

    def test_payload_lift_drop_once(self):
        plaintext_space = 5
        public, private = generate_keypair(128, plaintext_space)
        data = Payload(1337, public, plaintext_space, plaintext_space)
        encrypted = data.lift_by(1)
        decrypted = encrypted.drop_by(1, private)
        self.assertEqual(decrypted.payload, 1337)


if __name__ == '__main__':
    unittest.main()
