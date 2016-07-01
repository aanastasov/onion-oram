import unittest
import utils


class TestUtils(unittest.TestCase):
    def test_bitreverse(self):
        self.assertEqual(utils.bitreverse(7, 10), 512 + 256 + 128)
        self.assertEqual(utils.bitreverse(16 + 8 + 1, 5), 16 + 2 + 1)

if __name__ == '__main__':
    unittest.main()
