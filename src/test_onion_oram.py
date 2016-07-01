import unittest
import random
import damgard_jurik
from onion_oram import NonEncServerWrapper, EncServerWrapper
from onion_oram import Client, Operations


class TestOnionORAM(unittest.TestCase):
    def test_basic(self):
        lambda_ = 5
        total_levels = 5
        total_usable_buckets = 1 << total_levels
        blocks_per_bucket = lambda_ * 5
        total_blocks = total_usable_buckets * blocks_per_bucket
        chunks_per_block = 10
        eviction_period = -1

        server_wrapper = NonEncServerWrapper(total_levels, blocks_per_bucket,
                                             chunks_per_block)

        client = Client(total_levels, total_blocks, blocks_per_bucket,
                        chunks_per_block, eviction_period, server_wrapper)

        chunks = range(10)
        chunks.reverse()
        client.access(1, Operations.WRITE, chunks)
        data = client.access(1, Operations.READ)
        self.assertEqual(data, chunks)
        client.access(13, Operations.WRITE, [189, 224])
        self.assertEqual(client.access(13, Operations.READ), [189, 224])
        self.assertEqual(client.access(1, Operations.READ), chunks)

    def test_stress_non_encrypted(self):
        lambda_ = 80
        total_levels = 5
        total_usable_buckets = 1 << total_levels
        blocks_per_bucket = lambda_
        total_blocks = total_usable_buckets * (blocks_per_bucket / 5)
        chunks_per_block = 10
        eviction_period = 80

        server_wrapper = NonEncServerWrapper(total_levels, blocks_per_bucket,
                                             chunks_per_block)

        client = Client(total_levels, total_blocks, blocks_per_bucket,
                        chunks_per_block, eviction_period, server_wrapper)

        datas = [range(30) for _ in range(total_blocks)]
        for i in range(len(datas)):
            random.shuffle(datas[i])
            client.access(i, Operations.WRITE, datas[i])
            self.assertEqual(client.access(i, Operations.READ), datas[i])

        for iteration in range(1000):
            piece = random.randint(0, total_blocks - 1)
            self.assertEqual(client.access(piece, Operations.READ),
                             datas[piece])
            random.shuffle(datas[piece])
            client.access(piece, Operations.WRITE, datas[piece])

    def test_basic_encrypted(self):
        lambda_ = 80
        total_levels = 5
        total_usable_buckets = 1 << total_levels
        blocks_per_bucket = lambda_
        total_blocks = total_usable_buckets * (blocks_per_bucket / 5)
        chunks_per_block = 10
        eviction_period = -1

        root_plain_space = 3
        public, private = damgard_jurik.generate_keypair(128, root_plain_space)
        server_wrapper = EncServerWrapper(total_levels, blocks_per_bucket,
                                          chunks_per_block, root_plain_space,
                                          public, private)
        client = Client(total_levels, total_blocks, blocks_per_bucket,
                        chunks_per_block, eviction_period, server_wrapper)

        chunks = range(10)
        chunks.reverse()
        client.access(1, Operations.WRITE, chunks)
        data = client.access(1, Operations.READ)
        self.assertEqual(data, chunks)

        client.access(13, Operations.WRITE, [189, 224, 1, 2, 3, 4, 5, 6, 7, 8])
        self.assertEqual(client.access(13, Operations.READ),
                         [189, 224, 1, 2, 3, 4, 5, 6, 7, 8])
        self.assertEqual(client.access(1, Operations.READ), chunks)

    def test_stress_encrypted(self):
        lambda_ = 20
        total_levels = 3
        total_usable_buckets = 1 << total_levels
        blocks_per_bucket = lambda_
        total_blocks = total_usable_buckets * (blocks_per_bucket / 5)
        chunks_per_block = 3
        eviction_period = 20

        root_plain_space = 1
        public, private = damgard_jurik.generate_keypair(128, root_plain_space)
        server_wrapper = EncServerWrapper(total_levels, blocks_per_bucket,
                                          chunks_per_block, root_plain_space,
                                          public, private)
        client = Client(total_levels, total_blocks, blocks_per_bucket,
                        chunks_per_block, eviction_period, server_wrapper)

        datas = [range(3) for _ in range(total_blocks)]
        for i in range(len(datas)):
            random.shuffle(datas[i])
            client.access(i, Operations.WRITE, datas[i])
            self.assertEqual(client.access(i, Operations.READ), datas[i])

        for iteration in range(30):
            piece = random.randint(0, total_blocks - 1)
            self.assertEqual(client.access(piece, Operations.READ),
                             datas[piece])
            random.shuffle(datas[piece])
            client.access(piece, Operations.WRITE, datas[piece])


if __name__ == '__main__':
    unittest.main()
