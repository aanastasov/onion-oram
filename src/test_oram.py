import unittest
import oram


class TestORAM(unittest.TestCase):
    def test_basic(self):
        for _ in range(30):
            total_levels = 6
            blocks_per_bucket = 5
            eviction_period = 5

            server = oram.Server(total_levels, blocks_per_bucket)
            client = oram.Client(total_levels, blocks_per_bucket,
                                 eviction_period, server)
            server.traverse()
            client.access(0, oram.Operations.READ)
            server.traverse()
            client.access(2, oram.Operations.WRITE, "first_string")
            server.traverse()
            self.assertEqual("first_string",
                             client.access(2, oram.Operations.READ))
            server.traverse()
            client.access(3, oram.Operations.READ)
            server.traverse()
            client.access(2, oram.Operations.WRITE, "second_string")
            server.traverse()
            self.assertEqual("second_string",
                             client.access(2, oram.Operations.READ))

    def test_dynamic_string(self):
        block_len = 8
        total_levels = 7
        blocks_per_bucket = 10
        eviction_period = 7

        server = oram.Server(total_levels, blocks_per_bucket)
        client = oram.Client(total_levels, blocks_per_bucket,
                             eviction_period, server)
        server.traverse()

        def write(start_pos, str_):
            first_pos = start_pos
            last_pos = first_pos + len(str_) - 1
            first_piece = start_pos / block_len
            last_piece = (last_pos + block_len - 1) / block_len
            for piece in range(first_piece, last_piece + 1):
                contents = list(client.access(piece, oram.Operations.READ))
                for pos in range(block_len):
                    if first_pos <= pos + block_len * piece <= last_pos:
                        string_pos = pos + block_len * piece - first_pos
                        contents[pos] = str_[string_pos]
                client.access(piece, oram.Operations.WRITE, "".join(contents))
            server.traverse()

        def read(start_pos, length):
            first_pos = start_pos
            last_pos = first_pos + length - 1
            first_piece = start_pos / block_len
            last_piece = (last_pos + block_len - 1) / block_len
            res = ""
            for piece in range(first_piece, last_piece + 1):
                contents = client.access(piece, oram.Operations.READ)
                for pos in range(block_len):
                    if first_pos <= pos + block_len * piece <= last_pos:
                        res += contents[pos]
            server.traverse()
            return res

        for _ in range(30):
            write(0, "This is an amazing thing and I can't believe that it" +
                  "might actually work correctly.")
            server.traverse()
            self.assertEqual(read(5, 15), "is an amazing t")

            write(500, "This is such an interesting data structure.")
            self.assertEqual(read(501, 10), "his is suc")
            server.traverse()

            write(20, "I have no idea!")
            self.assertEqual(read(10, 30), " amazing tI have no idea!t bel")
            server.traverse()


if __name__ == '__main__':
    unittest.main()
