import utils
import copy
import random
from damgard_jurik import Payload, homomorphic_select

VERBOSE_DEBUGGING = False

Operations = utils.enum(READ=1, WRITE=2)


class Block(object):
    def __init__(self, chunks_per_block, address=-1, bucket_leaf_target=-1,
                 chunks=None):
        self.address = address
        self.bucket_leaf_target = bucket_leaf_target
        self.chunks_per_block = chunks_per_block
        if address >= 0:
            if chunks is None:
                self.chunks = [0] * chunks_per_block
            else:
                self.chunks = chunks

    def is_dummy(self):
        return self.address < 0

    def __str__(self):
        return ("address = " + str(self.address) + ", leaf_target= " +
                str(self.bucket_leaf_target))


class Bucket(object):
    def __init__(self, blocks_per_bucket, chunks_per_block):
        self.blocks_per_bucket = blocks_per_bucket
        self.chunks_per_block = chunks_per_block
        self.blocks = [Block(chunks_per_block)
                       for _ in range(blocks_per_bucket)]


class Server(object):
    def __init__(self, total_levels, blocks_per_bucket, chunks_per_block):
        self.total_levels = total_levels
        self.blocks_per_bucket = blocks_per_bucket
        self.chunks_per_block = chunks_per_block

        total_buckets = (1 << (total_levels + 1)) - 1
        self.buckets = [Bucket(blocks_per_bucket, chunks_per_block)
                        for _ in range(total_buckets)]

    def get_addresses(self, target):
        bucket_at = target + (1 << self.total_levels) - 1

        buckets = []
        addresses = []
        for _ in range(self.total_levels + 1):
            buckets.append(bucket_at)
            addresses.append([block.address
                             for block in self.buckets[bucket_at].blocks])
            bucket_at = (bucket_at - 1) / 2
        addresses.reverse()
        buckets.reverse()
        return buckets, addresses

    def set_addresses(self, buckets, addresses):
        for i in range(len(buckets)):
            bucket = buckets[i]
            for j in range(self.blocks_per_bucket):
                self.buckets[bucket].blocks[j].address = addresses[i][j]


class EncServerWrapper(object):
    def __init__(self, total_levels, blocks_per_bucket,
                 chunks_per_block, root_plain_space,
                 public_key, private_key):
        self.root_plain_space = root_plain_space
        self.public_key = public_key
        self.private_key = private_key
        self.chunks_per_block = chunks_per_block
        self.blocks_per_bucket = blocks_per_bucket
        self.server = Server(total_levels, blocks_per_bucket,
                             chunks_per_block)

    def get_addresses(self, target):
        buckets_, addresses_ = self.server.get_addresses(target)
        buckets = copy.deepcopy(buckets_)
        addresses = copy.deepcopy(addresses_)
        for i in range(len(buckets)):
            for j in range(self.blocks_per_bucket):
                if addresses[i][j] < 0:
                    continue
                p = Payload(addresses[i][j], self.public_key, 1, 2)
                addresses[i][j] = p.get_plaintext(self.private_key).payload
        return buckets, addresses

    def set_addresses(self, buckets, addresses):
        for i in range(len(buckets)):
            for j in range(self.blocks_per_bucket):
                if addresses[i][j] < 0:
                    continue
                p = Payload(addresses[i][j], self.public_key, 1, 1).lift_once()
                addresses[i][j] = p.payload
        self.server.set_addresses(buckets, addresses)

    def __onions(self, bucket_id):
        res = 1
        while bucket_id > 0:
            bucket_id = (bucket_id - 1) / 2
            res += 1
        return res

    def select_block(self, bucket_ids, select_vector):
        max_onion_layers = max([self.__onions(x) for x in bucket_ids])
        max_onion_layers += self.root_plain_space
        selectors = []
        for i in range(len(bucket_ids)):
            bucket_id = bucket_ids[i]
            for j in range(self.blocks_per_bucket):
                assert select_vector[i][j] in [0, 1]
                if self.is_dummy(bucket_id, j):
                    continue
                p = Payload(select_vector[i][j], self.public_key,
                            max_onion_layers, max_onion_layers).lift_once()
                selectors.append(p)
        selected_chunks = []
        for c in range(self.chunks_per_block):
            payloads = []
            for i in range(len(bucket_ids)):
                bucket_id = bucket_ids[i]
                onion_layers = self.__onions(bucket_id)
                for j in range(self.blocks_per_bucket):
                    if self.is_dummy(bucket_id, j):
                        continue
                    data = self.server.buckets[bucket_id].blocks[j].chunks[c]
                    chunk = Payload(data, self.public_key,
                                    self.root_plain_space,
                                    self.root_plain_space + onion_layers)
                    payloads.append(chunk)
            decrypted = homomorphic_select(payloads, selectors).get_plaintext(
                self.private_key).payload
            selected_chunks.append(decrypted)
        return copy.deepcopy(selected_chunks)

    def is_dummy(self, bucket_id, block_id):
        return self.server.buckets[bucket_id].blocks[block_id].is_dummy()

    def get_block(self, bucket_id, block_id):
        block = copy.deepcopy(self.server.buckets[bucket_id].blocks[block_id])
        metadata = self.get_metadata(bucket_id, block_id)

        # decrypt the metadata of this block
        block.address = metadata[0]
        block.bucket_leaf_target = metadata[1]
        block.chunks_per_block = metadata[2]

        onion_layers = self.__onions(bucket_id)
        # decrypt all chunks of this block
        for c in range(block.chunks_per_block):
            p = Payload(block.chunks[c], self.public_key,
                        self.root_plain_space,
                        self.root_plain_space + onion_layers)
            block.chunks[c] = p.get_plaintext(self.private_key).payload
        return block

    def get_metadata(self, bucket_id, block_id):
        def remove_layer(data):
            return Payload(data, self.public_key, 1, 2).get_plaintext(
                self.private_key).payload

        ref = self.server.buckets[bucket_id].blocks[block_id]
        return remove_layer(ref.address), remove_layer(ref.bucket_leaf_target), \
            self.server.chunks_per_block

    def invalidate(self, bucket_id, block_id):
        self.server.buckets[bucket_id].blocks[block_id].address = -1
        self.server.buckets[bucket_id].blocks[block_id].chunks = None

    def set_block(self, bucket_id, block_id, block_):
        block = copy.deepcopy(block_)

        def add_layer(data):
            return Payload(data, self.public_key, 1, 1).lift_once().payload

        # encrypt the metadata of this block
        block.address = add_layer(block.address)
        block.bucket_leaf_target = add_layer(block.bucket_leaf_target)

        onion_layers = self.__onions(bucket_id)
        # encrypt all chunks of this block
        for c in range(block.chunks_per_block):
            p = Payload(block.chunks[c], self.public_key,
                        self.root_plain_space,
                        self.root_plain_space).lift_by(onion_layers)
            block.chunks[c] = p.payload

        self.server.buckets[bucket_id].blocks[block_id] = block


class NonEncServerWrapper(object):
    def __init__(self, total_levels, blocks_per_bucket, chunks_per_block):
        self.server = Server(total_levels, blocks_per_bucket, chunks_per_block)
        self.chunks_per_block = chunks_per_block

    def get_addresses(self, target):
        return self.server.get_addresses(target)

    def set_addresses(self, buckets, addresses):
        self.server.set_addresses(buckets, addresses)

    def select_block(self, bucket_ids, select_vector):
        blocks_per_bucket = self.server.blocks_per_bucket
        assert len(select_vector) == len(bucket_ids)
        for i in range(len(bucket_ids)):
            assert len(select_vector[i]) == self.server.blocks_per_bucket
        total_sum = 0
        for i in range(len(bucket_ids)):
            for j in range(self.server.blocks_per_bucket):
                total_sum += select_vector[i][j]
                assert select_vector[i][j] >= 0 and select_vector[i][j] <= 1
        assert total_sum == 1

        occurances = 0
        chunks = None
        for i in range(len(bucket_ids)):
            bucket = self.server.buckets[bucket_ids[i]]
            for block_id in range(blocks_per_bucket):
                selected = select_vector[i][block_id]
                assert (selected >= 0 and selected <= 1)
                if selected > 0:
                    occurances += 1
                    chunks = bucket.blocks[block_id].chunks
        assert occurances == 1
        return copy.deepcopy(chunks)

    def is_dummy(self, bucket_id, block_id):
        return self.server.buckets[bucket_id].blocks[block_id].is_dummy()

    def get_block(self, bucket_id, block_id):
        return copy.deepcopy(self.server.buckets[bucket_id].blocks[block_id])

    def get_metadata(self, bucket_id, block_id):
        ref = self.server.buckets[bucket_id].blocks[block_id]
        return ref.address, ref.bucket_leaf_target, ref.chunks_per_block

    def invalidate(self, bucket_id, block_id):
        self.server.buckets[bucket_id].blocks[block_id].address = -1
        self.server.buckets[bucket_id].blocks[block_id].chunks = None

    def set_block(self, bucket_id, block_id, block):
        self.server.buckets[bucket_id].blocks[block_id] = copy.deepcopy(block)


class Client(object):
    def __init__(self, total_levels, total_blocks, blocks_per_bucket,
                 chunks_per_block, eviction_period, server_wrapper,
                 public_key=None, private_key=None):
        self.public_key = public_key
        self.private_key = private_key

        self.total_levels = total_levels
        self.total_blocks = total_blocks
        self.total_leaf_buckets = 1 << total_levels
        self.blocks_per_bucket = blocks_per_bucket
        self.chunks_per_block = chunks_per_block
        self.eviction_period = eviction_period
        self.server_wrapper = server_wrapper

        self.eviction_counter = 0
        self.next_evicted_path = 0

        # initilize the position map with -1 which indicate invalid blocks
        self.position_map = [-1 for _ in range(self.total_blocks)]

    def __is_parent(self, parent, child):
        if parent == 0:
            return True
        while child > parent:
            child = (child - 1) / 2
        return child == parent

    def _push(self, source):
        assert source >= 0
        assert source < (1 << self.total_levels) - 1
        child = [source * 2 + 1, source * 2 + 2]
        next_index = [0, 0]
        for block_index in range(self.blocks_per_bucket):
            if self.server_wrapper.is_dummy(source, block_index):
                continue
            address, bucket_leaf_target, _ = \
                self.server_wrapper.get_metadata(source, block_index)
            target = (1 << self.total_levels) - 1 + bucket_leaf_target
            assert (self.__is_parent(child[0], target) ^
                    self.__is_parent(child[1], target))
            goesto = 0 if self.__is_parent(child[0], target) else 1
            assert self.__is_parent(child[goesto], target)
            while (next_index[goesto] < self.blocks_per_bucket and
                   not self.server_wrapper.is_dummy(child[goesto],
                                                    next_index[goesto])):
                next_index[goesto] += 1
            if next_index[goesto] == self.blocks_per_bucket:
                raise RuntimeError("Not enough room for eviction.")
            buckets = [source, child[goesto]]
            select_vector = [[0] * self.blocks_per_bucket,
                             [0] * self.blocks_per_bucket]
            select_vector[0][block_index] = 1
            chunks = self.server_wrapper.select_block(buckets, select_vector)
            new_block = Block(self.chunks_per_block, address,
                              bucket_leaf_target, chunks)
            self.server_wrapper.set_block(child[goesto],
                                          next_index[goesto],
                                          new_block)
            next_index[goesto] += 1
            self.server_wrapper.invalidate(source, block_index)

    def _evict_along_path(self, leaf_target):
        at = leaf_target + (1 << self.total_levels) - 1

        nodes_along_path = []
        for _ in range(self.total_levels + 1):
            nodes_along_path.append(at)
            at = (at - 1) / 2

        nodes_along_path.reverse()
        for source in nodes_along_path[: -1]:
            self._push(source)

    def _initialize_block(self, block_id):
        assert self.position_map[block_id] < 0
        while True:
            _bucket_id = random.randint(1, self.total_leaf_buckets * 2 - 2)
            _block_id = random.randint(0, self.blocks_per_bucket - 1)
            if self.server_wrapper.is_dummy(_bucket_id, _block_id):
                target = _bucket_id
                while target * 2 + 2 < self.total_leaf_buckets * 2 - 1:
                    target = target * 2 + random.randint(1, 2)
                target -= self.total_leaf_buckets - 1
                assert self.total_leaf_buckets == 1 << self.total_levels
                corresponding_leaf = target + self.total_leaf_buckets - 1
                assert self.__is_parent(_bucket_id, corresponding_leaf)
                block = Block(self.server_wrapper.chunks_per_block)
                block.address = block_id
                block.bucket_leaf_target = target
                block.chunks = [0] * self.server_wrapper.chunks_per_block
                self.server_wrapper.set_block(_bucket_id, _block_id, block)
                self.position_map[block_id] = target
                break

    def access(self, block_id, operation, new_chunks=None):
        assert (block_id >= 0 and block_id < self.total_blocks)
        if (self.position_map[block_id] < 0 and operation == Operations.WRITE):
            self._initialize_block(block_id)
        if self.position_map[block_id] < 0:
            raise RuntimeError("Trying to access block not written before.")

        new_bucket_leaf_target = random.randint(0, self.total_leaf_buckets - 1)
        leaf_target = self.position_map[block_id]
        self.position_map[block_id] = new_bucket_leaf_target

        bucket_ids_, addresses_ = self.server_wrapper.get_addresses(leaf_target)
        bucket_ids = copy.deepcopy(bucket_ids_)
        addresses = copy.deepcopy(addresses_)
        select_vector = copy.deepcopy(addresses)
        counter = {}
        matches = 0
        for i in range(len(addresses)):
            for j in range(self.blocks_per_bucket):
                if addresses[i][j] not in counter:
                    counter[addresses[i][j]] = 0
                counter[addresses[i][j]] += 1
                if counter[addresses[i][j]] > 1 and addresses[i][j] >= 0:
                    raise RuntimeError("duplicate blocks")
                select_vector[i][j] = 0
                if addresses[i][j] == block_id:
                    select_vector[i][j] = 1
                    addresses[i][j] = -1
                    matches += 1
        assert matches == 1
        chunks = self.server_wrapper.select_block(bucket_ids, select_vector)
        if operation == Operations.WRITE:
            chunks = new_chunks
        # invalidates the old bucket by resetting all the metadata
        self.server_wrapper.set_addresses(bucket_ids, addresses)

        new_block = Block(self.chunks_per_block, block_id,
                          new_bucket_leaf_target, chunks)
        self.server_wrapper.set_block(0, self.eviction_counter, new_block)

        self.eviction_counter += 1
        if self.eviction_counter == self.eviction_period:
            self.eviction_counter = 0
            self._evict_along_path(
                utils.bitreverse(self.next_evicted_path, self.total_levels))
            self.next_evicted_path = self.next_evicted_path + 1
            if self.next_evicted_path >= self.total_blocks:
                self.next_evicted_path -= self.total_blocks

        if operation == Operations.READ:
            return chunks
        return None
