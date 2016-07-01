import copy
import random
import string
import utils

VERBOSE_DEBUGGING = False

Operations = utils.enum(READ=1, WRITE=2)


class Block(object):
    def __init__(self, address=-1, leaf_target=-1, contents=None):
        alphabet = string.ascii_uppercase + string.digits

        self.address = address
        self.leaf_target = leaf_target

        if contents is None:
            # initialize some junk data
            self.contents = ''.join(random.choice(alphabet) for _ in range(8))
        else:
            self.contents = contents

    def is_valid(self):
        return self.address >= 0

    def invalidate(self):
        self.address = -1
        self.leaf_target = -1

    def __str__(self):
        return ("address = " + str(self.address) + ", leaf_target= " +
                str(self.leaf_target) + "sign: " + self.contents)


class Bucket(object):
    def __init__(self, blocks_per_bucket):
        self.blocks = [Block() for _ in range(blocks_per_bucket)]

    def get_valid_blocks(self):
        free_slots = []
        valid_blocks = []
        for i, block in enumerate(self.blocks):
            if block.is_valid():
                valid_blocks.append(block)
            else:
                free_slots.append(i)
        return free_slots, valid_blocks

    def invalidate_all(self):
        for block in self.blocks:
            block.invalidate()


class Server(object):
    def __init__(self, total_levels, blocks_per_bucket):
        self._total_levels = total_levels
        self._blocks_per_bucket = blocks_per_bucket

        total_buckets = (1 << (total_levels + 1)) - 1
        self.buckets = [Bucket(blocks_per_bucket)
                        for _ in range(total_buckets)]

    @property
    def total_levels(self):
        return self._total_levels

    @property
    def blocks_per_bucket(self):
        return self._blocks_per_bucket

    def read_path(self, leaf_target, address):
        at = leaf_target + (1 << self.total_levels) - 1

        occurances = 0
        bucket_id, block_id = -1, -1
        for _ in range(self.total_levels + 1):
            for block in range(self.blocks_per_bucket):
                if self.buckets[at].blocks[block].address == address:
                    bucket_id, block_id = at, block
                    occurances += 1
            at = (at - 1) / 2

        if occurances != 1:
            raise RuntimeError("Block not found on the path at all.")
        if VERBOSE_DEBUGGING:
            print "invalidating: ", \
                self.buckets[bucket_id].blocks[block_id].address
        self.buckets[bucket_id].blocks[block_id].invalidate()
        return self.buckets[bucket_id].blocks[block_id].contents

    def get_bucket(self, bucket_id):
        return copy.deepcopy(self.buckets[bucket_id])

    def set_bucket(self, bucket_id, bucket):
        self.buckets[bucket_id] = copy.deepcopy(bucket)

    def get_block(self, bucket_id, block_id):
        return copy.deepcopy(self.buckets[bucket_id].blocks[block_id])

    def set_block(self, bucket_id, block_id, block):
        self.buckets[bucket_id].blocks[block_id] = copy.deepcopy(block)

    def traverse(self):
        if VERBOSE_DEBUGGING:
            print "doing traverse()"
        stack = []
        stack.append(0)
        seen = [False for _ in range(1 << self.total_levels)]
        missing = 1 << self.total_levels
        while len(stack) > 0:
            at = stack[-1]
            stack.pop()
            if at * 2 + 1 < len(self.buckets):
                stack.append(at * 2 + 1)
            if at * 2 + 2 < len(self.buckets):
                stack.append(at * 2 + 2)
            data = []
            for block in self.buckets[at].blocks:
                if block.is_valid():
                    data.append(block.address)
                    if not seen[block.address]:
                        seen[block.address] = True
                        missing -= 1
                    else:
                        raise RuntimeError("Duplicate element present!")
            if VERBOSE_DEBUGGING:
                if len(data) > 0:
                    print "at = ", at, " contains ", data
        if missing != 0:
            for (i, present) in enumerate(seen):
                if VERBOSE_DEBUGGING:
                    if not present:
                        print "missing element", i
            raise RuntimeError(
                str(missing) + " elements missing from the tree.")


class Client(object):
    def __init__(self, total_levels, blocks_per_bucket,
                 eviction_period, server):
        # initilize the position map with -1 which indicate invalidate blocks
        self._total_levels = total_levels
        self._total_blocks = 1 << total_levels
        self._blocks_per_bucket = blocks_per_bucket
        self.eviction_period = eviction_period
        self.server = server

        self.eviction_counter = 0
        self.next_evicted_path = 0

        self.position_map = [-1 for _ in range(self.total_blocks)]
        self.__bootstrap()

    @property
    def total_levels(self):
        return self._total_levels

    @property
    def total_blocks(self):
        return self._total_blocks

    @property
    def blocks_per_bucket(self):
        return self._blocks_per_bucket

    def __is_parent(self, parent, child):
        if parent == 0:
            return True
        while child > parent:
            child = (child - 1) / 2
        return child == parent

    def __bootstrap(self):
        block = 0
        while block < self.total_blocks:
            bucket_id = random.randint(1, self.total_blocks * 2 - 2)
            block_id = random.randint(0, self.blocks_per_bucket - 1)
            if not self.server.get_block(bucket_id, block_id).is_valid():
                target = bucket_id
                while target * 2 + 2 < self.total_blocks * 2 - 1:
                    target = target * 2 + random.randint(1, 2)
                target -= self.total_blocks - 1
                corresponding_leaf = target + self.total_blocks - 1
                assert self.__is_parent(bucket_id, corresponding_leaf)
                new_block = Block(block, target, "anastaso")
                self.server.set_block(bucket_id, block_id, new_block)
                self.position_map[block] = target
                block += 1

    def __push(self, source):
        assert source >= 0
        assert source < (1 << self.total_levels) - 1
        left_child = source * 2 + 1
        right_child = source * 2 + 2

        source_bucket = self.server.get_bucket(source)
        left_child_bucket = self.server.get_bucket(left_child)
        right_child_bucket = self.server.get_bucket(right_child)

        _, source_blocks = source_bucket.get_valid_blocks()
        slots_left, _ = left_child_bucket.get_valid_blocks()
        slots_right, _ = right_child_bucket.get_valid_blocks()

        towards_left, towards_right = [], []
        for block in source_blocks:
            target = block.leaf_target + (1 << self.total_levels) - 1
            assert (self.__is_parent(left_child, target) ^
                    self.__is_parent(right_child, target))
            if self.__is_parent(left_child, target):
                towards_left.append(block)
            else:
                towards_right.append(block)
        if (len(slots_left) < len(towards_left) or
                len(slots_right) < len(towards_right)):
            raise RuntimeError("Not enough room for eviction.")
        for (population, place, bucket) in [
                (slots_left, towards_left, left_child_bucket),
                (slots_right, towards_right, right_child_bucket)]:
            chosen = random.sample(population, len(place))
            for i, x in enumerate(chosen):
                assert not bucket.blocks[x].is_valid()
                bucket.blocks[x] = copy.deepcopy(place[i])

        source_bucket.invalidate_all()
        self.server.set_bucket(source, source_bucket)
        self.server.set_bucket(left_child, left_child_bucket)
        self.server.set_bucket(right_child, right_child_bucket)

        source_bucket = self.server.get_bucket(source)
        left_child_bucket = self.server.get_bucket(left_child)
        right_child_bucket = self.server.get_bucket(right_child)

    def _evict_along_path(self, leaf_target):
        at = leaf_target + (1 << self.total_levels) - 1

        nodes_along_path = []
        for _ in range(self.total_levels + 1):
            nodes_along_path.append(at)
            at = (at - 1) / 2

        nodes_along_path.reverse()
        for source in nodes_along_path[: -1]:
            self.__push(source)

    def access(self, block_id, operation, new_data=None):
        assert (block_id >= 0 and block_id < self.total_blocks)
        if self.position_map[block_id] < 0:
            raise RuntimeError("Trying to access block not written before.")

        new_leaf_target = random.randint(0, self.total_blocks - 1)
        leaf_target = self.position_map[block_id]
        self.position_map[block_id] = new_leaf_target

        data = self.server.read_path(leaf_target, block_id)
        if operation == Operations.WRITE:
            data = new_data

        # Write this block at the root of the tree.
        new_block = Block(block_id, new_leaf_target, data)
        self.server.set_block(0, self.eviction_counter, new_block)

        self.eviction_counter += 1
        if self.eviction_counter == self.eviction_period:
            self.eviction_counter = 0
            self._evict_along_path(
                utils.bitreverse(self.next_evicted_path, self.total_levels))
            self.next_evicted_path = self.next_evicted_path + 1
            if self.next_evicted_path >= self.total_blocks:
                self.next_evicted_path -= self.total_blocks

        if operation == Operations.READ:
            return data
        return None
