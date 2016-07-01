
def enum(**enums):
    return type('Enum', (), enums)


def bitreverse(value, num_bits):
    res = 0
    for i in range(num_bits):
        if (value & (1 << i)) > 0:
            res |= 1 << (num_bits - 1 - i)
    return res
