
def untemper(y, param):
    y = reverse_xorshift_right(y, int(param.l))
    y = reverse_xorshift_left(y, int(param.t), param.c)
    y = reverse_xorshift_left(y, int(param.s), param.b)
    y = reverse_xorshift_right(y, int(param.u), param.d)
    return y

def reverse_xorshift_left(value, n_shift, and_mask):
    if n_shift == 0:
        raise ValueError("`n_shift` should not be 0")
    
    n_remains = 32 - n_shift
    mask = (1 << n_shift) - 1
    while n_remains > 0:
        value ^= ((value & mask) << n_shift) & and_mask
        n_remains -= n_shift
        mask <<= n_shift
    return value

def reverse_xorshift_right(value, n_shift, and_mask):
    if n_shift == 0:
        raise ValueError("`n_shift` should not be 0")
    
    n_remains = 32 - n_shift
    mask = ~((1 << n_remains) - 1)
    while n_remains > 0:
        value ^= ((value & mask) >> n_shift) & and_mask
        n_remains -= n_shift
        mask >>= n_shift
    return value

def reverse_xorshift_left(value, n_shift):
    if n_shift == 0:
        raise ValueError("`n_shift` should not be 0")
    
    while n_shift < 32:
        value ^= value << n_shift
        n_shift *= 2
    return value

def reverse_xorshift_right(value, n_shift):
    if n_shift == 0:
        raise ValueError("`n_shift` should not be 0")
    
    while n_shift < 32:
        value ^= value >> n_shift
        n_shift *= 2
    return value
