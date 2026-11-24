import random

p = 11470374874925275658116663507232161402086650258453896274534991676898999262641581519101074740642369848233294239851519212341844337347119899874391456329785623
q = 335062023296420808191071248367701059461
j = 34233586850807404623475048381328686211071196701374230492615844865929237417097514638999377942356150481334217896204702
g = 622952335333961296978159266084741085889881358738459939978290179936063635566740258555167783009058567397963466103140082647486611657350811560630587013183357
y_small = 7760073848032689505395005705677365876654629189298052775754597607446617558600394076764814236081991643094239886772481052254010323780165093955236429914607119
y_big = 9388897478013399550694114614498790691034187453089355259602614074132918843899833277397448144245883225611726912025846772975325932794909655215329941809013733


def kangaroo(base, target, low, high, k=None):
    """Find e in [low, high] with base^e == target (mod p), or None."""
    if k is None:
        k = max(2, (high - low).bit_length() // 2 + 2)
    # jump table: step k is 2^k, precompute base^(2^k) so each hop is one multiply
    jump_sizes = [2 ** i for i in range(k)]
    jump_elems = [pow(base, s, p) for s in jump_sizes]
    mean_jump = sum(jump_sizes) / k
    hops = int(4 * mean_jump)

    def pick(element):
        return element % k

    # tame kangaroo: starts at the top of the range
    tame_dist = 0
    tame_pos = pow(base, high, p)
    for _ in range(hops):
        i = pick(tame_pos)
        tame_dist += jump_sizes[i]
        tame_pos = tame_pos * jump_elems[i] % p

    # wild kangaroo: starts at the target
    wild_dist = 0
    wild_pos = target
    limit = high - low + tame_dist
    while wild_dist < limit:
        i = pick(wild_pos)
        wild_dist += jump_sizes[i]
        wild_pos = wild_pos * jump_elems[i] % p
        if wild_pos == tame_pos:
            return high + tame_dist - wild_dist
    return None


def find_with_retries(base, target, low, high):
    for k in range(high.bit_length() // 2 - 2, high.bit_length() // 2 + 8):
        found = kangaroo(base, target, low, high, k)
        if found is not None and pow(base, found, p) == target:
            return found
    return None


# Part 1: the two warm-up targets
print("2^20 target:", find_with_retries(g, y_small, 0, 2 ** 20))
print("2^40 target:", find_with_retries(g, y_big, 0, 2 ** 40))

# Part 2: attack Bob
bob_secret = random.randrange(1, q)
bob_public = pow(g, bob_secret, p)

# small prime factors of the cofactor j = (p-1)/q
small_factors = []
rest, d = j, 2
while d < 2 ** 17:
    if rest % d == 0:
        small_factors.append(d)
        while rest % d == 0:
            rest //= d
    d += 1 if d == 2 else 2

residues, moduli = [], []
for r in small_factors:
    # element of order r
    while True:
        h = pow(random.randrange(2, p - 1), (p - 1) // r, p)
        if h != 1:
            break
    # Bob's "response" to the malicious public key h is h^x; we find x mod r by brute force
    bobs_answer = pow(h, bob_secret, p)
    walker = 1
    for guess in range(r):
        if walker == bobs_answer:
            residues.append(guess)
            moduli.append(r)
            break
        walker = walker * h % p

# CRT
known_residue, known_modulus = 0, 1
for res, mod in zip(residues, moduli):
    step = ((res - known_residue) * pow(known_modulus, -1, mod)) % mod
    known_residue += known_modulus * step
    known_modulus *= mod
print("recovered x mod", known_modulus, "=", known_residue, "| matches:", bob_secret % known_modulus == known_residue)

# shift the problem: y' = y * g^-n, g' = g^r, find m in [0, (q-1)/r]
shifted_target = bob_public * pow(g, -known_residue, p) % p
shifted_base = pow(g, known_modulus, p)
m_upper = (q - 1) // known_modulus
print("search range for m: 2^%.1f" % (m_upper.bit_length()))
m = find_with_retries(shifted_base, shifted_target, 0, m_upper)
recovered = known_residue + m * known_modulus
print("recovered secret:", recovered)
print("actual secret:   ", bob_secret)
print("success:", recovered == bob_secret)
