
// Use of Sage library

from sage.all import *
from random import randrange

p = 7199773997391911030609999317773941274322764333428698921736339643928346453700085358802973900485592910475480089726140708102474957429903531369589969318716771
g = 4565356397095740655436854503483826832136106141639563487732438195343690437606117828318042418238184896212352329118608100083187535033402010599512641674644143
q = 236234353446506858198510045061214171961

g = mod(g, p)

def fermatproof(g):
    assert bool(g^(p-1) == mod(1, p)), "Fermat fails!"

fermatproof(g)

print("2 * 3^2 * 5 * 109 * 7963 * 8539 * 20641 * 38833 * 39341 * 46337 * 51977 * 54319 * 57529 * 96142199 * 46323892554437 * 534232641372537546151 * 80913087354323463709999234471")
print([2, 3, 5, 109, 7963, 8539, 20641, 38833, 39341, 46337, 51977, 54319, 57529])

def checkorder(g, o):
    assert bool(g^(o) == mod(1, p)), "Incorrect order!"

checkorder(g, q)

truncated_p = euler_phi(p)/q

assert truncated_p == 30477252323177606811760882179058908038824640750610513771646768011063128035873508507547741559514324673960576895059570, "Error!"

fct = factor(truncated_p)

print(fct)

fct = list(fct)

fct = [i[0] for i in list(filter(lambda x: x[0] < 2^16, fct))]

print(fct)

x = randrange(p-1)+1
x = (mod(x, q)).lift()

def find_h(v):
    a = mod(randrange(1, p), p)^((p-1)/v)
    while a == mod(1, p):
        a = mod(randrange(1, p), p)^((p-1)/v)
    return a

def findxmodr(hexp, h, v):
    for a in range(1, v):
        if hexp == h^a:
            return a
    return 0

reducedval = []

for i in fct:
    h = find_h(i)
    hexp = h^x
    reducedval.append((findxmodr(hexp, h, i), i))

reducedval = list(filter(lambda x: x[0]>0 and x[1]!=3, reducedval))

def crt(val):
    val2 = [i[1] for i in val]
    val3 = [i[0] for i in val]
    n = reduce(lambda x, y: x*y, val2)
    assert q < n, "Not possible to reconstruct the secret!"
    ni = []
    for i in val2:
        va = n//i
        ni.append(va)
    answer = 0
    for i in range(len(val2)):
        assert gcd(ni[i], val2[i]) == 1, "Not coprime!"
        k = mod(ni[i], val2[i]).lift()
        k = inverse_mod(k, val2[i])
        answer += val3[i]*ni[i]*k
    quotient = answer//n
    qd = quotient*(n-q)
    answer = answer - qd
    return (mod(answer, q)).lift()

assert x == crt(reducedval), "Incorrect implementation"
print(x)
print(crt(reducedval))
print("Successfully recovered the secret x. Hence, the scheme breaks.")

