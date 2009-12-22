#!/usr/bin/env python

# implementation of
# Anonymous Voting by 2-Round Public Discussion
# Feng Hao and Peter Ryan Piotr Zieliski
# http://sites.google.com/site/haofeng662/OpenVote_final.pdf?attredirects=0

import struct, sys

# from https://git.torproject.org/checkout/tor/master/doc/spec/tor-spec.txt
G = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF
g = 2

def memtol(s):
    "Given a string of bytes, returns the big-endian bignum value."
    r = 0
    for x in struct.unpack('%dB' % n, s):
        r = r * 256 + x
    return r

def rand(n):
    return memtol(open('/dev/urandom').read(n))

def g_pow_x_mod_G(g, x, G):
    g0 = g
    if x == 0: return 1
    while x > 1:
        g *= g
        if x & 1:
            g *= g0
        x >>= 1
        g %= G
    return g

def extended_gcd(a, b):
    x = 0
    lastx = 1
    y = 1
    lasty = 0
    while b != 0:
        q = a / b
        t = b
        b = a % b
        a = t
        t = x
        x = lastx - q * x
        lastx = t
        t = y
        y = lasty - q * y
        lasty = t
    return (lastx, lasty, a)

def mult_inv(x, G):
    "Returns the multiplicative inverse of x mod G"
    r = extended_gcd(x, G)[0]
    if r < 0:
        r = G + r
    return r

assert(mult_inv(14, 23) == 5)
assert(mult_inv(5, 23) == 14)

def div(a, b, G):
    "Returns a / b (mod G)."
    return (a * mult_inv(b, G)) % G

def zero_k(x):
    # XXX need a zero knowledge proof
    return 0

def check_zk(x):
    return True # XXX

def product(L):
    return reduce(lambda a,b: a*b, L, 1)

def vote(v, me, n):
    x = rand(512/8)

    # round 1: fight
    gx = g_pow_x_mod_G(g, x, G)
    zx = zero_k(x)

    print "round 1, voter %d:" % me
    print "(0x%x,0x%x)" % (gx, zx)

    (gxa, zxa) = ([], [])
    for i in xrange(1, n+1):
        print "voter %d:" % i,
        r = sys.stdin.readline()
        (gxi, zxi) = eval(r)
        gxa.append(gxi)
        zxa.append(zxi)
        if not check_zk(zxi):
            die("ZK proof failed to check out")

    if len(gxa) != n:
        print "got %d inputs, expected %d" % (len(gxa), n)
        return False
    if gxa[me-1] != gx:
        print "wrong self value on input, expected:\n0x%x\ngot:\n0x%x" % (
                gx, gxa[me])
        return False

    pgxa = product(gxa[:me-1])
    pgxb = product(gxa[me:])

    gy = div(pgxa, pgxb, G)

    gxyv = (g_pow_x_mod_G(gy, x, G) * g_pow_x_mod_G(g, v, G)) % G
    zv = zero_k(v)

    print "round 2, voter %d:" % me
    print "(0x%x,0x%x)" % (gxyv, zv)
    (votes, zvs) = ([], [])
    for i in xrange(1, n+1):
        print "voter %d:" % i,
        r = sys.stdin.readline()
        (gxyvi, zvi) = eval(r)
        votes.append(gxyvi)
        zvs.append(zvi)
        if not check_zk(zvi):
            die("ZK proof failed to check out: %r" % zvi)

    p = product(votes) % G
    for i in xrange(0, n + 3):
        if p == g_pow_x_mod_G(g, i, G):
            print "Vote total: %d" % i
    return True

if sys.argv[1] == "vote":
    v = int(sys.argv[2])
    n = int(sys.argv[3])
    me = int(sys.argv[4])
    vote(v, me, n)
