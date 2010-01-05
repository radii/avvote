#!/usr/bin/env python

# implementation of
# Anonymous Voting by 2-Round Public Discussion
# Feng Hao and Peter Ryan Piotr Zieliski
# http://sites.google.com/site/haofeng662/OpenVote_final.pdf?attredirects=0

import struct, sys, hashlib

# from https://git.torproject.org/checkout/tor/master/doc/spec/tor-spec.txt
G = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF
g = 2

def memtol(s):
    "Given a string of bytes, returns the big-endian bignum value."
    r = 0
    for x in struct.unpack('%dB' % len(s), s):
        r = r * 256 + x
    return r

def rand(n):
    return memtol(open('/dev/urandom').read(n))

def g_pow_x_mod_G(g, x, G, debugpow = 0):
    if x == 0: return 1
    g0 = g
    # find the high bit of x, using the fact that x&(x-1) is
    # "x with its lowest 1 bit turned to 0".
    i = x
    while i & i-1:
        i &= i-1
    assert(x&i == i)
    assert(x^i < x)
    g = 1
    while i > 0:
        if debugpow: print 'i=%x g=%d' % (i, g)
        if x & i:
            g *= g0
        i >>= 1
        if i: g = g * g % G
    return g % G

m = 2**257-1
for i in range(256):
    x = g_pow_x_mod_G(2, i, m)
    y = 2**i
    if x != y:
        raise "i = %d, %d != %d" % (i, x, y)

m = m*m
for j in (2,3,4,7,8,9,23,56,590,591,592,593,594):
    for i in range(256):
        x = g_pow_x_mod_G(i, j, m)
        assert x == (i ** j) % m, 'x=%d; i=%d; j=%d; m=%d' % (x,i,j,m)

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

def sha(s):
    "Return SHA-256 of s as byte string"
    return hashlib.sha256(s).digest()

def sig_schnorr(g, x, G, i):
    "Schnorr's signature."
    G_1 = G-1
    v = rand(512/8) % G_1
    gv = g_pow_x_mod_G(g, v, G)
    gx = g_pow_x_mod_G(g, x, G)
    h = sha(','.join(map(str, (g, gv, gx, i))))
    z = memtol(h)
    r = (v - (x * z)) % G_1
    debugpow = 0
    if debugpow: print "x=%d;v=%d;z=%d;r=%d;gv=%d;gx=%d" % (x,v,z,r,gv,gx)
    assert(gv == g_pow_x_mod_G(g, (r + x*z) % G_1, G))
    assert(gv == g_pow_x_mod_G(g, r + x*z, G, debugpow))
    assert(gv == (g_pow_x_mod_G(g, r, G) * g_pow_x_mod_G(g, x*z, G)) % G)
    return (gv, r)

def check_schnorr(g, gv, gx, i, r, G):
    """Check a Schnorr signature by computing
        g^r * g^(xi * z)
    and comparing the result to g^v.  We have g pre-agreed,
    the sender provided g^xi, and we compute z according to
    the agreed hash function."""
    h = sha(','.join(map(str, (g, gv, gx, i))))
    z = memtol(h)
    gr = g_pow_x_mod_G(g, r, G)
    # print "gr=%d;r=%d;z=%d;gv=%d;gx=%d" % (gr,r,z,gv,gx)
    return gv == ((gr * g_pow_x_mod_G(gx, z, G)) % G)

def sig_cds(g, xi, v, gy, gxyv, i, G):
    G_1 = G - 1
    w = rand(512/8) % G_1
    gx = g_pow_x_mod_G(g, xi, G)
    h = gy
    x = gx
    y = gxyv
    if v:
        d1 = rand(512/8) % G_1
        r1 = rand(512/8) % G_1
        a1 = g_pow_x_mod_G(g, r1, G) * g_pow_x_mod_G(x, d1, G) % G
        b1 = g_pow_x_mod_G(h, r1, G) * g_pow_x_mod_G(y, d1, G) % G
        a2 = g_pow_x_mod_G(g, w, G)
        b2 = g_pow_x_mod_G(h, w, G)
    else:
        d2 = rand(512/8) % G_1
        r2 = rand(512/8) % G_1
        a1 = g_pow_x_mod_G(g, w, G)
        b1 = g_pow_x_mod_G(h, w, G)
        a2 = g_pow_x_mod_G(g, r2, G) * g_pow_x_mod_G(x, d2, G) % G
        b2 = g_pow_x_mod_G(h, r2, G) * g_pow_x_mod_G(div(y, g, G), d2, G) % G
    c = memtol(sha(','.join(map(str, (i,x,y,a1,b1,a2,b2)))))
    if v:
        d2 = (c - d1) % G_1
        r2 = (w - xi * d2) % G_1
    else:
        d1 = (c - d2) % G_1
        r1 = (w - xi * d1) % G_1
    print 'from="sig_cds"; xi=%d; gx=%d; c=%d' % (xi, gx, c)
    return (x,y,a1,b1,a2,b2,c,d1,d2,r1,r2)

def check_cds(g, G, gy, x, y, a1, b1, a2, b2, c, d1, d2, r1, r2):
    G_1 = G-1
    h = gy
    if not c == (d1 + d2) % G_1:
        print 'c=%d; d1=%d; d2=%d' % (c, d1, d2)
        return False
    if not a1 == g_pow_x_mod_G(g, r1, G) * g_pow_x_mod_G(x, d1, G) % G:
        print 'a1=%d; r1=%d; x=%d; d1=%d' % (a1, r1, x, d1)
        return False
    if not b1 == g_pow_x_mod_G(h, r1, G) * g_pow_x_mod_G(y, d1, G) % G:
        print 'b1=%d; h=%d; r1=%d, y=%d; d1=%d' % (b1, h, r1, y, d1)
        return False
    if not a2 == g_pow_x_mod_G(g, r2, G) * g_pow_x_mod_G(x, d2, G) % G:
        print 'a2=%d; r2=%d; d2=%d' % (a2, r2, d2)
        return False
    y_g = div(y, g, G)
    if not b2 == g_pow_x_mod_G(h, r2, G) * g_pow_x_mod_G(y_g, d2, G) % G:
        print 'b2=%d; h=%d; r2=%d; y_g=%d; d2=%d' % (b2, h, r2, y_g, d2)
        return False
    return True

def product(L):
    return reduce(lambda a,b: a*b, L, 1)

def vote(v, me, n):
    x = rand(512/8)

    # round 1: fight
    gx = g_pow_x_mod_G(g, x, G)
    zx = sig_schnorr(g, x, G, me)

    print "round 1, voter %d:" % me
    print "(0x%x,(0x%x,0x%x))" % (gx, zx[0], zx[1])

    (gxa, zxa) = ([], [])
    for i in xrange(1, n+1):
        print "voter %d:" % i,
        r = sys.stdin.readline()
        (gxi, (gvi, ri)) = eval(r)
        gxa.append(gxi)
        zxa.append((gvi, ri))
        if not check_schnorr(g, gvi, gxi, i, ri, G):
            raise "Schnorr signature failed for voter %d" % i

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

    # round 2: fight
    gxyv = (g_pow_x_mod_G(gy, x, G) * g_pow_x_mod_G(g, v, G)) % G
    zv = sig_cds(g, x, v, gy, gxyv, me, G)

    print "round 2, voter %d:" % me
    print "(0x%x,%r)" % (gxyv, zv)
    (votes, zvs) = ([], [])
    for i in xrange(1, n+1):
        print "voter %d:" % i,
        r = sys.stdin.readline()
        (gxyvi, zvi) = eval(r)
        votes.append(gxyvi)
        zvs.append(zvi)
        pgxa = product(gxa[:i-1])
        pgxb = product(gxa[i:])
        gy = div(pgxa, pgxb, G)
        if not check_cds(g, G, gy, *zvi):
            raise 'ZK proof failed to check out, voter %d' % i

    p = product(votes) % G
    for i in xrange(0, n + 3):
        if p == g_pow_x_mod_G(g, i, G):
            print "Vote total: %d" % i
    return True

if __name__ == '__main__':
    if sys.argv[1] == "vote":
        v = int(sys.argv[2])
        n = int(sys.argv[3])
        me = int(sys.argv[4])
        vote(v, me, n)
