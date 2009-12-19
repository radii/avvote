#!/usr/bin/env python

# implementation of
# Anonymous Voting by 2-Round Public Discussion
# Feng Hao and Peter Ryan Piotr Zieliski
# http://sites.google.com/site/haofeng662/OpenVote_final.pdf?attredirects=0

import struct, sys

# from https://git.torproject.org/checkout/tor/master/doc/spec/tor-spec.txt
G = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF
g = 2

def rand(n):
    r = 0
    for x in struct.unpack('%dB' % n, open('/dev/urandom').read(n)):
        r = r * 256 + x
    return r

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

def zero_k(x):
    # XXX need a zero knowledge proof
    return 0

def check_zk(x):
    return true # XXX

def product(L):
    reduce(lambda a,b: a*b, L)

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

    if len(gxa) != n:
        print "got %d inputs, expected %d" % (len(gxa), n)
        return false
    if gxa[me] != gx:
        print "wrong self value on input, expected:\n0x%x\ngot:\n0x%x" % (
                gx, gxa[me])
        return false

    pgxa = product(gxa[:me-1])
    pgxb = product(gxa[me:])
    
