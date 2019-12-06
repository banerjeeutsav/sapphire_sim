#! /usr/bin/python

import math, os
from sha3 import *

###################################################################################################
#
# Python Simulator for Sapphire Lattice Crypto-Processor
#
# Author: Utsav Banerjee
# Last Modified: 19-Oct-2019
#
###################################################################################################

########################################################################
# Sage script to compute roots of unity:
"""
q = 7681

nlist = []
for i in range(6,13):
    n = 2**i
    if (q-1) % n == 0:
        nlist.append(n)

R = IntegerModRing(q)
g = R(1)

for n in nlist:
    r = g.nth_root(n, all=True)
    r.sort()
    omega = 1
    for root in r:
        count = 0
        for i in range(1,n):
            if root**i % q == 1:
                count = count + 1
        if count == 0:
            omega = root
            break
    print "n = %d: omega = %d" % (n, omega)
"""
########################################################################

roots_of_unity = {
3329:    { 64: 56,     128: 33,     256: 17 },
7681:    { 64: 330,    128: 202,    256: 198,    512: 62 },
12289:   { 64: 563,    128: 81,     256: 9,      512: 3,     1024: 49,    2048: 7,     4096: 41 },
40961:   { 64: 1554,   128: 223,    256: 82,     512: 248,   1024: 40,    2048: 32,    4096: 28 },
65537:   { 64: 255,    128: 2469,   256: 141,    512: 157,   1024: 431,   2048: 33,    4096: 21 },
120833:  { 64: 4454,   128: 158,    256: 204,    512: 133,   1024: 206,   2048: 171 },
133121:  { 64: 2340,   128: 6409,   256: 1143,   512: 348,   1024: 454,   2048: 39 },
184321:  { 64: 7114,   128: 3388,   256: 946,    512: 445,   1024: 71,    2048: 391,   4096: 145 },
4205569: { 64: 4429,   128: 3244,   256: 2818,   512: 30909, 1024: 742 },
4206593: { 64: 435133, 128: 79570,  256: 10298,  512: 27945, 1024: 990,   2048: 1332,  4096: 629 },
8058881: { 64: 414515, 128: 44206,  256: 5168,   512: 70867, 1024: 20460, 2048: 11507 },
8380417: { 64: 434125, 128: 394148, 256: 169688, 512: 1753,  1024: 10730, 2048: 1306,  4096: 2741 },
8404993: { 64: 90438,  128: 287322, 256: 56156,  512: 35544, 1024: 2893,  2048: 16204, 4096: 2687 },
}

rej_fast_factors = {
3329:    19,
7681:    1,
12289:   5,
40961:   3,
65537:   7,
120833:  1,
133121:  7,
184321:  11,
4205569: 7,
4206593: 7,
8058881: 1,
8380417: 1,
8404993: 7,
}

def mult_psi(n, q, poly, line, instr):
    if 2*n not in roots_of_unity[q]:
        print("\n[Line %d] %s\nERROR: 2n-th root of unity modulo q does not exist for \"n = %d\" and \"q = %d\"\n" % (line, instr, n, q))
        exit()        
    psi = roots_of_unity[q][2*n]
    factor = 1
    for i in range(n):
        poly[i] = (int(poly[i]) * factor) % q
        factor = (factor * psi) % q
    return 2 + 1 + (n+1)

def mult_psi_inv(n, q, poly, line, instr):
    if 2*n not in roots_of_unity[q]:
        print("\n[Line %d] %s\nERROR: 2n-th root of unity modulo q does not exist for \"n = %d\" and \"q = %d\"\n" % (line, instr, n, q))
        exit()        
    psi = roots_of_unity[q][2*n]
    psi_inv = (psi**(q-2)) % q
    n_inv = (n**(q-2)) % q
    factor = 1
    for i in range(n):
        poly[i] = (((int(poly[i]) * n_inv) % q) * factor) % q
        factor = (factor * psi_inv) % q
    return 2 + 1 + (n+1)

def dif_ntt(n, q, poly, line, instr):
    if 2*n not in roots_of_unity[q]:
        print("\n[Line %d] %s\nERROR: 2n-th root of unity modulo q does not exist for \"n = %d\" and \"q = %d\"\n" % (line, instr, n, q))
        exit()        
    omega = roots_of_unity[q][n]
    # bitrev_shuffle
    j = 0
    for i in range(1,n):
        b = n >> 1
        while j >= b:
            j -= b
            b >>= 1
        j += b
        if j > i:
            poly[i], poly[j] = poly[j], poly[i]
    # ntt
    trans_size = 2
    for trans_size in [2**i for i in range(1,int(math.log(n,2))+1)]:
        wb = 1
        wb_step = (omega**(int(n/trans_size))) % q
        for t in range(trans_size >> 1):
            for trans in range(int(n/trans_size)):
                i = trans * trans_size + t
                j = i + (trans_size >> 1)
                a = poly[i]
                b = (int(poly[j]) * wb) % q
                poly[i] = (a + b) % q
                poly[j] = (a - b) % q
            wb = (wb * wb_step) % q
    # bitrev_shuffle
    j = 0
    for i in range(1,n):
        b = n >> 1
        while j >= b:
            j -= b
            b >>= 1
        j += b
        if j > i:
            poly[i], poly[j] = poly[j], poly[i]
    return 2 + 1 + (1+int(n/2))*int(math.log(n,2))

def dit_ntt(n, q, poly, line, instr):
    if 2*n not in roots_of_unity[q]:
        print("\n[Line %d] %s\nERROR: 2n-th root of unity modulo q does not exist for \"n = %d\" and \"q = %d\"\n" % (line, instr, n, q))
        exit()        
    omega = roots_of_unity[q][n]
    # ntt
    trans_size = 2
    for trans_size in [2**i for i in range(1,int(math.log(n,2))+1)]:
        wb = 1
        wb_step = (omega**(int(n/trans_size))) % q
        for t in range(trans_size >> 1):
            for trans in range(int(n/trans_size)):
                i = trans * trans_size + t
                j = i + (trans_size >> 1)
                a = poly[i]
                b = (int(poly[j]) * wb) % q
                poly[i] = (a + b) % q
                poly[j] = (a - b) % q
            wb = (wb * wb_step) % q
    return 2 + 1 + (1+int(n/2))*int(math.log(n,2))

def dif_intt(n, q, poly, line, instr):
    if 2*n not in roots_of_unity[q]:
        print("\n[Line %d] %s\nERROR: 2n-th root of unity modulo q does not exist for \"n = %d\" and \"q = %d\"\n" % (line, instr, n, q))
        exit()        
    omega = roots_of_unity[q][n]
    omega_inv = (omega**(q-2)) % q
    # bitrev_shuffle
    j = 0
    for i in range(1,n):
        b = n >> 1
        while j >= b:
            j -= b
            b >>= 1
        j += b
        if j > i:
            poly[i], poly[j] = poly[j], poly[i]
    # intt
    trans_size = 2
    for trans_size in [2**i for i in range(1,int(math.log(n,2))+1)]:
        wb = 1
        wb_step = (omega_inv**(int(n/trans_size))) % q
        for t in range(trans_size >> 1):
            for trans in range(int(n/trans_size)):
                i = trans * trans_size + t
                j = i + (trans_size >> 1)
                a = poly[i]
                b = (int(poly[j]) * wb) % q
                poly[i] = (a + b) % q
                poly[j] = (a - b) % q
            wb = (wb * wb_step) % q
    # bitrev_shuffle
    j = 0
    for i in range(1,n):
        b = n >> 1
        while j >= b:
            j -= b
            b >>= 1
        j += b
        if j > i:
            poly[i], poly[j] = poly[j], poly[i]
    return 2 + 1 + (1+int(n/2))*int(math.log(n,2))

def dit_intt(n, q, poly, line, instr):
    if 2*n not in roots_of_unity[q]:
        print("\n[Line %d] %s\nERROR: 2n-th root of unity modulo q does not exist for \"n = %d\" and \"q = %d\"\n" % (line, instr, n, q))
        exit()        
    omega = roots_of_unity[q][n]
    omega_inv = (omega**(q-2)) % q
    # intt
    trans_size = 2
    for trans_size in [2**i for i in range(1,int(math.log(n,2))+1)]:
        wb = 1
        wb_step = (omega_inv**(int(n/trans_size))) % q
        for t in range(trans_size >> 1):
            for trans in range(int(n/trans_size)):
                i = trans * trans_size + t
                j = i + (trans_size >> 1)
                a = poly[i]
                b = (int(poly[j]) * wb) % q
                poly[i] = (a + b) % q
                poly[j] = (a - b) % q
            wb = (wb * wb_step) % q
    return 2 + 1 + (1+int(n/2))*int(math.log(n,2))

def poly_shift(n, q, ring, poly):
    coeff = poly[n-1]
    for i in range(1,n):
        poly[i] = poly[i-1]
    if ring == "+":
        poly[0] = q-coeff
    if ring == "-":
        poly[0] = coeff
    return 2 + 1 + 1 + (3*n)

def rejection_sample(n, q, mode, seed, poly):
    # Minimum probability of successful rejection sampling of a coefficient in the range [0, q)
    # for currently supported primes q is 88%, so it may be enough to generate n*32/0.88 = 37n bits
    # However, we generate 100*n bits to be safe (note that this is for the simulator only, the
    # actual hardware squeezes out bits from SHAKE only when needed)
    if mode == 128:
        buf = shake_128(seed, 100*n)
    if mode == 256:
        buf = shake_256(seed, 100*n)
    bound = rej_fast_factors[q] * q
    bits = math.ceil(math.log(bound,2))
    count = 0
    i = 0
    while (i < n):
        sample = int(buf[:8], 16) % 2**bits
        if sample < bound:
            poly[i] = sample % q
            i = i + 1
        buf = buf[8:]
        count = count + 1
    if mode == 128:
        return 2 + 1 + (25+25+math.ceil(count*29/42)+count)
    if mode == 256:
        return 2 + 1 + (25+25+math.ceil(count*33/34)+count)

def binomial_sample(n, q, k, mode, seed, poly):
    if mode == 128:
        if k <= 16:
            buf = shake_128(seed, 32*n)
        else:
            buf = shake_128(seed, 64*n)
    if mode == 256:
        if k <= 16:
            buf = shake_256(seed, 32*n)
        else:
            buf = shake_256(seed, 64*n)
    for i in range(n):
        if k <= 16:
            a = int(buf[:4], 16) % 2**k
            buf = buf[4:]
            b = int(buf[:4], 16) % 2**k
            buf = buf[4:]
        else:
            a = int(buf[:8], 16) % 2**k
            buf = buf[8:]
            b = int(buf[:8], 16) % 2**k
            buf = buf[8:]
        hw_a = sum( [a & (1<<j) > 0 for j in range(k)] )
        hw_b = sum( [b & (1<<j) > 0 for j in range(k)] )
        poly[i] = (hw_a - hw_b + q) % q
    if mode == 128:
        if k <= 16:
            return 2 + 1 + (25+25+math.ceil(n*29/42)+n)
        else:
            return 2 + 1 + (25+25+math.ceil(n*29/21)+n)
    if mode == 256:
        if k <= 16:
            return 2 + 1 + (25+25+math.ceil(n*33/34)+n)
        else:
            return 2 + 1 + (25+25+math.ceil(n*33/17)+n)

def cdt_sample(n, q, r, mode, seed, cdt, poly):
    if mode == 128:
        buf = shake_128(seed, 32*n)
    if mode == 256:
        buf = shake_256(seed, 32*n)
    for i in range(n):
        val = int(buf[:8], 16) % 2**(r-1)
        sign = (-1)**(int(int(buf[:8], 16) / 2**(r-1)))
        buf = buf[8:]
        sample = 0
        for j in range(len(cdt)):
            sample = sample + int(cdt[j] < val)
        poly[i] = (sign*sample + q) % q
    if mode == 128:
        return 2 + 1 + (25+25+math.ceil(n*29/42)+((len(cdt)+3)*n))
    if mode == 256:
        return 2 + 1 + (25+25+math.ceil(n*33/34)+((len(cdt)+3)*n))

def uniform_sample(n, q, eta, mode, seed, poly):
    # Again, we generate 100*n bits to be safe (note that this is for the simulator only, the
    # actual hardware squeezes out bits from SHAKE only when needed)
    if mode == 128:
        buf = shake_128(seed, 100*n)
    if mode == 256:
        buf = shake_256(seed, 100*n)
    bound = 2*eta + 1
    bits = math.ceil(math.log(bound,2))
    count = 0
    i = 0
    while (i < n):
        sample = int(buf[:8], 16) % 2**bits
        if sample < bound:
            poly[i] = (sample - eta + q) % q
            i = i + 1
        buf = buf[8:]
        count = count + 1
    if mode == 128:
        return 2 + 1 + (25+25+math.ceil(count*29/42)+count)
    if mode == 256:
        return 2 + 1 + (25+25+math.ceil(count*33/34)+count)

def trinary_sample_1(n, q, m, mode, seed, poly):
    # Again, we generate 100*n bits to be safe (note that this is for the simulator only, the
    # actual hardware squeezes out bits from SHAKE only when needed)
    if mode == 128:
        buf = shake_128(seed, 100*n)
    if mode == 256:
        buf = shake_256(seed, 100*n)
    poly = [0] * n
    count = 0
    i = 0
    while (i < m):
        sample = int(buf[:8], 16) % param_n
        sign = (-1)**(int(int(buf[:8], 16) / 2**31))
        if poly[sample] == 0:
            poly[sample] = (sign + q) % q
            i = i + 1
        buf = buf[8:]
        count = count + 1
    if mode == 128:
        return 2 + 1 + (25+25+math.ceil(count*29/42)+(2*count)+n)
    if mode == 256:
        return 2 + 1 + (25+25+math.ceil(count*33/34)+(2*count)+n)

def trinary_sample_2(n, q, m0, m1, mode, seed, poly):
    # Again, we generate 100*n bits to be safe (note that this is for the simulator only, the
    # actual hardware squeezes out bits from SHAKE only when needed)
    if mode == 128:
        buf = shake_128(seed, 100*n)
    if mode == 256:
        buf = shake_256(seed, 100*n)
    poly = [0] * n
    count = 0
    i = 0
    while (i < m0):
        sample = int(buf[:8], 16) % param_n
        if poly[sample] == 0:
            poly[sample] = 1
            i = i + 1
        buf = buf[8:]
        count = count + 1
    i = 0
    while (i < m1):
        sample = int(buf[:8], 16) % param_n
        if poly[sample] == 0:
            poly[sample] = q-1
            i = i + 1
        buf = buf[8:]
        count = count + 1
    if mode == 128:
        return 2 + 1 + (25+25+math.ceil(count*29/42)+(2*count)+n)
    if mode == 256:
        return 2 + 1 + (25+25+math.ceil(count*33/34)+(2*count)+n)

def trinary_sample_3(n, q, rho, mode, seed, poly):
    if mode == 128:
        buf = shake_128(seed, 32*n)
    if mode == 256:
        buf = shake_256(seed, 32*n)
    bits = int(math.log(rho,2))+1
    for i in range(n):
        sample = int(buf[:8], 16) % 2**bits
        if sample == 0:
            poly[i] = 1
        elif sample == 1:
            poly[i] = q-1
        else:
            poly[i] = 0
        buf = buf[8:]
    if mode == 128:
            return 2 + 1 + (25+25+math.ceil(n*29/42)+n)
    if mode == 256:
            return 2 + 1 + (25+25+math.ceil(n*33/34)+n)

        
        




