#! /usr/bin/python

import math, sys, os, random

###################################################################################################
#
# Python Simulator for Sapphire Lattice Crypto-Processor
#
# Author: Utsav Banerjee
# Last Modified: 19-Oct-2019
#
###################################################################################################

supported_encodings = ["BINARY_0RED", "BINARY_2RED", "BINARY_4RED", "BINARY_8RED", "TRUNC_256", "TRUNC_256_MSB", "RECON_SIMPLE"]

def encode_to_bytearray(n, q, poly, encoding, line, instr):
    if encoding == "BINARY_0RED":
        tmp = [0]*(n)
        for i in range(n):
            tmp[i] = int(round((2/q)*poly[i])) % 2
        b_arr = [0]*(int(n/8))
        for i in range(int(n/8)):
            for j in range(8):
                b_arr[i] = b_arr[i] + (2**j)*tmp[8*i+j]
        #print("b_arr = %s" % b_arr)
        return b_arr
    elif encoding == "BINARY_2RED":
        tmp = [0]*(int(n/2))
        for i in range(int(n/2)):
            tmp[i] += abs(poly[i         ] - int(math.floor(q/2)))
            tmp[i] += abs(poly[i+int(n/2)] - int(math.floor(q/2)))
            tmp[i] = 1 - int(tmp[i] > (q/2))
        b_arr = [0]*(int(n/16))
        for i in range(int(n/16)):
            for j in range(8):
                b_arr[i] = b_arr[i] + (2**j)*tmp[8*i+j]
        #print("b_arr = %s" % b_arr)
        return b_arr
    elif encoding == "BINARY_4RED":
        tmp = [0]*(int(n/4))
        for i in range(int(n/4)):
            tmp[i] += abs(poly[i           ] - int(math.floor(q/2)))
            tmp[i] += abs(poly[i+  int(n/4)] - int(math.floor(q/2)))
            tmp[i] += abs(poly[i+2*int(n/4)] - int(math.floor(q/2)))
            tmp[i] += abs(poly[i+3*int(n/4)] - int(math.floor(q/2)))
            tmp[i] = 1 - int(tmp[i] > (q))
        b_arr = [0]*(int(n/32))
        for i in range(int(n/32)):
            for j in range(8):
                b_arr[i] = b_arr[i] + (2**j)*tmp[8*i+j]
        #print("b_arr = %s" % b_arr)
        return b_arr
    elif encoding == "BINARY_8RED":
        tmp = [0]*(int(n/8))
        for i in range(int(n/8)):
            tmp[i] += abs(poly[i           ] - int(math.floor(q/2)))
            tmp[i] += abs(poly[i+  int(n/8)] - int(math.floor(q/2)))
            tmp[i] += abs(poly[i+2*int(n/8)] - int(math.floor(q/2)))
            tmp[i] += abs(poly[i+3*int(n/8)] - int(math.floor(q/2)))
            tmp[i] += abs(poly[i+4*int(n/8)] - int(math.floor(q/2)))
            tmp[i] += abs(poly[i+5*int(n/8)] - int(math.floor(q/2)))
            tmp[i] += abs(poly[i+6*int(n/8)] - int(math.floor(q/2)))
            tmp[i] += abs(poly[i+7*int(n/8)] - int(math.floor(q/2)))
            tmp[i] = 1 - int(tmp[i] > (2*q))
        b_arr = [0]*(int(n/64))
        for i in range(int(n/64)):
            for j in range(8):
                b_arr[i] = b_arr[i] + (2**j)*tmp[8*i+j]
        #print("b_arr = %s" % b_arr)
        return b_arr
    elif encoding == "TRUNC_256":
        tmp = [0]*(256)
        for i in range(256):
            tmp[i] = int(round((2/q)*poly[i])) % 2
        b_arr = [0]*(int(256/8))
        for i in range(int(256/8)):
            for j in range(8):
                b_arr[i] = b_arr[i] + (2**j)*tmp[8*i+j]
        #print("b_arr = %s" % b_arr)
        return b_arr
    elif encoding == "TRUNC_256_MSB":
        lsbits = int(math.floor(math.log(q,2))) - 2
        tmp = [0]*(256)
        for i in range(256):
            tmp[i] = poly[i] >> (lsbits+1)
        b_arr = [0]*(int(256/8))
        for i in range(int(256/8)):
            for j in range(8):
                b_arr[i] = b_arr[i] + (2**j)*tmp[8*i+j]
        #print("b_arr = %s" % b_arr)
        return b_arr
    elif encoding == "RECON_SIMPLE":
        tmp = [0]*(n)
        for i in range(n):
            if poly[i] < int(round(q/4)) or poly[i] > int(round(3*q/4)):
                tmp[i] = 0
            else:
                tmp[i] = 1
        b_arr = [0]*(int(n/8))
        for i in range(int(n/8)):
            for j in range(8):
                b_arr[i] = b_arr[i] + (2**j)*tmp[8*i+j]
        #print("b_arr = %s" % b_arr)
        return b_arr
    else:
        print("\n[Line %d] %s\nERROR: Unsupported encoding \"%s\", allowed encodings are %s\n" % (line, instr, encoding, supported_encodings))
        exit()

def random_poly_encode(n, q, poly, encoding, line, instr):
    if encoding == "BINARY_0RED":
        for i in range(n):
            poly[i] = int(round((q/2)*random.getrandbits(1)))
    elif encoding == "BINARY_2RED":
        for i in range(int(n/2)):
            poly[i         ] = int(round((q/2)*random.getrandbits(1)))
            poly[i+int(n/2)] = poly[i]
    elif encoding == "BINARY_4RED":
        for i in range(int(n/4)):
            poly[i           ] = int(round((q/2)*random.getrandbits(1)))
            poly[i+  int(n/4)] = poly[i]
            poly[i+2*int(n/4)] = poly[i]
            poly[i+3*int(n/4)] = poly[i]
    elif encoding == "BINARY_8RED":
        for i in range(int(n/8)):
            poly[i           ] = int(round((q/2)*random.getrandbits(1)))
            poly[i+  int(n/8)] = poly[i]
            poly[i+2*int(n/8)] = poly[i]
            poly[i+3*int(n/8)] = poly[i]
            poly[i+4*int(n/8)] = poly[i]
            poly[i+5*int(n/8)] = poly[i]
            poly[i+6*int(n/8)] = poly[i]
            poly[i+7*int(n/8)] = poly[i]
    elif encoding == "TRUNC_256":
        for i in range(256):
            poly[i] = int(round((q/2)*random.getrandbits(1)))
        for i in range(256,n):
            poly[i] = 0
    elif encoding == "TRUNC_256_MSB":
        lsbits = int(math.floor(math.log(q,2))) - 2
        for i in range(256):
            poly[i] = (random.getrandbits(1) << (lsbits+1)) + (1 << lsbits)
        for i in range(256,n):
            poly[i] = 0
    else:
        print("\n[Line %d] %s\nERROR: Unsupported encoding \"%s\", allowed encodings are %s\n" % (line, instr, encoding, supported_encodings))
        exit()
