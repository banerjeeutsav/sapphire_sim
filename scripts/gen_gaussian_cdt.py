#! /usr/bin/python

###################################################################################################
#
# Python CDT Generator
#
# Author: Utsav Banerjee
# Last Modified: 12-Oct-2019
#
###################################################################################################

import sys, math, os, binascii, random
from decimal import *

####################################
# CDT for Discrete Gaussian Sampler
####################################

def gen_Gaussian_CDT(sigma, cdt_len, precision, cdt_file):
    # Compute golden PMF
    prob_golden = [0.0] * (cdt_len)
    for i in range(cdt_len):
        prob_golden[i] = Decimal(0.5 * (math.erf((i + 0.5) / (sigma * math.sqrt(2))) - math.erf((i - 0.5) / (sigma * math.sqrt(2)))))

    # Compute quantized CDT
    CDT = [0 for i in range(cdt_len)]
    CDT[0] = prob_golden[0]
    for i in range(1, cdt_len):
        CDT[i] = CDT[i-1] + 2*prob_golden[i]
    CDT = [int((CDT[i]) * (2 ** (precision-1))) for i in range(cdt_len)]

    print("CDF_TABLE = %s" % CDT)

    f = open(cdt_file, "w")
    for i in range(cdt_len):
        f.write("%d\n" % CDT[i])
    f.close()

if len(sys.argv) < 5:
    print("ERROR: Incorrect arguments provided for CDT generator script")
    print("Usage: python gen_gaussian_cdt.py <sigma> <cdt_len> <prec> <out_cdt_file_path>")
    exit()

if int(sys.argv[2]) > 64:
    print("ERROR: Length of CDT must not be greater than 64\n")
    exit()

if int(sys.argv[3]) > 32:
    print("ERROR: Precision of CDT must not be greater than 32\n")
    exit()
    
gen_Gaussian_CDT(float(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]), sys.argv[4])
