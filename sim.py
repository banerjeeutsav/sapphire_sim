#! /usr/bin/python

###################################################################################################
#
# Python Simulator for Sapphire Lattice Crypto-Processor
#
# Author: Utsav Banerjee
# Last Modified: 25-Nov-2019
#
# Inputs:  Parameters (n,q), Operating Conditions, Program, Simulation Options
# Outputs: Instruction Count, Cycle Count, Total Time, Average Power, Total Energy
#
###################################################################################################

import matplotlib.pyplot as plt
import matplotlib as mpl
import numpy as np
import math, sys, os, re, random
from sha3 import *
from core import *
from encoding import *

# Read / Write Cycle Counts
READ_CYCLES = 2  # read data from the crypto core
WRITE_CYCLES = 2 # write data to the crypto core

# Supported Parameters
valid_n = [64, 128, 256, 512, 1024, 2048]
valid_q = [3329, 7681, 12289, 40961, 65537, 120833, 133121, 184321, 4205569, 4206593, 8058881, 8380417, 8404993]

# Power Consumption Table (Current in uA at 1.1 V and 72 MHz)
idd_dict = {
"ctrl"              : 1815,
"reg_alu"           : 3271,
"reg_poly"          : 2795,
"sha3"              : 6115,
"poly_read_write"   : 6145,
"poly_init"         : 6120,
"poly_bitrev"       : 6212,
"poly_copy"         : 6183,
"poly_eq_check"     : 5523,
"poly_norm_check"   : 3019,
"poly_shift"        : 6201,
"poly_hash"         : 7503,
"poly_sum_elems"    : 3630,
"poly_max_elems"    : 3184,
"poly_mult_psi"     : { 3329: 7546, 7681: 7335, 12289: 8067, 40961:  9032, 65537: 7455, 120833:  8890, 133121: 8055, 184321:  8740, 4205569: 10418, 4206593:  9352, 8058881: 11726, 8380417:  8441, 8404993:  9156 },
"poly_ntt"          : { 3329: 8591, 7681: 8483, 12289: 9589, 40961: 10783, 65537: 8619, 120833: 10764, 133121: 9958, 184321: 10585, 4205569: 13455, 4206593: 12657, 8058881: 14365, 8380417: 10366, 8404993: 10922 },
"poly_poly_addsub"  : { 3329: 5022, 7681: 5290, 12289: 5523, 40961:  5717, 65537: 5464, 120833:  5950, 133121: 5688, 184321:  6125, 4205569:  6422, 4206593:  6498, 8058881:  6862, 8380417:  5921, 8404993:  6071 },
"poly_poly_mul"     : { 3329: 7557, 7681: 7347, 12289: 8075, 40961:  9046, 65537: 7464, 120833:  8900, 133121: 8066, 184321:  8753, 4205569: 10433, 4206593:  9367, 8058881: 11734, 8380417:  8454, 8404993:  9173 },
"poly_const_addsub" : { 3329: 3558, 7681: 3581, 12289: 3640, 40961:  3640, 65537: 3630, 120833:  3630, 133121: 3611, 184321:  3644, 4205569:  3653, 4206593:  3655, 8058881:  3620, 8380417:  3611, 8404993:  3628 },
"poly_const_mul"    : { 3329: 5946, 7681: 5736, 12289: 6134, 40961:  6940, 65537: 5794, 120833:  7144, 133121: 6396, 184321:  7142, 4205569:  8822, 4206593:  7756, 8058881:  9939, 8380417:  7046, 8404993:  7562 },
"poly_const_and"    : 3504,
"poly_const_or"     : 3552,
"poly_const_xor"    : 3514,
"poly_const_shift"  : 3484,
"sample_rej"        : 6755,
"sample_bin"        : 7545,
"sample_cdt"        : 2764,
"sample_uni"        : 7573,
"sample_tri_1"      : 3645,
"sample_tri_2"      : 3627,
"sample_tri_3"      : 6791,
}

# Instruction decode and execute
def instr_exec(instr, iter_count):
    global keccak_buf
    global proc_regs
    global poly_mem
    global poly_tmp
    global param_n
    global param_q
    global ticks
    global pc
    global power

    instr_t = instr.replace(" ", "")

    # INSTRUCTION - Parameter Configuration
    matchObj = re.match(r'config\(n=(\d+),q=(\d+)\)', instr_t, re.M|re.I)
    if matchObj:
        param_n = int(matchObj.group(1))
        param_q = int(matchObj.group(2))
        #print("config: n = %d, q = %d" % (param_n, param_q))
        if param_n not in valid_n:
            print("\n[Line %4d] %s\nERROR: Unsupported parameter \"n = %d\" (Valid \"n\": %s)\n" % (lines[pc], instr, param_n, valid_n))
            exit()
        if param_q not in valid_q:
            print("\n[Line %4d] %s\nERROR: Unsupported parameter \"q = %d\" (Valid prime \"q\": %s)\n" % (lines[pc], instr, param_q, valid_q))
            exit()
        # Initialize polynomial memory
        poly_mem = [[0 for i in range(param_n)] for j in range(int(8192/param_n))]
        poly_tmp = [0 for i in range(param_n)]
        #poly_mem = np.zeros((int(8192/param_n), param_n))
        #poly_tmp = np.zeros((param_n))
        #poly_mem = np.array(poly_mem, dtype=np.int64).tolist()
        #poly_tmp = np.array(poly_mem, dtype=np.int64).tolist()
        pc = pc + 1
        ticks = ticks + 2
        power = power + ([idd_dict["ctrl"]]*2)
        return 0

    # INSTRUCTION - Register Write Operation
    matchObj = re.match(r'c(\d)=(\d+)', instr_t, re.M|re.I)
    if matchObj:
        reg = int(matchObj.group(1))
        val = int(matchObj.group(2))
        if reg > 1:
            print("\n[Line %4d] %s\nERROR: No such register \"c%d\", please use \"c0\" or \"c1\"\n" % (lines[pc], instr, reg))
            exit()
        if val >= 2**16:
            print("\n[Line %4d] %s\nERROR: Value %s too big for 16-bit register \"c%d\"\n" % (lines[pc], instr, val, reg))
            exit()
        # Update register value
        proc_regs["c%s" % reg] = val
        pc = pc + 1
        ticks = ticks + 2
        power = power + ([idd_dict["ctrl"]]*2)
        return 1
    matchObj = re.match(r'c(\d)=c(\d)([\+\-])(\d+)', instr_t, re.M|re.I)
    if matchObj:
        reg_dst = int(matchObj.group(1))
        reg_src = int(matchObj.group(2))
        val = int(matchObj.group(4))
        if reg_dst > 1:
            print("\n[Line %4d] %s\nERROR: No such register \"c%d\", please use \"c0\" or \"c1\"\n" % (lines[pc], instr, reg_dst))
            exit()
        if reg_src > 1:
            print("\n[Line %4d] %s\nERROR: No such register \"c%d\", please use \"c0\" or \"c1\"\n" % (lines[pc], instr, reg_src))
            exit()
        if reg_dst != reg_src:
            print("\n[Line %4d] %s\nERROR: Must use \"c0 = c0 +/- <val>\" or \"c1 = c1 +/- <val>\"\n" % (lines[pc], instr))
            exit()
        if val >= 2**16:
            print("\n[Line %4d] %s\nERROR: Value %d too big for 16-bit register \"c%d\"\n" % (lines[pc], instr, val, reg_dst))
            exit()
        # Update register value
        if matchObj.group(3) == "+":
            proc_regs["c%d" % reg_dst] = (proc_regs["c%d" % reg_dst] + val) % 2**16
        if matchObj.group(3) == "-":
            proc_regs["c%d" % reg_dst] = (proc_regs["c%d" % reg_dst] - val) % 2**16
        pc = pc + 1
        ticks = ticks + 2
        power = power + ([idd_dict["reg_alu"]]*2)
        return 1
    matchObj = re.match(r'reg=(\d+)', instr_t, re.M|re.I)
    if matchObj:
        val = int(matchObj.group(1))
        if val >= 2**24:
            print("\n[Line %4d] %s\nERROR: Value %d too big for 24-bit register \"reg\"\n" % (lines[pc], instr, val))
            exit()
        # Update register value
        proc_regs["reg"] = val
        pc = pc + 1
        ticks = ticks + 2
        power = power + ([idd_dict["ctrl"]]*2)
        return 1
    matchObj = re.match(r'tmp=(\d+)', instr_t, re.M|re.I)
    if matchObj:
        val = int(matchObj.group(1))
        if val >= 2**24:
            print("\n[Line %4d] %s\nERROR: Value %d too big for 24-bit register \"tmp\"\n" % (lines[pc], instr, val))
            exit()
        # Update register value
        proc_regs["tmp"] = val
        pc = pc + 1
        ticks = ticks + 2
        power = power + ([idd_dict["ctrl"]]*2)
        return 1
    matchObj = re.match(r'reg=tmp', instr_t, re.M|re.I)
    if matchObj:
        # Update register value
        proc_regs["reg"] = proc_regs["tmp"]
        pc = pc + 1
        ticks = ticks + 2
        power = power + ([idd_dict["ctrl"]]*2)
        return 1

    # INSTRUCTION - Register ALU Operation
    matchObj = re.match(r'tmp=tmp([\+\-\*&\|\^><][><]*)reg', instr_t, re.M|re.I)
    if matchObj:
        op = matchObj.group(1)
        #print("op: %s" % op)
        if op == "+":
            # Update register value
            proc_regs["tmp"] = (proc_regs["tmp"] + proc_regs["reg"]) % param_q
        elif op == "-":
            # Update register value
            proc_regs["tmp"] = (proc_regs["tmp"] - proc_regs["reg"]) % param_q
        elif op == "*":
            # Update register value
            proc_regs["tmp"] = (proc_regs["tmp"] * proc_regs["reg"]) % param_q
        elif op == "&":
            # Update register value
            proc_regs["tmp"] = proc_regs["tmp"] & proc_regs["reg"]
        elif op == "|":
            # Update register value
            proc_regs["tmp"] = proc_regs["tmp"] | proc_regs["reg"]
        elif op == "^":
            # Update register value
            proc_regs["tmp"] = proc_regs["tmp"] ^ proc_regs["reg"]
        elif op == ">>":
            # Update register value
            if proc_regs["reg"] < 24: 
                proc_regs["tmp"] = (proc_regs["tmp"] >> proc_regs["reg"]) % 2**24
            else:
                proc_regs["tmp"] = 0
        elif op == "<<":
            # Update register value
            if proc_regs["reg"] < 24:
                proc_regs["tmp"] = (proc_regs["tmp"] << proc_regs["reg"]) % 2**24
            else:
                proc_regs["tmp"] = 0
        else:
            print("\n[Line %4d] %s\nERROR: Unsupported operation \"%s\", allowed operators are {+, -, *, &, |, ^, >>, <<}\n" % (lines[pc], instr, op))
            exit()
        pc = pc + 1
        ticks = ticks + 2
        power = power + ([idd_dict["reg_alu"]]*2)
        return 1

    # INSTRUCTION - Register Polynomial Operation
    matchObj = re.match(r'reg=\(poly=(\d+)\)\[(\d+)\]', instr_t, re.M|re.I)
    if matchObj:
        poly = int(matchObj.group(1))
        index = int(matchObj.group(2))
        if poly >= int(8192/param_n):
            print("\n[Line %4d] %s\nERROR: No such polynomial \"poly = %d\", allowed polynomials for n = %d are 0 to %d\n" % (lines[pc], instr, poly, param_n, int(8192/param_n)))
            exit()
        if index >= param_n:
            print("\n[Line %4d] %s\nERROR: Index \"%d\" out of range, allowed indices for n = %d are 0 to %d\n" % (lines[pc], instr, poly, param_n, param_n))
            exit()
        # Read polynomial coefficient and update register value
        proc_regs["reg"] = poly_mem[poly][index]
        cycles = 2 + 1 + 2
        pc = pc + 1
        ticks = ticks + cycles
        power = power + ([idd_dict["reg_poly"]]*cycles)
        return 2
    matchObj = re.match(r'reg=\(poly=(\d+)\)\[c(\d)\]', instr_t, re.M|re.I)
    if matchObj:
        poly = int(matchObj.group(1))
        reg = int(matchObj.group(2))
        if poly >= int(8192/param_n):
            print("\n[Line %4d] %s\nERROR: No such polynomial \"poly = %d\", allowed polynomials for n = %d are 0 to %d\n" % (lines[pc], instr, poly, param_n, int(8192/param_n)))
            exit()
        if int(matchObj.group(1)) > 1:
            print("\n[Line %4d] %s\nERROR: No such register \"c%d\", please use \"c0\" or \"c1\"\n" % (lines[pc], instr, reg))
            exit()
        # Read polynomial coefficient and update register value
        proc_regs["reg"] = poly_mem[poly][proc_regs["c%d" % reg] % param_n]
        cycles = 2 + 1 + 2
        pc = pc + 1
        ticks = ticks + cycles
        power = power + ([idd_dict["reg_poly"]]*cycles)
        return 2
    matchObj = re.match(r'\(poly=(\d+)\)\[(\d+)\]=reg', instr_t, re.M|re.I)
    if matchObj:
        poly = int(matchObj.group(1))
        index = int(matchObj.group(2))
        if poly >= int(8192/param_n):
            print("\n[Line %4d] %s\nERROR: No such polynomial \"poly = %d\", allowed polynomials for n = %d are 0 to %d\n" % (lines[pc], instr, poly, param_n, int(8192/param_n)))
            exit()
        if index >= param_n:
            print("\n[Line %4d] %s\nERROR: Index \"%d\" out of range, allowed indices for n = %d are 0 to %d\n" % (lines[pc], instr, poly, param_n, param_n))
            exit()
        # Read register value and update polynomial coefficient
        poly_mem[poly][index] = proc_regs["reg"]
        cycles = 2 + 1 + 1
        pc = pc + 1
        ticks = ticks + cycles
        power = power + ([idd_dict["reg_poly"]]*cycles)
        return 2
    matchObj = re.match(r'\(poly=(\d+)\)\[c(\d)\]=reg', instr_t, re.M|re.I)
    if matchObj:
        poly = int(matchObj.group(1))
        reg = int(matchObj.group(2))
        if poly >= int(8192/param_n):
            print("\n[Line %4d] %s\nERROR: No such polynomial \"poly = %d\", allowed polynomials for n = %d are 0 to %d\n" % (lines[pc], instr, poly, param_n, int(8192/param_n)))
            exit()
        if reg > 1:
            print("\n[Line %4d] %s\nERROR: No such register \"c%d\", please use \"c0\" or \"c1\"\n" % (lines[pc], instr, reg))
            exit()
        # Read register value and update polynomial coefficient
        poly_mem[poly][proc_regs["c%d" % reg] % param_n] = proc_regs["reg"]
        cycles = 2 + 1 + 1
        pc = pc + 1
        ticks = ticks + cycles
        power = power + ([idd_dict["reg_poly"]]*cycles)
        return 2

    # INSTRUCTION - Polynomial Absolute Maximum in range [-q/2, + q/2]
    matchObj = re.match(r'reg=max\(poly=(\d+)\)', instr_t, re.M|re.I)
    if matchObj:
        poly = int(matchObj.group(1))
        if poly >= int(8192/param_n):
            print("\n[Line %4d] %s\nERROR: No such polynomial \"poly = %d\", allowed polynomials for n = %d are 0 to %d\n" % (lines[pc], instr, poly, param_n, int(8192/param_n)))
            exit()
        # Compute maximum of coefficients and update register value
        proc_regs["reg"] = 0
        for i in range(param_n):
            if poly_mem[poly][i] < int(param_q/2) and poly_mem[poly][i] > proc_regs["reg"]:
                proc_regs["reg"] = poly_mem[poly][i]
            if poly_mem[poly][i] >= int(param_q/2) and (param_q - poly_mem[poly][i]) > proc_regs["reg"]:
                proc_regs["reg"] = (param_q - poly_mem[poly][i])
        cycles = 2 + 1 + 1 + param_n
        pc = pc + 1
        ticks = ticks + cycles
        power = power + ([idd_dict["poly_max_elems"]]*cycles)
        return 2

    # INSTRUCTION - Polynomial Sum of Coefficients in range [-q/2, + q/2]
    matchObj = re.match(r'reg=sum\(poly=(\d+)\)', instr_t, re.M|re.I)
    if matchObj:
        poly = int(matchObj.group(1))
        if poly >= int(8192/param_n):
            print("\n[Line %4d] %s\nERROR: No such polynomial \"poly = %d\", allowed polynomials for n = %d are 0 to %d\n" % (lines[pc], instr, poly, param_n, int(8192/param_n)))
            exit()
        # Compute sum of coefficients and update register value
        proc_regs["reg"] = 0
        for i in range(param_n):
            if poly_mem[poly][i] < int(param_q/2):
                proc_regs["reg"] = proc_regs["reg"] + poly_mem[poly][i]
            if poly_mem[poly][i] >= int(param_q/2):
                proc_regs["reg"] = proc_regs["reg"] + (poly_mem[poly][i] - param_q)
        proc_regs["reg"] = abs(proc_regs["reg"])
        #print("sum = %d" % proc_regs["reg"])
        cycles = 2 + 1 + 1 + param_n
        pc = pc + 1
        ticks = ticks + cycles
        power = power + ([idd_dict["poly_sum_elems"]]*cycles)
        return 2

    # INSTRUCTION - Polynomial Number Theoretic Transform
    matchObj = re.match(r'transform\(mode=(DI[FT]_I{0,1}NTT),poly_dst=(\d+),poly_src=(\d+)\)', instr_t, re.M|re.I)
    if matchObj:
        mode = matchObj.group(1)
        poly_dst = int(matchObj.group(2))
        poly_src = int(matchObj.group(3))
        if poly_dst >= int(8192/param_n):
            print("\n[Line %4d] %s\nERROR: No such polynomial \"poly_dst = %d\", allowed polynomials for n = %d are 0 to %d\n" % (lines[pc], instr, poly_dst, param_n, int(8192/param_n)))
            exit()
        if poly_src >= int(8192/param_n):
            print("\n[Line %4d] %s\nERROR: No such polynomial \"poly_src = %d\", allowed polynomials for n = %d are 0 to %d\n" % (lines[pc], instr, poly_src, param_n, int(8192/param_n)))
            exit()
        if not ((poly_src < int(4096/param_n) and poly_dst >= int(4096/param_n)) or (poly_dst < int(4096/param_n) and poly_src >= int(4096/param_n))):
            print("\n[Line %4d] %s\nERROR: Polynomial pair \"poly_dst = %d, poly_src = %d\" is not allowed for n = %d, ensure \"poly_dst < %d, poly_src >= %d\" or \"poly_src < %d, poly_dst >= %d\"\n" % (lines[pc], instr, poly_dst, poly_src, param_n, int(4096/param_n), int(4096/param_n), int(4096/param_n), int(4096/param_n)))
            exit()
        # Compute transform and update polynomial coefficients
        if mode == "DIF_NTT":
            # assume standard input, bit-reversed output
            cycles = dif_ntt(param_n, param_q, poly_mem[poly_src], lines[pc], instr)
            poly_mem[poly_dst] = poly_mem[poly_src].copy()
            poly_mem[poly_src] = [(random.getrandbits(24) % param_q) for i in range(param_n)] # Source polynomial gets clobbered
        if mode == "DIT_NTT":
            # assume bit-reversed input, standard output
            cycles = dit_ntt(param_n, param_q, poly_mem[poly_src], lines[pc], instr)
            poly_mem[poly_dst] = poly_mem[poly_src].copy()
            poly_mem[poly_src] = [(random.getrandbits(24) % param_q) for i in range(param_n)] # Source polynomial gets clobbered
        if mode == "DIF_INTT":
            # assume standard input, bit-reversed output
            cycles = dif_intt(param_n, param_q, poly_mem[poly_src], lines[pc], instr)
            poly_mem[poly_dst] = poly_mem[poly_src].copy()
            poly_mem[poly_src] = [(random.getrandbits(24) % param_q) for i in range(param_n)] # Source polynomial gets clobbered
        if mode == "DIT_INTT":
            # assume bit-reversed input, standard output
            cycles = dit_intt(param_n, param_q, poly_mem[poly_src], lines[pc], instr)
            poly_mem[poly_dst] = poly_mem[poly_src].copy()
            poly_mem[poly_src] = [(random.getrandbits(24) % param_q) for i in range(param_n)] # Source polynomial gets clobbered
        pc = pc + 1
        ticks = ticks + cycles
        power = power + ([idd_dict["poly_ntt"][param_q]]*cycles)
        # Need to copy polynomial when n is an even power of 2
        if int(math.log(param_n,2)) % 2 == 0:
            cycles = 2 + 1 + 1 + int(param_n/4)
            ticks = ticks + cycles
            power = power + ([idd_dict["poly_copy"]]*cycles)
        return 3

    # INSTRUCTION - Pre- and Post- Processing for Negative-Wrapped Convolution
    matchObj = re.match(r'mult_psi\(poly=(\d+)\)', instr_t, re.M|re.I)
    if matchObj:
        poly = int(matchObj.group(1))
        if poly >= int(8192/param_n):
            print("\n[Line %4d] %s\nERROR: No such polynomial \"poly = %d\", allowed polynomials for n = %d are 0 to %d\n" % (lines[pc], instr, poly, param_n, int(8192/param_n)))
            exit()
        # Pre-process polynomial coefficients
        cycles = mult_psi(param_n, param_q, poly_mem[poly], lines[pc], instr)
        proc_regs["tmp"] = random.getrandbits(24) # "tmp" register gets clobbered
        pc = pc + 1
        ticks = ticks + cycles
        power = power + ([idd_dict["poly_mult_psi"][param_q]]*cycles)
        return 3
    matchObj = re.match(r'mult_psi_inv\(poly=(\d+)\)', instr_t, re.M|re.I)
    if matchObj:
        poly = int(matchObj.group(1))
        if poly >= int(8192/param_n):
            print("\n[Line %4d] %s\nERROR: No such polynomial \"poly = %d\", allowed polynomials for n = %d are 0 to %d\n" % (lines[pc], instr, poly, param_n, int(8192/param_n)))
            exit()
        # Pre-process polynomial coefficients
        cycles = mult_psi_inv(param_n, param_q, poly_mem[poly], lines[pc], instr)
        proc_regs["tmp"] = random.getrandbits(24) # "tmp" register gets clobbered
        pc = pc + 1
        ticks = ticks + cycles
        power = power + ([idd_dict["poly_mult_psi"][param_q]]*cycles)
        return 3

    # PSEUDO-INSTRUCTION - Rejection Sampling
    matchObj = re.match(r'rej_sample\(prng=SHAKE-(\d+),seed=r(\d),c0=(\d+),c1=(\d+),poly=(\d+)\)', instr_t, re.M|re.I)
    if matchObj:
        mode = int(matchObj.group(1))
        reg = int(matchObj.group(2))
        val_c0 = int(matchObj.group(3))
        val_c1 = int(matchObj.group(4))
        poly = int(matchObj.group(5))
        if mode != 128 and mode != 256:
            print("\n[Line %4d] %s\nERROR: Only SHAKE-128 and SHAKE-256 are supported\n" % (lines[pc], instr))
            exit()
        if reg != 0 and reg != 1:
            print("\n[Line %4d] %s\nERROR: No such register \"r%d\", allowed registers are r0 and r1\n" % (lines[pc], instr, reg))
            exit()
        if val_c0 >= 2**16:
            print("\n[Line %4d] %s\nERROR: Value %d too big for 16-bit register \"c0\"\n" % (lines[pc], instr, val_c0))
            exit()
        if val_c1 >= 2**16:
            print("\n[Line %4d] %s\nERROR: Value %d too big for 16-bit register \"c1\"\n" % (lines[pc], instr, val_c1))
            exit()
        if poly >= int(8192/param_n):
            print("\n[Line %4d] %s\nERROR: No such polynomial \"poly = %d\", allowed polynomials for n = %d are 0 to %d\n" % (lines[pc], instr, poly, param_n, int(8192/param_n)))
            exit()
        # Update register values
        proc_regs["c0"] = val_c0
        proc_regs["c1"] = val_c1
        cycles = 2 + 2
        # Sample polynomial coefficients
        cycles = cycles + rejection_sample(param_n, param_q, mode, hex(proc_regs["r%d" % reg])[2:].rstrip("L").rjust(64,'0') + hex(proc_regs["c0"])[2:].rstrip("L").rjust(4,'0') + hex(proc_regs["c1"])[2:].rstrip("L").rjust(4,'0'), poly_mem[poly])
        pc = pc + 1
        ticks = ticks + cycles
        power = power + ([idd_dict["sample_rej"]]*cycles)
        return 4

    # PSEUDO-INSTRUCTION - Binomial Sampling
    matchObj = re.match(r'bin_sample\(prng=SHAKE-(\d+),seed=r(\d),c0=(\d+),c1=(\d+),k=(\d+),poly=(\d+)\)', instr_t, re.M|re.I)
    if matchObj:
        mode = int(matchObj.group(1))
        reg = int(matchObj.group(2))
        val_c0 = int(matchObj.group(3))
        val_c1 = int(matchObj.group(4))
        param_k = int(matchObj.group(5))
        poly = int(matchObj.group(6))
        if mode != 128 and mode != 256:
            print("\n[Line %4d] %s\nERROR: Only SHAKE-128 and SHAKE-256 are supported\n" % (lines[pc], instr))
            exit()
        if reg != 0 and reg != 1:
            print("\n[Line %4d] %s\nERROR: No such register \"r%d\", allowed registers are r0 and r1\n" % (lines[pc], instr, reg))
            exit()
        if val_c0 >= 2**16:
            print("\n[Line %4d] %s\nERROR: Value %d too big for 16-bit register \"c0\"\n" % (lines[pc], instr, val_c0))
            exit()
        if val_c1 >= 2**16:
            print("\n[Line %4d] %s\nERROR: Value %d too big for 16-bit register \"c1\"\n" % (lines[pc], instr, val_c1))
            exit()
        if param_k < 1 or param_k > 32:
            print("\n[Line %4d] %s\nERROR: Value of \"k\" must be in the range 1 to 32\n" % (lines[pc], instr))
            exit()
        if poly >= int(8192/param_n):
            print("\n[Line %4d] %s\nERROR: No such polynomial \"poly = %d\", allowed polynomials for n = %d are 0 to %d\n" % (lines[pc], instr, poly, param_n, int(8192/param_n)))
            exit()
        # Update register values
        proc_regs["c0"] = val_c0
        proc_regs["c1"] = val_c1
        cycles = 2 + 2
        # Sample polynomial coefficients
        cycles = cycles + binomial_sample(param_n, param_q, param_k, mode, hex(proc_regs["r%d" % reg])[2:].rstrip("L").rjust(64,'0') + hex(proc_regs["c0"])[2:].rstrip("L").rjust(4,'0') + hex(proc_regs["c1"])[2:].rstrip("L").rjust(4,'0'), poly_mem[poly])
        pc = pc + 1
        ticks = ticks + cycles
        power = power + ([idd_dict["sample_bin"]]*cycles)
        return 4

    # PSEUDO-INSTRUCTION - Cumulative Distribution Table Sampling
    matchObj = re.match(r'cdt_sample\(prng=SHAKE-(\d+),seed=r(\d),c0=(\d+),c1=(\d+),r=(\d+),poly=(\d+)\)', instr_t, re.M|re.I)
    if matchObj:
        mode = int(matchObj.group(1))
        reg = int(matchObj.group(2))
        val_c0 = int(matchObj.group(3))
        val_c1 = int(matchObj.group(4))
        param_r = int(matchObj.group(5))
        poly = int(matchObj.group(6))
        if mode != 128 and mode != 256:
            print("\n[Line %4d] %s\nERROR: Only SHAKE-128 and SHAKE-256 are supported\n" % (lines[pc], instr))
            exit()
        if reg != 0 and reg != 1:
            print("\n[Line %4d] %s\nERROR: No such register \"r%d\", allowed registers are r0 and r1\n" % (lines[pc], instr, reg))
            exit()
        if val_c0 >= 2**16:
            print("\n[Line %4d] %s\nERROR: Value %d too big for 16-bit register \"c0\"\n" % (lines[pc], instr, val_c0))
            exit()
        if val_c1 >= 2**16:
            print("\n[Line %4d] %s\nERROR: Value %d too big for 16-bit register \"c1\"\n" % (lines[pc], instr, val_c1))
            exit()
        if param_r < 1 or param_r > 32:
            print("\n[Line %4d] %s\nERROR: Value of \"r\" must be in the range 1 to 32\n" % (lines[pc], instr))
            exit()
        if poly >= int(8192/param_n):
            print("\n[Line %4d] %s\nERROR: No such polynomial \"poly = %d\", allowed polynomials for n = %d are 0 to %d\n" % (lines[pc], instr, poly, param_n, int(8192/param_n)))
            exit()
        if "--cdt" not in sys.argv:
            print("\n[Line %4d] %s\nERROR: CDT not provided, please provide a valid CDT file to use CDT-based sampling\n" % (lines[pc], instr))
            exit()
        # Update register values
        proc_regs["c0"] = val_c0
        proc_regs["c1"] = val_c1
        cycles = 2 + 2
        # Sample polynomial coefficients
        cycles = cycles + cdt_sample(param_n, param_q, param_r, mode, hex(proc_regs["r%d" % reg])[2:].rstrip("L").rjust(64,'0') + hex(proc_regs["c0"])[2:].rstrip("L").rjust(4,'0') + hex(proc_regs["c1"])[2:].rstrip("L").rjust(4,'0'), cdt_mem, poly_mem[poly])
        pc = pc + 1
        ticks = ticks + cycles
        power = power + ([idd_dict["sample_cdt"]]*cycles)
        return 4

    # PSEUDO-INSTRUCTION - Uniform Sampling
    matchObj = re.match(r'uni_sample\(prng=SHAKE-(\d+),seed=r(\d),c0=(\d+),c1=(\d+),eta=(\d+),poly=(\d+)\)', instr_t, re.M|re.I)
    if matchObj:
        mode = int(matchObj.group(1))
        reg = int(matchObj.group(2))
        val_c0 = int(matchObj.group(3))
        val_c1 = int(matchObj.group(4))
        param_eta = int(matchObj.group(5))
        poly = int(matchObj.group(6))
        if mode != 128 and mode != 256:
            print("\n[Line %4d] %s\nERROR: Only SHAKE-128 and SHAKE-256 are supported\n" % (lines[pc], instr))
            exit()
        if reg != 0 and reg != 1:
            print("\n[Line %4d] %s\nERROR: No such register \"r%d\", allowed registers are r0 and r1\n" % (lines[pc], instr, reg))
            exit()
        if val_c0 >= 2**16:
            print("\n[Line %4d] %s\nERROR: Value %d too big for 16-bit register \"c0\"\n" % (lines[pc], instr, val_c0))
            exit()
        if val_c1 >= 2**16:
            print("\n[Line %4d] %s\nERROR: Value %d too big for 16-bit register \"c1\"\n" % (lines[pc], instr, val_c1))
            exit()
        if param_eta >= param_q:
            print("\n[Line %4d] %s\nERROR: Value of \"eta\" too large, must be less than %d\n" % (lines[pc], instr, param_q))
            exit()
        if poly >= int(8192/param_n):
            print("\n[Line %4d] %s\nERROR: No such polynomial \"poly = %d\", allowed polynomials for n = %d are 0 to %d\n" % (lines[pc], instr, poly, param_n, int(8192/param_n)))
            exit()
        # Update register values
        proc_regs["c0"] = val_c0
        proc_regs["c1"] = val_c1
        proc_regs["reg"] = param_eta
        cycles = 2 + 2 + 2
        # Sample polynomial coefficients
        cycles = cycles + uniform_sample(param_n, param_q, param_eta, mode, hex(proc_regs["r%d" % reg])[2:].rstrip("L").rjust(64,'0') + hex(proc_regs["c0"])[2:].rstrip("L").rjust(4,'0') + hex(proc_regs["c1"])[2:].rstrip("L").rjust(4,'0'), poly_mem[poly])
        pc = pc + 1
        ticks = ticks + cycles
        power = power + ([idd_dict["sample_uni"]]*cycles)
        return 4

    # PSEUDO-INSTRUCTION - Trinary Sampling #1
    matchObj = re.match(r'tri_sample_1\(prng=SHAKE-(\d+),seed=r(\d),c0=(\d+),c1=(\d+),m=(\d+),poly=(\d+)\)', instr_t, re.M|re.I)
    if matchObj:
        mode = int(matchObj.group(1))
        reg = int(matchObj.group(2))
        val_c0 = int(matchObj.group(3))
        val_c1 = int(matchObj.group(4))
        param_m = int(matchObj.group(5))
        poly = int(matchObj.group(6))
        if mode != 128 and mode != 256:
            print("\n[Line %4d] %s\nERROR: Only SHAKE-128 and SHAKE-256 are supported\n" % (lines[pc], instr))
            exit()
        if reg != 0 and reg != 1:
            print("\n[Line %4d] %s\nERROR: No such register \"r%d\", allowed registers are r0 and r1\n" % (lines[pc], instr, reg))
            exit()
        if val_c0 >= 2**16:
            print("\n[Line %4d] %s\nERROR: Value %d too big for 16-bit register \"c0\"\n" % (lines[pc], instr, val_c0))
            exit()
        if val_c1 >= 2**16:
            print("\n[Line %4d] %s\nERROR: Value %d too big for 16-bit register \"c1\"\n" % (lines[pc], instr, val_c1))
            exit()
        if param_m >= param_n:
            print("\n[Line %4d] %s\nERROR: Value of \"m\" too large, must be less than %d\n" % (lines[pc], instr, param_n))
            exit()
        if poly >= int(8192/param_n):
            print("\n[Line %4d] %s\nERROR: No such polynomial \"poly = %d\", allowed polynomials for n = %d are 0 to %d\n" % (lines[pc], instr, poly, param_n, int(8192/param_n)))
            exit()
        # Update register values
        proc_regs["c0"] = val_c0
        proc_regs["c1"] = val_c1
        cycles = 2 + 2
        # Sample polynomial coefficients
        cycles = cycles + trinary_sample_1(param_n, param_q, param_m, mode, hex(proc_regs["r%d" % reg])[2:].rstrip("L").rjust(64,'0') + hex(proc_regs["c0"])[2:].rstrip("L").rjust(4,'0') + hex(proc_regs["c1"])[2:].rstrip("L").rjust(4,'0'), poly_mem[poly])
        pc = pc + 1
        ticks = ticks + cycles
        power = power + ([idd_dict["sample_tri_1"]]*cycles)
        return 4

    # PSEUDO-INSTRUCTION - Trinary Sampling #2
    matchObj = re.match(r'tri_sample_2\(prng=SHAKE-(\d+),seed=r(\d),c0=(\d+),c1=(\d+),m0=(\d+),m1=(\d+),poly=(\d+)\)', instr_t, re.M|re.I)
    if matchObj:
        mode = int(matchObj.group(1))
        reg = int(matchObj.group(2))
        val_c0 = int(matchObj.group(3))
        val_c1 = int(matchObj.group(4))
        param_m0 = int(matchObj.group(5))
        param_m1 = int(matchObj.group(6))
        poly = int(matchObj.group(7))
        if mode != 128 and mode != 256:
            print("\n[Line %4d] %s\nERROR: Only SHAKE-128 and SHAKE-256 are supported\n" % (lines[pc], instr))
            exit()
        if reg != 0 and reg != 1:
            print("\n[Line %4d] %s\nERROR: No such register \"r%d\", allowed registers are r0 and r1\n" % (lines[pc], instr, reg))
            exit()
        if val_c0 >= 2**16:
            print("\n[Line %4d] %s\nERROR: Value %d too big for 16-bit register \"c0\"\n" % (lines[pc], instr, val_c0))
            exit()
        if val_c1 >= 2**16:
            print("\n[Line %4d] %s\nERROR: Value %d too big for 16-bit register \"c1\"\n" % (lines[pc], instr, val_c1))
            exit()
        if param_m0 >= param_n:
            print("\n[Line %4d] %s\nERROR: Value of \"m0\" too large, must be less than %d\n" % (lines[pc], instr, param_n))
            exit()
        if param_m1 >= param_n:
            print("\n[Line %4d] %s\nERROR: Value of \"m1\" too large, must be less than %d\n" % (lines[pc], instr, param_n))
            exit()
        if (param_m0 + param_m1) >= param_n:
            print("\n[Line %4d] %s\nERROR: Value of \"m0 + m1\" too large, must be less than %d\n" % (lines[pc], instr, param_n))
            exit()
        if poly >= int(8192/param_n):
            print("\n[Line %4d] %s\nERROR: No such polynomial \"poly = %d\", allowed polynomials for n = %d are 0 to %d\n" % (lines[pc], instr, poly, param_n, int(8192/param_n)))
            exit()
        # Update register values
        proc_regs["c0"] = val_c0
        proc_regs["c1"] = val_c1
        proc_regs["reg"] = param_m0 + (param_m1 * 2**12)
        cycles = 2 + 2 + 2
        # Sample polynomial coefficients
        cycles = cycles + trinary_sample_2(param_n, param_q, param_m0, param_m1, mode, hex(proc_regs["r%d" % reg])[2:].rstrip("L").rjust(64,'0') + hex(proc_regs["c0"])[2:].rstrip("L").rjust(4,'0') + hex(proc_regs["c1"])[2:].rstrip("L").rjust(4,'0'), poly_mem[poly])
        pc = pc + 1
        ticks = ticks + cycles
        power = power + ([idd_dict["sample_tri_2"]]*cycles)
        return 4

    # PSEUDO-INSTRUCTION - Trinary Sampling #3
    matchObj = re.match(r'tri_sample_3\(prng=SHAKE-(\d+),seed=r(\d),c0=(\d+),c1=(\d+),rho=1/(\d+),poly=(\d+)\)', instr_t, re.M|re.I)
    if matchObj:
        mode = int(matchObj.group(1))
        reg = int(matchObj.group(2))
        val_c0 = int(matchObj.group(3))
        val_c1 = int(matchObj.group(4))
        param_rho = int(matchObj.group(5))
        poly = int(matchObj.group(6))
        if mode != 128 and mode != 256:
            print("\n[Line %4d] %s\nERROR: Only SHAKE-128 and SHAKE-256 are supported\n" % (lines[pc], instr))
            exit()
        if reg != 0 and reg != 1:
            print("\n[Line %4d] %s\nERROR: No such register \"r%d\", allowed registers are r0 and r1\n" % (lines[pc], instr, reg))
            exit()
        if val_c0 >= 2**16:
            print("\n[Line %4d] %s\nERROR: Value %d too big for 16-bit register \"c0\"\n" % (lines[pc], instr, val_c0))
            exit()
        if val_c1 >= 2**16:
            print("\n[Line %4d] %s\nERROR: Value %d too big for 16-bit register \"c1\"\n" % (lines[pc], instr, val_c1))
            exit()
        if param_rho != 2 and param_rho != 4 and param_rho != 8 and param_rho != 16 and param_rho != 32 and param_rho != 64 and param_rho != 128:
            print("\n[Line %4d] %s\nERROR: Unsupported parameter \"rho = 1/%d\" (Valid \"rho\": [1/2, 1/4, 1/8, 1/16, 1/32, 1/64, 1/128])\n" % (lines[pc], instr, param_rho))
            exit()
        if poly >= int(8192/param_n):
            print("\n[Line %4d] %s\nERROR: No such polynomial \"poly = %d\", allowed polynomials for n = %d are 0 to %d\n" % (lines[pc], instr, poly, param_n, int(8192/param_n)))
            exit()
        # Update register values
        proc_regs["c0"] = val_c0
        proc_regs["c1"] = val_c1
        cycles = 2 + 2
        # Sample polynomial coefficients
        cycles = cycles + trinary_sample_3(param_n, param_q, param_rho, mode, hex(proc_regs["r%d" % reg])[2:].rstrip("L").rjust(64,'0') + hex(proc_regs["c0"])[2:].rstrip("L").rjust(4,'0') + hex(proc_regs["c1"])[2:].rstrip("L").rjust(4,'0'), poly_mem[poly])
        pc = pc + 1
        ticks = ticks + cycles
        power = power + ([idd_dict["sample_tri_3"]]*cycles)
        return 4

    # INSTRUCTION - Rejection Sampling
    matchObj = re.match(r'rej_sample\(prng=SHAKE-(\d+),seed=r(\d),poly=(\d+)\)', instr_t, re.M|re.I)
    if matchObj:
        mode = int(matchObj.group(1))
        reg = int(matchObj.group(2))
        poly = int(matchObj.group(3))
        if mode != 128 and mode != 256:
            print("\n[Line %4d] %s\nERROR: Only SHAKE-128 and SHAKE-256 are supported\n" % (lines[pc], instr))
            exit()
        if reg != 0 and reg != 1:
            print("\n[Line %4d] %s\nERROR: No such register \"r%d\", allowed registers are r0 and r1\n" % (lines[pc], instr, reg))
            exit()
        if poly >= int(8192/param_n):
            print("\n[Line %4d] %s\nERROR: No such polynomial \"poly = %d\", allowed polynomials for n = %d are 0 to %d\n" % (lines[pc], instr, poly, param_n, int(8192/param_n)))
            exit()
        # Sample polynomial coefficients
        cycles = rejection_sample(param_n, param_q, mode, hex(proc_regs["r%d" % reg])[2:].rstrip("L").rjust(64,'0') + hex(proc_regs["c0"])[2:].rstrip("L").rjust(4,'0') + hex(proc_regs["c1"])[2:].rstrip("L").rjust(4,'0'), poly_mem[poly])
        pc = pc + 1
        ticks = ticks + cycles
        power = power + ([idd_dict["sample_rej"]]*cycles)
        return 4

    # INSTRUCTION - Binomial Sampling
    matchObj = re.match(r'bin_sample\(prng=SHAKE-(\d+),seed=r(\d),k=(\d+),poly=(\d+)\)', instr_t, re.M|re.I)
    if matchObj:
        mode = int(matchObj.group(1))
        reg = int(matchObj.group(2))
        param_k = int(matchObj.group(3))
        poly = int(matchObj.group(4))
        if mode != 128 and mode != 256:
            print("\n[Line %4d] %s\nERROR: Only SHAKE-128 and SHAKE-256 are supported\n" % (lines[pc], instr))
            exit()
        if reg != 0 and reg != 1:
            print("\n[Line %4d] %s\nERROR: No such register \"r%d\", allowed registers are r0 and r1\n" % (lines[pc], instr, reg))
            exit()
        if param_k < 1 or param_k > 32:
            print("\n[Line %4d] %s\nERROR: Value of \"k\" must be in the range 1 to 32\n" % (lines[pc], instr))
            exit()
        if poly >= int(8192/param_n):
            print("\n[Line %4d] %s\nERROR: No such polynomial \"poly = %d\", allowed polynomials for n = %d are 0 to %d\n" % (lines[pc], instr, poly, param_n, int(8192/param_n)))
            exit()
        # Sample polynomial coefficients
        cycles = binomial_sample(param_n, param_q, param_k, mode, hex(proc_regs["r%d" % reg])[2:].rstrip("L").rjust(64,'0') + hex(proc_regs["c0"])[2:].rstrip("L").rjust(4,'0') + hex(proc_regs["c1"])[2:].rstrip("L").rjust(4,'0'), poly_mem[poly])
        pc = pc + 1
        ticks = ticks + cycles
        power = power + ([idd_dict["sample_bin"]]*cycles)
        return 4

    # INSTRUCTION - Cumulative Distribution Table Sampling
    matchObj = re.match(r'cdt_sample\(prng=SHAKE-(\d+),seed=r(\d),r=(\d+),poly=(\d+)\)', instr_t, re.M|re.I)
    if matchObj:
        mode = int(matchObj.group(1))
        reg = int(matchObj.group(2))
        param_r = int(matchObj.group(3))
        poly = int(matchObj.group(4))
        if mode != 128 and mode != 256:
            print("\n[Line %4d] %s\nERROR: Only SHAKE-128 and SHAKE-256 are supported\n" % (lines[pc], instr))
            exit()
        if reg != 0 and reg != 1:
            print("\n[Line %4d] %s\nERROR: No such register \"r%d\", allowed registers are r0 and r1\n" % (lines[pc], instr, reg))
            exit()
        if param_r < 1 or param_r > 32:
            print("\n[Line %4d] %s\nERROR: Value of \"r\" must be in the range 1 to 32\n" % (lines[pc], instr))
            exit()
        if poly >= int(8192/param_n):
            print("\n[Line %4d] %s\nERROR: No such polynomial \"poly = %d\", allowed polynomials for n = %d are 0 to %d\n" % (lines[pc], instr, poly, param_n, int(8192/param_n)))
            exit()
        if "--cdt" not in sys.argv:
            print("\n[Line %4d] %s\nERROR: CDT not provided, please provide a valid CDT file to use CDT-based sampling\n" % (lines[pc], instr))
            exit()
        # Sample polynomial coefficients
        cycles = cdt_sample(param_n, param_q, param_r, mode, hex(proc_regs["r%d" % reg])[2:].rstrip("L").rjust(64,'0') + hex(proc_regs["c0"])[2:].rstrip("L").rjust(4,'0') + hex(proc_regs["c1"])[2:].rstrip("L").rjust(4,'0'), cdt_mem, poly_mem[poly])
        pc = pc + 1
        ticks = ticks + cycles
        power = power + ([idd_dict["sample_cdt"]]*cycles)
        return 4

    # INSTRUCTION - Uniform Sampling
    matchObj = re.match(r'uni_sample\(prng=SHAKE-(\d+),seed=r(\d),eta=(\d+),poly=(\d+)\)', instr_t, re.M|re.I)
    if matchObj:
        mode = int(matchObj.group(1))
        reg = int(matchObj.group(2))
        param_eta = int(matchObj.group(3))
        poly = int(matchObj.group(4))
        if mode != 128 and mode != 256:
            print("\n[Line %4d] %s\nERROR: Only SHAKE-128 and SHAKE-256 are supported\n" % (lines[pc], instr))
            exit()
        if reg != 0 and reg != 1:
            print("\n[Line %4d] %s\nERROR: No such register \"r%d\", allowed registers are r0 and r1\n" % (lines[pc], instr, reg))
            exit()
        if param_eta >= param_q:
            print("\n[Line %4d] %s\nERROR: Value of \"eta\" too large, must be less than %d\n" % (lines[pc], instr, param_q))
            exit()
        if poly >= int(8192/param_n):
            print("\n[Line %4d] %s\nERROR: No such polynomial \"poly = %d\", allowed polynomials for n = %d are 0 to %d\n" % (lines[pc], instr, poly, param_n, int(8192/param_n)))
            exit()
        # Update register values
        proc_regs["reg"] = param_eta
        cycles = 2
        # Sample polynomial coefficients
        cycles = cycles + uniform_sample(param_n, param_q, param_eta, mode, hex(proc_regs["r%d" % reg])[2:].rstrip("L").rjust(64,'0') + hex(proc_regs["c0"])[2:].rstrip("L").rjust(4,'0') + hex(proc_regs["c1"])[2:].rstrip("L").rjust(4,'0'), poly_mem[poly])
        pc = pc + 1
        ticks = ticks + cycles
        power = power + ([idd_dict["sample_uni"]]*cycles)
        return 4

    # INSTRUCTION - Trinary Sampling #1
    matchObj = re.match(r'tri_sample_1\(prng=SHAKE-(\d+),seed=r(\d),m=(\d+),poly=(\d+)\)', instr_t, re.M|re.I)
    if matchObj:
        mode = int(matchObj.group(1))
        reg = int(matchObj.group(2))
        param_m = int(matchObj.group(3))
        poly = int(matchObj.group(4))
        if mode != 128 and mode != 256:
            print("\n[Line %4d] %s\nERROR: Only SHAKE-128 and SHAKE-256 are supported\n" % (lines[pc], instr))
            exit()
        if reg != 0 and reg != 1:
            print("\n[Line %4d] %s\nERROR: No such register \"r%d\", allowed registers are r0 and r1\n" % (lines[pc], instr, reg))
            exit()
        if param_m >= param_n:
            print("\n[Line %4d] %s\nERROR: Value of \"m\" too large, must be less than %d\n" % (lines[pc], instr, param_n))
            exit()
        if poly >= int(8192/param_n):
            print("\n[Line %4d] %s\nERROR: No such polynomial \"poly = %d\", allowed polynomials for n = %d are 0 to %d\n" % (lines[pc], instr, poly, param_n, int(8192/param_n)))
            exit()
        # Sample polynomial coefficients
        cycles = trinary_sample_1(param_n, param_q, param_m, mode, hex(proc_regs["r%d" % reg])[2:].rstrip("L").rjust(64,'0') + hex(proc_regs["c0"])[2:].rstrip("L").rjust(4,'0') + hex(proc_regs["c1"])[2:].rstrip("L").rjust(4,'0'), poly_mem[poly])
        pc = pc + 1
        ticks = ticks + cycles
        power = power + ([idd_dict["sample_tri_1"]]*cycles)
        return 4

    # INSTRUCTION - Trinary Sampling #2
    matchObj = re.match(r'tri_sample_2\(prng=SHAKE-(\d+),seed=r(\d),m0=(\d+),m1=(\d+),poly=(\d+)\)', instr_t, re.M|re.I)
    if matchObj:
        mode = int(matchObj.group(1))
        reg = int(matchObj.group(2))
        param_m0 = int(matchObj.group(3))
        param_m1 = int(matchObj.group(4))
        poly = int(matchObj.group(5))
        if mode != 128 and mode != 256:
            print("\n[Line %4d] %s\nERROR: Only SHAKE-128 and SHAKE-256 are supported\n" % (lines[pc], instr))
            exit()
        if reg != 0 and reg != 1:
            print("\n[Line %4d] %s\nERROR: No such register \"r%d\", allowed registers are r0 and r1\n" % (lines[pc], instr, reg))
            exit()
        if param_m0 >= param_n:
            print("\n[Line %4d] %s\nERROR: Value of \"m0\" too large, must be less than %d\n" % (lines[pc], instr, param_n))
            exit()
        if param_m1 >= param_n:
            print("\n[Line %4d] %s\nERROR: Value of \"m1\" too large, must be less than %d\n" % (lines[pc], instr, param_n))
            exit()
        if (param_m0 + param_m1) >= param_n:
            print("\n[Line %4d] %s\nERROR: Value of \"m0 + m1\" too large, must be less than %d\n" % (lines[pc], instr, param_n))
            exit()
        if poly >= int(8192/param_n):
            print("\n[Line %4d] %s\nERROR: No such polynomial \"poly = %d\", allowed polynomials for n = %d are 0 to %d\n" % (lines[pc], instr, poly, param_n, int(8192/param_n)))
            exit()
        # Update register values
        proc_regs["reg"] = param_m0 + (param_m1 * 2**12)
        cycles = 2
        # Sample polynomial coefficients
        cycles = cycles + trinary_sample_2(param_n, param_q, param_m0, param_m1, mode, hex(proc_regs["r%d" % reg])[2:].rstrip("L").rjust(64,'0') + hex(proc_regs["c0"])[2:].rstrip("L").rjust(4,'0') + hex(proc_regs["c1"])[2:].rstrip("L").rjust(4,'0'), poly_mem[poly])
        pc = pc + 1
        ticks = ticks + cycles
        power = power + ([idd_dict["sample_tri_2"]]*cycles)
        return 4

    # INSTRUCTION - Trinary Sampling #3
    matchObj = re.match(r'tri_sample_3\(prng=SHAKE-(\d+),seed=r(\d),rho=1/(\d+),poly=(\d+)\)', instr_t, re.M|re.I)
    if matchObj:
        mode = int(matchObj.group(1))
        reg = int(matchObj.group(2))
        param_rho = int(matchObj.group(3))
        poly = int(matchObj.group(4))
        if mode != 128 and mode != 256:
            print("\n[Line %4d] %s\nERROR: Only SHAKE-128 and SHAKE-256 are supported\n" % (lines[pc], instr))
            exit()
        if reg != 0 and reg != 1:
            print("\n[Line %4d] %s\nERROR: No such register \"r%d\", allowed registers are r0 and r1\n" % (lines[pc], instr, reg))
            exit()
        if param_rho != 2 and param_rho != 4 and param_rho != 8 and param_rho != 16 and param_rho != 32 and param_rho != 64 and param_rho != 128:
            print("\n[Line %4d] %s\nERROR: Unsupported parameter \"rho = 1/%d\" (Valid \"rho\": [1/2, 1/4, 1/8, 1/16, 1/32, 1/64, 1/128])\n" % (lines[pc], instr, param_rho))
            exit()
        if poly >= int(8192/param_n):
            print("\n[Line %4d] %s\nERROR: No such polynomial \"poly = %d\", allowed polynomials for n = %d are 0 to %d\n" % (lines[pc], instr, poly, param_n, int(8192/param_n)))
            exit()
        # Sample polynomial coefficients
        cycles = trinary_sample_3(param_n, param_q, param_rho, mode, hex(proc_regs["r%d" % reg])[2:].rstrip("L").rjust(64,'0') + hex(proc_regs["c0"])[2:].rstrip("L").rjust(4,'0') + hex(proc_regs["c1"])[2:].rstrip("L").rjust(4,'0'), poly_mem[poly])
        pc = pc + 1
        ticks = ticks + cycles
        power = power + ([idd_dict["sample_tri_3"]]*cycles)
        return 4
    
    # INSTRUCTION - Polynomial Initialization
    matchObj = re.match(r'init\(poly=(\d+)\)', instr_t, re.M|re.I)
    if matchObj:
        poly = int(matchObj.group(1))
        if poly >= int(8192/param_n):
            print("\n[Line %4d] %s\nERROR: No such polynomial \"poly = %d\", allowed polynomials for n = %d are 0 to %d\n" % (lines[pc], instr, poly, param_n, int(8192/param_n)))
            exit()
        # Set all polynomial coefficients to zero
        poly_mem[poly] = [0 for i in range(param_n)]
        cycles = 2 + 1 + 1 + int(param_n/4)
        pc = pc + 1
        ticks = ticks + cycles
        power = power + ([idd_dict["poly_init"]]*cycles)
        return 5

    # INSTRUCTION - Polynomial Copy
    matchObj = re.match(r'poly_copy\(poly_dst=(\d+),poly_src=(\d+)\)', instr_t, re.M|re.I)
    if matchObj:
        poly_dst = int(matchObj.group(1))
        poly_src = int(matchObj.group(2))
        if poly_dst >= int(8192/param_n):
            print("\n[Line %4d] %s\nERROR: No such polynomial \"poly_dst = %d\", allowed polynomials for n = %d are 0 to %d\n" % (lines[pc], instr, poly_dst, param_n, int(8192/param_n)))
            exit()
        if poly_src >= int(8192/param_n):
            print("\n[Line %4d] %s\nERROR: No such polynomial \"poly_src = %d\", allowed polynomials for n = %d are 0 to %d\n" % (lines[pc], instr, poly_src, param_n, int(8192/param_n)))
            exit()
        # Copy polynomial coefficients (handle both fast and slow cases in cycle count)
        poly_mem[poly_dst] = poly_mem[poly_src].copy()
        if ((poly_src < int(4096/param_n) and poly_dst >= int(4096/param_n)) or (poly_dst < int(4096/param_n) and poly_src >= int(4096/param_n))):
            cycles = 2 + 1 + 1 + int(param_n/4)
        else:
            cycles = 2 + 1 + 1 + (3*param_n)
        proc_regs["tmp"] = random.getrandbits(24) # "tmp" register gets clobbered
        pc = pc + 1
        ticks = ticks + cycles
        power = power + ([idd_dict["poly_copy"]]*cycles)
        return 5

    supported_poly_ops = ["ADD", "SUB", "MUL", "BITREV", "CONST_ADD", "CONST_SUB", "CONST_MUL", "CONST_AND", "CONST_OR", "CONST_XOR", "CONST_RSHIFT", "CONST_LSHIFT"]

    # INSTRUCTION - Polynomial ALU Operations
    matchObj = re.match(r'poly_op\(op=([\w_]+),poly_dst=(\d+),poly_src=(\d+)\)', instr_t, re.M|re.I)
    if matchObj:
        op = matchObj.group(1)
        poly_dst = int(matchObj.group(2))
        poly_src = int(matchObj.group(3))
        if poly_dst >= int(8192/param_n):
            print("\n[Line %4d] %s\nERROR: No such polynomial \"poly_dst = %d\", allowed polynomials for n = %d are 0 to %d\n" % (lines[pc], instr, poly_dst, param_n, int(8192/param_n)))
            exit()
        if poly_src >= int(8192/param_n):
            print("\n[Line %4d] %s\nERROR: No such polynomial \"poly_src = %d\", allowed polynomials for n = %d are 0 to %d\n" % (lines[pc], instr, poly_src, param_n, int(8192/param_n)))
            exit()
        if not ((poly_src < int(4096/param_n) and poly_dst >= int(4096/param_n)) or (poly_dst < int(4096/param_n) and poly_src >= int(4096/param_n))):
            print("\n[Line %4d] %s\nERROR: Polynomial pair \"poly_dst = %d, poly_src = %d\" is not allowed for n = %d, ensure \"poly_dst < %d, poly_src >= %d\" or \"poly_src < %d, poly_dst >= %d\"\n" % (lines[pc], instr, poly_dst, poly_src, param_n, int(4096/param_n), int(4096/param_n), int(4096/param_n), int(4096/param_n)))
            exit()
        #print("op: %s" % op)
        if op == "ADD":
            # Update polynomial coefficients
            for i in range(param_n):
                poly_mem[poly_dst][i] = (int(poly_mem[poly_src][i]) + int(poly_mem[poly_dst][i])) % param_q
            proc_regs["tmp"] = random.getrandbits(24) # "tmp" register gets clobbered
            cycles = 2 + 1 + 1 + param_n
            power = power + ([idd_dict["poly_poly_addsub"][param_q]]*cycles)
        elif op == "SUB":
            # Update polynomial coefficients
            for i in range(param_n):
                poly_mem[poly_dst][i] = (int(poly_mem[poly_src][i]) - int(poly_mem[poly_dst][i]) + param_q) % param_q
            proc_regs["tmp"] = random.getrandbits(24) # "tmp" register gets clobbered
            cycles = 2 + 1 + 1 + param_n
            power = power + ([idd_dict["poly_poly_addsub"][param_q]]*cycles)
        elif op == "MUL":
            # Update polynomial coefficients
            for i in range(param_n):
                poly_mem[poly_dst][i] = (int(poly_mem[poly_src][i]) * int(poly_mem[poly_dst][i])) % param_q
            proc_regs["tmp"] = random.getrandbits(24) # "tmp" register gets clobbered
            cycles = 2 + 1 + 1 + param_n
            power = power + ([idd_dict["poly_poly_mul"][param_q]]*cycles)
        elif op == "BITREV":
            # Update polynomial coefficients
            for i in range(param_n):
                i_rev = int(('{:0{w}b}'.format(i, w=int(math.log(param_n,2))))[::-1], 2)
                poly_mem[poly_dst][i_rev] = poly_mem[poly_src][i]
            cycles = 2 + 1 + (1+int(param_n/4))
            power = power + ([idd_dict["poly_bitrev"]]*cycles)
        elif op == "CONST_ADD":
            # Update polynomial coefficients
            for i in range(param_n):
                poly_mem[poly_dst][i] = (int(poly_mem[poly_src][i]) + proc_regs["reg"]) % param_q
            cycles = 2 + 1 + 1 + param_n
            power = power + ([idd_dict["poly_const_addsub"][param_q]]*cycles)
        elif op == "CONST_SUB":
            # Update polynomial coefficients
            for i in range(param_n):
                poly_mem[poly_dst][i] = (int(poly_mem[poly_src][i]) - proc_regs["reg"] + param_q) % param_q
            cycles = 2 + 1 + 1 + param_n
            power = power + ([idd_dict["poly_const_addsub"][param_q]]*cycles)
        elif op == "CONST_MUL":
            # Update polynomial coefficients
            for i in range(param_n):
                poly_mem[poly_dst][i] = (int(poly_mem[poly_src][i]) * proc_regs["reg"]) % param_q
            cycles = 2 + 1 + 1 + param_n
            power = power + ([idd_dict["poly_const_mul"][param_q]]*cycles)
        elif op == "CONST_AND":
            # Update polynomial coefficients
            for i in range(param_n):
                poly_mem[poly_dst][i] = (poly_mem[poly_src][i] & proc_regs["reg"])
            cycles = 2 + 1 + 1 + param_n
            power = power + ([idd_dict["poly_const_and"]]*cycles)
        elif op == "CONST_OR":
            # Update polynomial coefficients
            for i in range(param_n):
                poly_mem[poly_dst][i] = (poly_mem[poly_src][i] | proc_regs["reg"])
            cycles = 2 + 1 + 1 + param_n
            power = power + ([idd_dict["poly_const_or"]]*cycles)
        elif op == "CONST_XOR":
            # Update polynomial coefficients
            for i in range(param_n):
                poly_mem[poly_dst][i] = (poly_mem[poly_src][i] ^ proc_regs["reg"])
            cycles = 2 + 1 + 1 + param_n
            power = power + ([idd_dict["poly_const_xor"]]*cycles)
        elif op == "CONST_RSHIFT":
            # Update polynomial coefficients
            for i in range(param_n):
                if proc_regs["reg"] < 24:
                    poly_mem[poly_dst][i] = (poly_mem[poly_src][i] >> proc_regs["reg"]) % 2**24
                else:
                    poly_mem[poly_dst][i] = 0
            cycles = 2 + 1 + 1 + param_n
            power = power + ([idd_dict["poly_const_shift"]]*cycles)
        elif op == "CONST_LSHIFT":
            # Update polynomial coefficients
            for i in range(param_n):
                if proc_regs["reg"] < 24:
                    poly_mem[poly_dst][i] = (poly_mem[poly_src][i] << proc_regs["reg"]) % 2**24
                else:
                    poly_mem[poly_dst][i] = 0
            cycles = 2 + 1 + 1 + param_n
            power = power + ([idd_dict["poly_const_shift"]]*cycles)
        else:
            print("\n[Line %4d] %s\nERROR: Unsupported operation \"%s\", allowed operations are %s\n" % (lines[pc], instr, op, supported_poly_ops))
            exit()
        pc = pc + 1
        ticks = ticks + cycles
        return 5

    # INSTRUCTION - Polynomial Circular Left Shift (Multiplication by x modulo x^N+1 and x^N-1)
    matchObj = re.match(r'shift_poly\(ring=x\^N([\+\-])1,poly_dst=(\d+),poly_src=(\d+)\)', instr_t, re.M|re.I)
    if matchObj:
        ring = matchObj.group(1)
        poly_dst = int(matchObj.group(2))
        poly_src = int(matchObj.group(3))
        if poly_dst >= int(8192/param_n):
            print("\n[Line %4d] %s\nERROR: No such polynomial \"poly_dst = %d\", allowed polynomials for n = %d are 0 to %d\n" % (lines[pc], instr, poly_dst, param_n, int(8192/param_n)))
            exit()
        if poly_src >= int(8192/param_n):
            print("\n[Line %4d] %s\nERROR: No such polynomial \"poly_src = %d\", allowed polynomials for n = %d are 0 to %d\n" % (lines[pc], instr, poly_src, param_n, int(8192/param_n)))
            exit()
        if not ((poly_src < int(4096/param_n) and poly_dst >= int(4096/param_n)) or (poly_dst < int(4096/param_n) and poly_src >= int(4096/param_n))):
            print("\n[Line %4d] %s\nERROR: Polynomial pair \"poly_dst = %d, poly_src = %d\" is not allowed for n = %d, ensure \"poly_dst < %d, poly_src >= %d\" or \"poly_src < %d, poly_dst >= %d\"\n" % (lines[pc], instr, poly_dst, poly_src, param_n, int(4096/param_n), int(4096/param_n), int(4096/param_n), int(4096/param_n)))
            exit()
        # Update polynomial coefficients
        for i in range(1, param_n):
            poly_mem[poly_dst][i] = poly_mem[poly_src][i-1]
        if ring == "+":
            poly_mem[poly_dst][0] = param_q - poly_mem[poly_scr][param_n-1]
        if ring == "-":
            poly_mem[poly_dst][0] = poly_mem[poly_scr][param_n-1]
        cycles = 2 + 1 + 1 + int(param_n/4)
        pc = pc + 1
        ticks = ticks + cycles
        power = power + ([idd_dict["poly_shift"]]*cycles)
        return 5

    # INSTRUCTION - Polynomial Equality Check
    matchObj = re.match(r'flag=eq_check\(poly0=(\d+),poly1=(\d+)\)', instr_t, re.M|re.I)
    if matchObj:
        poly0 = int(matchObj.group(1))
        poly1 = int(matchObj.group(2))
        if poly0 >= int(8192/param_n):
            print("\n[Line %4d] %s\nERROR: No such polynomial \"poly0 = %d\", allowed polynomials for n = %d are 0 to %d\n" % (lines[pc], instr, poly0, param_n, int(8192/param_n)))
            exit()
        if poly1 >= int(8192/param_n):
            print("\n[Line %4d] %s\nERROR: No such polynomial \"poly1 = %d\", allowed polynomials for n = %d are 0 to %d\n" % (lines[pc], instr, poly1, param_n, int(8192/param_n)))
            exit()
        if not ((poly1 < int(4096/param_n) and poly0 >= int(4096/param_n)) or (poly0 < int(4096/param_n) and poly1 >= int(4096/param_n))):
            print("\n[Line %4d] %s\nERROR: Polynomial pair \"poly0 = %d, poly1 = %d\" is not allowed for n = %d, ensure \"poly0 < %d, poly1 >= %d\" or \"poly1 < %d, poly0 >= %d\"\n" % (lines[pc], instr, poly0, poly1, param_n, int(4096/param_n), int(4096/param_n), int(4096/param_n), int(4096/param_n)))
            exit()
        # Compare polynomial coefficients and update flag
        if poly_mem[poly0] == poly_mem[poly1]:
            proc_regs["flag"] = 1
        else:
            proc_regs["flag"] = 0
        proc_regs["tmp"] = random.getrandbits(24) # "tmp" register gets clobbered
        cycles = 2 + 1 + 2 + param_n
        pc = pc + 1
        ticks = ticks + cycles
        power = power + ([idd_dict["poly_eq_check"]]*cycles)
        return 6

    # INSTRUCTION - Polynomial Infinity Norm Check
    matchObj = re.match(r'flag=inf_norm_check\(poly=(\d+),bound=(\d+)\)', instr_t, re.M|re.I)
    if matchObj:
        poly = int(matchObj.group(1))
        bound = int(matchObj.group(2))
        if poly >= int(8192/param_n):
            print("\n[Line %4d] %s\nERROR: No such polynomial \"poly = %d\", allowed polynomials for n = %d are 0 to %d\n" % (lines[pc], instr, poly, param_n, int(8192/param_n)))
            exit()
        if bound >= 2**24:
            print("\n[Line %4d] %s\nERROR: Parameter \"bound = %d\" too large, must be less than 2**24\n" % (lines[pc], instr, bound))
            exit()
        # Update register value
        proc_regs["reg"] = bound
        cycles = 2
        # Compare infinity norm of polynomial with specified bound and update flag
        count = 0
        for i in range(param_n):
            if poly_mem[poly][i] > bound and poly_mem[poly][i] < (param_q - bound):
                count = count + 1
        if count == 0:
            proc_regs["flag"] = 1
        else:
            proc_regs["flag"] = 0
        cycles = cycles + 2 + 1 + 1 + param_n
        pc = pc + 1
        ticks = ticks + cycles
        power = power + ([idd_dict["poly_inf_norm_check"]]*cycles)
        return 6

    # INSTRUCTION - Register Comparison
    matchObj = re.match(r'flag=compare\(c(\d),(\d+)\)', instr_t, re.M|re.I)
    if matchObj:
        reg = int(matchObj.group(1))
        val = int(matchObj.group(2))
        if reg > 1:
            print("\n[Line %4d] %s\nERROR: No such register \"c%d\", please use \"c0\" or \"c1\"\n" % (lines[pc], instr, reg))
            exit()
        if val >= 2**16:
            print("\n[Line %4d] %s\nERROR: Value %s too big for 16-bit register \"c%d\"\n" % (lines[pc], instr, val, reg))
            exit()
        # Compare register value and update flag
        if proc_regs["c%s" % reg] < val:
            proc_regs["flag"] = -1
        elif proc_regs["c%s" % reg] > val:
            proc_regs["flag"] = 1
        else:
            proc_regs["flag"] = 0
        pc = pc + 1
        ticks = ticks + 2
        power = power + ([idd_dict["ctrl"]]*2)
        return 6
    matchObj = re.match(r'flag=compare\(reg,(\d+)\)', instr_t, re.M|re.I)
    if matchObj:
        val = int(matchObj.group(1))
        if val >= 2**24:
            print("\n[Line %4d] %s\nERROR: Value %s too big for 24-bit register \"reg\"\n" % (lines[pc], instr, val))
            exit()
        # Compare register value and update flag
        if proc_regs["reg"] < val:
            proc_regs["flag"] == -1
        elif proc_regs["reg"] > val:
            proc_regs["flag"] == 1
        else:
            proc_regs["flag"] = 0
        pc = pc + 1
        ticks = ticks + 2
        power = power + ([idd_dict["ctrl"]]*2)
        return 6
    matchObj = re.match(r'flag=compare\(tmp,(\d+)\)', instr_t, re.M|re.I)
    if matchObj:
        val = int(matchObj.group(1))
        if val >= 2**24:
            print("\n[Line %4d] %s\nERROR: Value %s too big for 24-bit register \"tmp\"\n" % (lines[pc], instr, val))
            exit()
        # Compare register value and update flag
        if proc_regs["tmp"] < val:
            proc_regs["flag"] == -1
        elif proc_regs["tmp"] > val:
            proc_regs["flag"] == 1
        else:
            proc_regs["flag"] = 0
        pc = pc + 1
        ticks = ticks + 2
        power = power + ([idd_dict["ctrl"]]*2)
        return 6
    
    # INSTRUCTION - Check Flag and Jump
    matchObj = re.match(r'if\(flag([!=]=)([\-\+]{0,1})([01])\)goto([\w\d_]+)', instr_t, re.M|re.I)
    if matchObj:
        op = matchObj.group(1)
        sign = matchObj.group(2)
        val = int(matchObj.group(3))
        label = matchObj.group(4)
        if label not in labels:
            print("\n[Line %4d] %s\nERROR: Label \"%s\" not found\n" % (lines[pc], instr, label))
            exit()
        # Check flag value and jump
        if op == "==":
            if val == 0:
                if proc_regs["flag"] == 0:
                    pc = labels[label]
                else:
                    pc = pc + 1
            if val == 1:
                if sign == "+" or sign == "":
                    if proc_regs["flag"] == 1:
                        pc = labels[label]
                    else:
                        pc = pc + 1
                if sign == "-":
                    if proc_regs["flag"] == -1:
                        pc = labels[label]
                    else:
                        pc = pc + 1
        if op == "!=":
            if val == 0:
                if proc_regs["flag"] != 0:
                    pc = labels[label]
                else:
                    pc = pc + 1
            if val == 1:
                if sign == "+" or sign == "":
                    if proc_regs["flag"] != 1:
                        pc = labels[label]
                    else:
                        pc = pc + 1
                if sign == "-":
                    if proc_regs["flag"] != -1:
                        pc = labels[label]
                    else:
                        pc = pc + 1
        ticks = ticks + 2
        power = power + ([idd_dict["ctrl"]]*2)
        return 6

    # INSTRUCTION - SHA3 Operations
    matchObj = re.match(r'sha3_init', instr_t, re.M|re.I)
    if matchObj:
        keccak_buf = ""
        cycles = 2 + 1 + 25
        pc = pc + 1
        ticks = ticks + cycles
        power = power + ([idd_dict["sha3"]]*cycles)
        return 7
    matchObj = re.match(r'sha3_(\d+)_absorb\(poly=(\d+)\)', instr_t, re.M|re.I)
    if matchObj:
        mode = int(matchObj.group(1))
        poly = int(matchObj.group(2))
        if mode != 256 and mode != 512:
            print("\n[Line %4d] %s\nERROR: Only SHA3-256 and SHA3-512 are supported\n" % (lines[pc], instr))
            exit()
        if poly >= int(8192/param_n):
            print("\n[Line %4d] %s\nERROR: No such polynomial \"poly = %d\", allowed polynomials for n = %d are 0 to %d\n" % (lines[pc], instr, poly, param_n, int(8192/param_n)))
            exit()
        # Push zero-padded polynomial coefficients into Keccak buffer
        for i in range(param_n):
            keccak_buf = keccak_buf + hex(poly_mem[poly][i])[2:].rstrip("L").rjust(8,'0')
        if mode == 256:
            cycles = 2 + 1 + 1 + param_n + math.ceil(param_n/34)*(17+25)
        if mode == 512:
            cycles = 2 + 1 + 1 + param_n + math.ceil(param_n/18)*(9+25)
        pc = pc + 1
        ticks = ticks + cycles
        power = power + ([idd_dict["poly_hash"]]*cycles)
        return 7
    matchObj = re.match(r'sha3_(\d+)_absorb\(r(\d)\)', instr_t, re.M|re.I)
    if matchObj:
        mode = int(matchObj.group(1))
        reg = int(matchObj.group(2))
        if mode != 256 and mode != 512:
            print("\n[Line %4d] %s\nERROR: Only SHA3-256 and SHA3-512 are supported\n" % (lines[pc], instr))
            exit()
        if reg != 0 and reg != 1:
            print("\n[Line %4d] %s\nERROR: No such register \"r%d\", allowed registers are r0 and r1\n" % (lines[pc], instr, reg))
            exit()
        # Push seed register contents into Keccak buffer
        keccak_buf = keccak_buf + hex(proc_regs["r%d" % reg])[2:].rstrip("L").rjust(64,'0')
        if mode == 256:
            cycles = 2 + 1 + (17+25)
        if mode == 512:
            cycles = 2 + 1 + (9+25)
        pc = pc + 1
        ticks = ticks + cycles
        power = power + ([idd_dict["sha3"]]*cycles)
        return 7
    matchObj = re.match(r'r(\d)=sha3_256_digest', instr_t, re.M|re.I)
    if matchObj:
        reg = int(matchObj.group(1))
        if reg != 0 and reg != 1:
            print("\n[Line %4d] %s\nERROR: No such register \"r%d\", allowed registers are r0 and r1\n" % (lines[pc], instr, reg))
            exit()
        # Generate SHA3-256 digest
        digest = sha3_256(keccak_buf)
        proc_regs["r%d" % reg] = int(digest, 16)
        keccak_buf = ""
        cycles = 2 + 1 + (25+25+2)
        pc = pc + 1
        ticks = ticks + cycles
        power = power + ([idd_dict["sha3"]]*cycles)
        return 7
    matchObj = re.match(r'r0\|\|r1=sha3_512_digest', instr_t, re.M|re.I)
    if matchObj:
        # Generate SHA3-512 digest
        digest = sha3_512(keccak_buf)
        proc_regs["r0"] = int(digest, 16) >> 256
        proc_regs["r1"] = int(digest, 16) % 2**256
        keccak_buf = ""
        cycles = 2 + 1 + (25+25+3)
        pc = pc + 1
        ticks = ticks + cycles
        power = power + ([idd_dict["sha3"]]*cycles)
        return 7

    # INSTRUCTION - End of Program
    matchObj = re.match(r'end', instr_t, re.M|re.I)
    if matchObj:
        #print("end-of-program")
        ticks = ticks + 2
        power = power + ([idd_dict["ctrl"]]*2)
        return 99

    # INSTRUCTION - NOP
    matchObj = re.match(r'nop', instr_t, re.M|re.I)
    if matchObj:
        #print("no-operation")
        ticks = ticks + 2
        power = power + ([idd_dict["ctrl"]]*2)
        return -98

    # DEBUG-INSTRUCTION - Compare Encoded Polynomials (Debug Only)
    # Append "iter_<iter_count>_" to all filenames in case of multiple iterations
    if num_iters > 1:
        f_prefix = "iter_%d_" % iter_count
    else:
        f_prefix = ""
    matchObj = re.match(r'encode_compare\("(.*)","(.*)",encoding=([\w_]+)\)', instr_t, re.M|re.I)
    if matchObj:
        f1 = matchObj.group(1)
        f2 = matchObj.group(2)
        if not f1.endswith(".npy"):
            print("\n[Line %4d] %s\nWARNING: Adding .npy extension to filename \"%s\"\n" % (lines[pc], instr, f1))
            f1 = f1 + ".npy"
        if not f2.endswith(".npy"):
            print("\n[Line %4d] %s\nWARNING: Adding .npy extension to filename \"%s\"\n" % (lines[pc], instr, f2))
            f2 = f2 + ".npy"
        f1 = f1.replace(os.path.basename(f1), f_prefix + os.path.basename(f1))
        f2 = f2.replace(os.path.basename(f2), f_prefix + os.path.basename(f2))
        encoding = matchObj.group(3)
        if not os.path.exists(f1):
            print("\n[Line %4d] %s\nERROR: Input file %s for \"encode_compare\" does not exist" % (lines[pc], instr, f1))
            exit()
        if not os.path.exists(f2):
            print("\n[Line %4d] %s\nERROR: Input file %s for \"encode_compare\" does not exist" % (lines[pc], instr, f2))
            exit()
        b1 = encode_to_bytearray(param_n, param_q, list(np.load(f1, allow_pickle = True)), encoding, lines[pc], instr)
        b2 = encode_to_bytearray(param_n, param_q, list(np.load(f2, allow_pickle = True)), encoding, lines[pc], instr)
        print("poly_1 = %s" % list(np.load(f1, allow_pickle = True)))
        print("poly_2 = %s" % list(np.load(f2, allow_pickle = True)))
        print("byte_array_1 = %s" % b1)
        print("byte_array_2 = %s" % b2)
        if b1 == b2:
            print("\n--- MATCH ---\n")
        else:
            print("\n--- NO MATCH ---\n")
        pc = pc + 1
        return -98

    # DEBUG-INSTRUCTION - Print Encoded Polynomial (Debug Only)
    matchObj = re.match(r'encode_print\(poly=(\d+),encoding=([\w_]+)\)', instr_t, re.M|re.I)
    if matchObj:
        poly = int(matchObj.group(1))
        encoding = matchObj.group(2)
        if poly >= int(8192/param_n):
            print("\n[Line %4d] %s\nERROR: No such polynomial \"poly = %d\", allowed polynomials for n = %d are 0 to %d\n" % (lines[pc], instr, poly, param_n, int(8192/param_n)))
            exit()
        if "--verbose" in sys.argv:
            b = encode_to_bytearray(param_n, param_q, poly_mem[poly], encoding, lines[pc], instr)
            print("byte_array = %s" % b)
        pc = pc + 1
        return -98

    # DEBUG-INSTRUCTION - Register / Polynomial Random-Init / Load / Store
    # These instructions are not really available in the crypto core, but act as
    # substitutes (in the simulator) for the actual 32-bit load / store interface
    # Append "iter_<iter_count>_" to all filenames in case of multiple iterations
    if num_iters > 1:
        f_prefix = "iter_%d_" % iter_count
    else:
        f_prefix = ""
    matchObj = re.match(r'random\(r(\d)\)', instr_t, re.M|re.I)
    if matchObj:
        reg = int(matchObj.group(1))
        if reg > 1:
            print("\n[Line %4d] %s\nERROR: No such register \"r%d\", please use \"r0\" or \"r1\"\n" % (lines[pc], instr, reg))
            exit()
        proc_regs["r%d" % reg] = random.getrandbits(256)
        cycles = WRITE_CYCLES*8
        pc = pc + 1
        if "--free_rw" not in sys.argv:
            ticks = ticks + cycles
            power = power + ([idd_dict["ctrl"]]*cycles)
        return -98
    matchObj = re.match(r'random\(poly=(\d+),encoding=([\w\d_]+),"(.*)"\)', instr_t, re.M|re.I)
    if matchObj:
        poly = int(matchObj.group(1))
        encoding = matchObj.group(2)
        f = matchObj.group(3)
        if not f.endswith(".npy"):
            print("\n[Line %4d] %s\nWARNING: Adding .npy extension to filename \"%s\"\n" % (lines[pc], instr, f))
            f = f + ".npy"
        f = f.replace(os.path.basename(f), f_prefix + os.path.basename(f))
        if poly >= int(8192/param_n):
            print("\n[Line %4d] %s\nERROR: No such polynomial \"poly = %d\", allowed polynomials for n = %d are 0 to %d\n" % (lines[pc], instr, poly, param_n, int(8192/param_n)))
            exit()
        if os.path.exists(f):
            print("\n[Line %4d] %s\nWARNING: Output file %s for \"random\" already exists" % (lines[pc], instr, f))
        random_poly_encode(param_n, param_q, poly_mem[poly], encoding, lines[pc], instr)
        np.save(f, np.asarray(poly_mem[poly]))
        cycles = WRITE_CYCLES*param_n
        pc = pc + 1
        if "--free_rw" not in sys.argv:
            ticks = ticks + cycles
            power = power + ([idd_dict["poly_read_write"]]*cycles)
        return -98
    matchObj = re.match(r'load\(r(\d),"(.*)"\)', instr_t, re.M|re.I)
    if matchObj:
        reg = int(matchObj.group(1))
        f = matchObj.group(2)
        if not f.endswith(".npy"):
            print("\n[Line %4d] %s\nWARNING: Adding .npy extension to filename \"%s\"\n" % (lines[pc], instr, f))
            f = f + ".npy"
        f = f.replace(os.path.basename(f), f_prefix + os.path.basename(f))
        if reg > 1:
            print("\n[Line %4d] %s\nERROR: No such register \"r%d\", please use \"r0\" or \"r1\"\n" % (lines[pc], instr, reg))
            exit()
        if not os.path.exists(f):
            print("\n[Line %4d] %s\nERROR: Input file %s for \"load\" does not exist" % (lines[pc], instr, f))
            exit()
        proc_regs["r%d" % reg] = list(np.load(f, allow_pickle = True))[0]
        cycles = WRITE_CYCLES*8
        pc = pc + 1
        if "--free_rw" not in sys.argv:
            ticks = ticks + cycles
            power = power + ([idd_dict["ctrl"]]*cycles)
        return -98
    matchObj = re.match(r'save\(r(\d),"(.*)"\)', instr_t, re.M|re.I)
    if matchObj:
        reg = int(matchObj.group(1))
        f = matchObj.group(2)
        if not f.endswith(".npy"):
            print("\n[Line %4d] %s\nWARNING: Adding .npy extension to filename \"%s\"\n" % (lines[pc], instr, f))
            f = f + ".npy"
        f = f.replace(os.path.basename(f), f_prefix + os.path.basename(f))
        if reg > 1:
            print("\n[Line %4d] %s\nERROR: No such register \"r%d\", please use \"r0\" or \"r1\"\n" % (lines[pc], instr, reg))
            exit()
        if os.path.exists(f):
            print("\n[Line %4d] %s\nWARNING: Output file %s for \"save\" already exists" % (lines[pc], instr, f))
        np.save(f, np.asarray([proc_regs["r%d" % reg]]))
        cycles = READ_CYCLES*8
        pc = pc + 1
        if "--free_rw" not in sys.argv:
            ticks = ticks + cycles
            power = power + ([idd_dict["ctrl"]]*cycles)
        return -98
    matchObj = re.match(r'load\(poly=(\d+),"(.*)"\)', instr_t, re.M|re.I)
    if matchObj:
        poly = int(matchObj.group(1))
        f = matchObj.group(2)
        if not f.endswith(".npy"):
            print("\n[Line %4d] %s\nWARNING: Adding .npy extension to filename \"%s\"\n" % (lines[pc], instr, f))
            f = f + ".npy"
        f = f.replace(os.path.basename(f), f_prefix + os.path.basename(f))
        if poly >= int(8192/param_n):
            print("\n[Line %4d] %s\nERROR: No such polynomial \"poly = %d\", allowed polynomials for n = %d are 0 to %d\n" % (lines[pc], instr, poly, param_n, int(8192/param_n)))
            exit()
        if not os.path.exists(f):
            print("\n[Line %4d] %s\nERROR: Input file %s for \"load\" does not exist" % (lines[pc], instr, f))
            exit()
        poly_mem[poly] = list(np.load(f, allow_pickle = True)).copy()
        cycles = WRITE_CYCLES*param_n
        pc = pc + 1
        if "--free_rw" not in sys.argv:
            ticks = ticks + cycles
            power = power + ([idd_dict["poly_read_write"]]*cycles)
        return -98
    matchObj = re.match(r'save\(poly=(\d+),"(.*)"\)', instr_t, re.M|re.I)
    if matchObj:
        poly = int(matchObj.group(1))
        f = matchObj.group(2)
        if not f.endswith(".npy"):
            print("\n[Line %4d] %s\nWARNING: Adding .npy extension to filename \"%s\"\n" % (lines[pc], instr, f))
            f = f + ".npy"
        f = f.replace(os.path.basename(f), f_prefix + os.path.basename(f))
        if poly >= int(8192/param_n):
            print("\n[Line %4d] %s\nERROR: No such polynomial \"poly = %d\", allowed polynomials for n = %d are 0 to %d\n" % (lines[pc], instr, poly, param_n, int(8192/param_n)))
            exit()
        if os.path.exists(f):
            print("\n[Line %4d] %s\nWARNING: Output file %s for \"save\" already exists" % (lines[pc], instr, f))
        np.save(f, np.asarray(poly_mem[poly]))
        cycles = READ_CYCLES*param_n
        pc = pc + 1
        if "--free_rw" not in sys.argv:
            ticks = ticks + cycles
            power = power + ([idd_dict["poly_read_write"]]*cycles)
        return -98

    # DEBUG-INSTRUCTION - Print (Debug Only)
    matchObj = re.match(r'print\(r(\d)\)', instr_t, re.M|re.I)
    if matchObj:
        reg = int(matchObj.group(1))
        if reg > 1:
            print("\n[Line %4d] %s\nERROR: No such register \"r%d\", please use \"r0\" or \"r1\"\n" % (lines[pc], instr, reg))
            exit()
        if "--verbose" in sys.argv:
            print("\nr%d = 0x%s\n" % (reg, hex(proc_regs["r%d" % reg])[2:].upper().rstrip("L").rjust(64,'0')))
        pc = pc + 1
        return -99
    matchObj = re.match(r'print\(reg\)', instr_t, re.M|re.I)
    if matchObj:
        if "--verbose" in sys.argv:
            print("\nreg = %d\n" % proc_regs["reg"])
        pc = pc + 1
        return -99
    matchObj = re.match(r'print\(tmp\)', instr_t, re.M|re.I)
    if matchObj:
        if "--verbose" in sys.argv:
            print("\ntmp = %d\n" % proc_regs["tmp"])
        pc = pc + 1
        return -99
    matchObj = re.match(r'print\(flag\)', instr_t, re.M|re.I)
    if matchObj:
        if "--verbose" in sys.argv:
            print("\nflag = %d\n" % proc_regs["flag"])
        pc = pc + 1
        return -99
    matchObj = re.match(r'print\(c(\d)\)', instr_t, re.M|re.I)
    if matchObj:
        reg = int(matchObj.group(1))
        if reg > 1:
            print("\n[Line %4d] %s\nERROR: No such register \"c%d\", please use \"c0\" or \"c1\"\n" % (lines[pc], instr, reg))
            exit()
        if "--verbose" in sys.argv:
            print("\nc%d = %d\n" % (reg, proc_regs["c%d" % reg]))
        pc = pc + 1
        return -99
    matchObj = re.match(r'print\(poly=(\d+)\)', instr_t, re.M|re.I)
    if matchObj:
        poly = int(matchObj.group(1))
        if poly >= int(8192/param_n):
            print("\n[Line %4d] %s\nERROR: No such polynomial \"poly = %d\", allowed polynomials for n = %d are 0 to %d\n" % (lines[pc], instr, poly, param_n, int(8192/param_n)))
            exit()
        if "--verbose" in sys.argv:
            print("\npoly[%d] = %s\n" % (poly, poly_mem[poly]))
        pc = pc + 1
        return -99

    # INVALID INSTRUCTION
    return -1

#====================================
# SAPPHIRE-SIM
#====================================

# Check arguments
if len(sys.argv) < 7 or ("--prog" not in sys.argv) or ("--vdd" not in sys.argv) or ("--fmhz" not in sys.argv):
    print("\nERROR: Incorrect arguments provided for simulator script")
    print("Usage: python sim.py --prog <program_file_path>")
    print("                     --vdd <voltage>")
    print("                     --fmhz <frequency_mhz>")
    print("                     [ --verbose ]")
    print("                     [ --free_rw ]")
    print("                     [ --plot_power ]")
    print("                     [ --cdt <cdt_file_path> ]")
    print("                     [ --iter <num_iterations> ]")
    exit()

# Check that program file exists
if not os.path.exists(sys.argv[sys.argv.index("--prog") + 1]):
    print("\nERROR: Program file %s does not exist" % sys.argv[2])
    exit()

# Check supply voltage
vdd = float(sys.argv[sys.argv.index("--vdd") + 1])
if vdd < 0.68 or vdd > 1.21:
    print("\nERROR: Supply voltage outside acceptable range of 0.68-1.21 V\n")
    exit()

# Check operating frequency
# fmax = 12 MHz at 0.68 V and 72 MHz at 1.1 V
# Model fmax as a linear function of vdd (not exactly accurate but good enough for our simulator)
fmhz = int(sys.argv[sys.argv.index("--fmhz") + 1])
fmax = int(12 + (72-12)*(vdd - 0.68)/(1.1-0.68))
if fmhz > fmax:
    print("\nERROR: Operating frequency above maximum %d MHz at %0.2f V\n" % (fmax, vdd))
    exit()

defines = ["main"]
ifdefs = []
active_ifdef = "main"
labels = {}

# Read program file
imem_f = open(sys.argv[sys.argv.index("--prog") + 1])
imem = []

# Process ifdefs
for (i, instr) in enumerate(imem_f):
    # Identify `define flags
    matchObj = re.match(r'`define\s*(.+)', instr.strip(), re.M|re.I)
    if matchObj:
        defines.append(matchObj.group(1))
        imem.append("")
        continue
    # Identify `ifdef flags
    matchObj = re.match(r'`ifdef\s*(.+)', instr.strip(), re.M|re.I)
    if matchObj:
        ifdefs.append(active_ifdef)
        active_ifdef = matchObj.group(1)
        imem.append("")
        continue
    # Identify `endif flags
    matchObj = re.match(r'`endif', instr.strip(), re.M|re.I)
    if matchObj:
        active_ifdef = ifdefs[-1]
        ifdefs = ifdefs[:-1]
        imem.append("")
        continue
    # Ignore instructions inside undeclared `ifdef blocks
    if active_ifdef not in defines:
        imem.append("")
        continue
    imem.append(instr)

imem_f.close()

# Remove comments
imem = [re.sub(r'#.*$', "", instr) for instr in imem]

# Remove empty lines and leading / trailing spaces
lines = [i+1 for i in range(len(imem)) if imem[i].strip()]
imem = [instr.strip() for instr in imem if instr.strip()]

# Parse labels (labels must be followed by an instruction in the same line)
for (i, instr) in enumerate(imem):
    matchObj = re.match(r'([\w\d_]+)\s*:\s*(.+)', instr.strip(), re.M|re.I)
    if matchObj:
        label = matchObj.group(1)
        labels[label] = i
        imem[i] = matchObj.group(2)

# Check if first instruction is "config"
if not re.match(r'config.*', imem[0], re.M|re.I):
    print("\nERROR: First instruction of program must be \"config\"\n")
    exit()

# Check if last instruction is "end"
if not re.match(r'end', imem[len(imem)-1], re.M|re.I):
    print("\nWARNING: Last instruction of program must be \"end\", appending \"end\" at the end of program\n")
    imem.append("end")

keccak_buf = ""
proc_regs = {
"r0"    : 0,
"r1"    : 0,
"reg"   : 0,
"tmp"   : 0,
"c0"    : 0,
"c1"    : 0,
"flag"  : 0,
}
poly_mem = []
poly_tmp = []
param_n = 0
param_q = 0
ticks = 0
pc = 0

power = []

# Read CDT file, if provided
if "--cdt" in sys.argv:
    if not os.path.exists(sys.argv[sys.argv.index("--cdt") + 1]):
        print("\nERROR: CDT file %s does not exist" % sys.argv[sys.argv.index("--cdt") + 1])
        exit()
    cdt_mem = open(sys.argv[sys.argv.index("--cdt") + 1])
    cdt_mem = [cdval.strip() for cdval in cdt_mem if cdval.strip()]
    cdt_mem = [int(cdval) for cdval in cdt_mem]
    if len(cdt_mem) > 64:
        print("\nERROR: CDT is longer than 64 entries")
        exit()

num_iters = 1

# Read number of iterations, if provided
if "--iter" in sys.argv:
    num_iters = int(sys.argv[sys.argv.index("--iter") + 1])

ticks_arr = []
power_arr = []
energy_arr = []

for i in range(num_iters):
    keccak_buf = ""
    proc_regs["r0"] = 0
    proc_regs["r1"] = 0
    proc_regs["reg"] = 0
    proc_regs["tmp"] = 0
    proc_regs["c0"] = 0
    proc_regs["c1"] = 0
    proc_regs["flag"] = 0
    ticks = 0
    pc = 0
    power = []

    # The lattice-crypto core is not pipelined
    # Requires 1 cycle to fetch and >= 1 cycles to decode and execute instruction
    instr_count = 0
    while (1):
        if "--verbose" in sys.argv:
            if pc in labels.values():
                for (label, label_pc) in labels.items():
                    if label_pc == pc:
                        break
                print("[%3d] %s : %s" %(pc, label, imem[pc]))
            else:
                print("[%3d] %s" %(pc, imem[pc]))
        ret = instr_exec(imem[pc], i)

        # Invalid instruction
        if ret == -1:
            print("\n[Line %4d] %s\nERROR: Instruction not supported\n" % (lines[pc], imem[pc]))
            exit()

        if ret >= 0:
            instr_count = instr_count + 1

        # End of program
        if ret == 99:
            break

    # Convert current to power at specified operating condition
    # Take into account the fact that leakage power and dynamic power scale differently
    # Leakage current is assumed independent of processor state and operating frequency
    # i_leak = 102.6 uA at 0.70 V
    # i_leak = 121.0 uA at 0.75 V
    # i_leak = 139.5 uA at 0.80 V
    # i_leak = 159.7 uA at 0.85 V
    # i_leak = 188.8 uA at 0.90 V
    # i_leak = 220.0 uA at 0.95 V
    # i_leak = 257.4 uA at 1.00 V
    # i_leak = 303.8 uA at 1.05 V
    # i_leak = 355.7 uA at 1.10 V
    # Model leakage current as an exponential function of vdd (pretty accurate, curve-fitted from measurements)
    # Model active current as proportional to vdd and fmhz (again, not exactly accurate but good enough for our simulator)
    i_leak = 11.728*math.exp(3.0933*vdd)
    power = [(i_leak + ((idd - 355.7)*(fmhz/72)*(vdd/1.1))) for idd in power]

    # Add some tiny random noise (+/-1%) to current values
    power = [idd + random.randrange(-int(idd/100),int(idd/100)) for idd in power]

    # Finally, convert current to power
    power = [idd*vdd for idd in power]

    if num_iters > 1:
        print("\n[iter = %d]" % (i+1))
    else:
        print("\n")
    print("------------------------------------------------------")
    print("Program Execution Summary (at %0.2f V and %d MHz)" % (vdd, fmhz))
    print("------------------------------------------------------")

    print("* Instructions:  %d" % instr_count)

    print("* Total Cycles:  %s" % format(ticks, ',d'))
    ticks_arr.append(ticks)

    time_us = ticks/fmhz
    if time_us < 1e3:
        print("* Total Time:    %0.2f us" % (time_us))
    elif time_us < 1e6:
        print("* Total Time:    %0.2f ms" % (time_us/1e3))
    elif time_us < 1e9:
        print("* Total Time:    %0.2f s" % (time_us/1e6))

    avg_power_uw = sum(power)/ticks
    if avg_power_uw < 1e3:
        print("* Average Power: %0.2f uW" % (avg_power_uw))
    elif avg_power_uw < 1e6:
        print("* Average Power: %0.2f mW" % (avg_power_uw/1e3))
    power_arr.append(avg_power_uw)

    energy_pj = sum(power)/fmhz
    if energy_pj < 1e3:
        print("* Total Energy:  %0.2f pJ" % (energy_pj))
    elif energy_pj < 1e6:
        print("* Total Energy:  %0.2f nJ" % (energy_pj/1e3))
    elif energy_pj < 1e9:
        print("* Total Energy:  %0.2f uJ" % (energy_pj/1e6))
    energy_arr.append(energy_pj)

    print("------------------------------------------------------")
    print("\n")

# Print average cycles and energy, only in case of multiple iterations
if num_iters > 1:
    print("Over %d Iterations:" % (num_iters))
    avg_ticks = math.ceil(sum(ticks_arr)/len(ticks_arr))
    print("    Average Cycles: %s" % (format(avg_ticks, ',d')))
    avg_avg_power_uw = sum(power_arr)/len(power_arr)
    if avg_avg_power_uw < 1e3:
        print("    Average Power:  %0.2f uW" % (avg_avg_power_uw))
    elif avg_avg_power_uw < 1e6:
        print("    Average Power:  %0.2f mW" % (avg_avg_power_uw/1e3))
    avg_energy_pj = sum(energy_arr)/len(energy_arr)
    if avg_energy_pj < 1e3:
        print("    Average Energy: %0.2f pJ" % (avg_energy_pj))
    elif avg_energy_pj < 1e6:
        print("    Average Energy: %0.2f nJ" % (avg_energy_pj/1e3))
    elif avg_energy_pj < 1e9:
        print("    Average Energy: %0.2f uJ" % (avg_energy_pj/1e6))

# Plot power profile, only in case of single iteration
if "--plot_power" in sys.argv and num_iters == 1:
    power = [i_leak] + power
    mpl.rcParams['xtick.major.pad'] = 5
    mpl.rcParams['ytick.major.pad'] = 5
    plt.figure(figsize=(15,5))
    plt.plot(power, linewidth=1.5)
    plt.xticks(fontsize=14)
    plt.yticks(fontsize=14)
    plt.xlabel("Cycles", fontsize=16, fontweight='bold')
    plt.ylabel("Power (uW)", fontsize=16, fontweight='bold')
    plt.tight_layout()
    plt.show()
