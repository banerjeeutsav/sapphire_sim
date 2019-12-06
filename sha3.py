#! /usr/bin/python

###################################################################################################
#
# Python Simulator for Sapphire Lattice Crypto-Processor
#
# Author: Utsav Banerjee
# Last Modified: 19-Oct-2019
#
###################################################################################################

# SHA-3 functions based on Kecak

import keccak

def sha3_pad(m, r, pad):
    # "m" is byte-hex, but "pad" is binary
    mbits = 4*len(m)
    # add domain separation and 10*1 padding bits
    p = pad + "1"
    padbits = r - ((mbits + len(p)) % r)
    p = p + ("0"*(padbits-1)) + "1"
    pbits = len(p)
    # handle byte ordering
    pt = ""
    while (p != ""):
        byte = p[:8]
        p = p[8:]
        byte_rev = ""
        for b in byte:
            byte_rev = b + byte_rev
        pt = pt + byte_rev
    p = hex(int(pt, 2))[2:].rjust(int(pbits/4), '0')
    m = m + p
    #print("m_pad = %s" % m)
    return m

def sha3_224(msg):
    sha3_keccak = keccak.Keccak(1600)
    msg = sha3_pad(msg, 1152, "01")
    digest = sha3_keccak.Keccak((4*len(msg), msg), 1152, 448, 224, False)
    return digest

def sha3_256(msg):
    sha3_keccak = keccak.Keccak(1600)
    msg = sha3_pad(msg, 1088, "01")
    digest = sha3_keccak.Keccak((4*len(msg), msg), 1088, 512, 256, False)
    return digest

def sha3_384(msg):
    sha3_keccak = keccak.Keccak(1600)
    msg = sha3_pad(msg, 832, "01")
    digest = sha3_keccak.Keccak((4*len(msg), msg), 832, 768, 384, False)
    return digest

def sha3_512(msg):
    sha3_keccak = keccak.Keccak(1600)
    msg = sha3_pad(msg, 576, "01")
    digest = sha3_keccak.Keccak((4*len(msg), msg), 576, 1024, 512, False)
    return digest

def shake_128(msg, d):
    sha3_keccak = keccak.Keccak(1600)
    msg = sha3_pad(msg, 1344, "1111")
    digest = sha3_keccak.Keccak((4*len(msg), msg), 1344, 256, d, False)
    return digest

def shake_256(msg, d):
    sha3_keccak = keccak.Keccak(1600)
    msg = sha3_pad(msg, 1088, "1111")
    digest = sha3_keccak.Keccak((4*len(msg), msg), 1088, 512, d, False)
    return digest

def test_sha3_null():
    print("\nTEST-SHA3-NULL")
    err = 0
    if sha3_224("") != "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7".upper():
        err = err + 1
        print("FAIL - SHA3-224")
    if sha3_256("") != "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a".upper():
        err = err + 1
        print("FAIL - SHA3-256")
    if sha3_384("") != "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004".upper():
        err = err + 1
        print("FAIL - SHA3-384")
    if sha3_512("") != "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26".upper():
        err = err + 1
        print("FAIL - SHA3-512")
    if shake_128("", 256) != "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26".upper():
        err = err + 1
        print("FAIL - SHAKE-128")
    if shake_256("", 512) != "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be".upper():
        err = err + 1
        print("FAIL - SHAKE-256")
    if err == 0:
        print("PASS")
    print("\n")

def test_sha3_abc():
    print("\nTEST-SHA3-\"abc\"")
    err = 0
    if sha3_224("616263") != "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf".upper():
        err = err + 1
        print("FAIL - SHA3-224")
    if sha3_256("616263") != "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532".upper():
        err = err + 1
        print("FAIL - SHA3-256")
    if sha3_384("616263") != "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25".upper():
        err = err + 1
        print("FAIL - SHA3-384")
    if sha3_512("616263") != "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0".upper():
        err = err + 1
        print("FAIL - SHA3-512")
    if shake_128("616263", 256) != "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8".upper():
        err = err + 1
        print("FAIL - SHAKE-128")
    if shake_256("616263", 512) != "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4".upper():
        err = err + 1
        print("FAIL - SHAKE-256")
    if err == 0:
        print("PASS")
    print("\n")

def test_sha3_a1M():
    print("\nTEST-SHA3-\"a\"*1M")
    err = 0
    if sha3_224("61"*1000000) != "d69335b93325192e516a912e6d19a15cb51c6ed5c15243e7a7fd653c".upper():
        err = err + 1
        print("FAIL - SHA3-224")
    if sha3_256("61"*1000000) != "5c8875ae474a3634ba4fd55ec85bffd661f32aca75c6d699d0cdcb6c115891c1".upper():
        err = err + 1
        print("FAIL - SHA3-256")
    if sha3_384("61"*1000000) != "eee9e24d78c1855337983451df97c8ad9eedf256c6334f8e948d252d5e0e76847aa0774ddb90a842190d2c558b4b8340".upper():
        err = err + 1
        print("FAIL - SHA3-384")
    if sha3_512("61"*1000000) != "3c3a876da14034ab60627c077bb98f7e120a2a5370212dffb3385a18d4f38859ed311d0a9d5141ce9cc5c66ee689b266a8aa18ace8282a0e0db596c90b0a7b87".upper():
        err = err + 1
        print("FAIL - SHA3-512")
    if err == 0:
        print("PASS")
    print("\n")


## All tests are PASS
#test_sha3_null()
#test_sha3_abc()
#test_sha3_a1M()
