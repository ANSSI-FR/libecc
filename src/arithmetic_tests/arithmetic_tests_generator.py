#/*
# *  Copyright (C) 2017 - This file is part of libecc project
# *
# *  Authors:
# *      Ryad BENADJILA <ryadbenadjila@gmail.com>
# *      Arnaud EBALARD <arnaud.ebalard@ssi.gouv.fr>
# *      Jean-Pierre FLORI <jean-pierre.flori@ssi.gouv.fr>
# *
# *  Contributors:
# *      Nicolas VIVET <nicolas.vivet@ssi.gouv.fr>
# *      Karim KHALFALLAH <karim.khalfallah@ssi.gouv.fr>
# *
# *  This software is licensed under a dual BSD and GPL v2 license.
# *  See LICENSE file at the root folder of the project.
# */
#! /usr/bin/env python

import random, sys, re, math, socket, os, select, signal

### Ctrl-C handler
def handler(signal, frame):
    sys.tracebacklimit = 0
    exit(0)

DEFBUFSIZE=32768

def get_cpu_count():
    """
    Try and estimate the number of CPU on the host. First using multiprocessing
    native function, other using content of /proc/cpuinfo. If none of those
    methods did work, 4 is returned.
    """
    try:
        import multiprocessing
        cpucount = multiprocessing.cpu_count()
    except:
        try:
            s = open("/proc/cpuinfo").read()
            cpucount = int(s.split('processor')[-1].split(":")[1].split("\n")[0])
            cpucount += 1
        except:
            cpucount = 4
    return cpucount

# Simple helper to remove comments from a C program
def C_comment_remover(text):
    def replacer(match):
        s = match.group(0)
        if s.startswith('/'):
            return " " # note: a space and not an empty string
        else:
            return s
    regexp = r'//.*?$|/\*.*?\*/|\'(?:\\.|[^\\\'])*\'|"(?:\\.|[^\\"])*"'
    pattern = re.compile(regexp, re.DOTALL | re.MULTILINE)
    return re.sub(pattern, replacer, text)


def egcd(b, n):
    x0, x1, y0, y1 = 1, 0, 0, 1
    while n != 0:
        q, b, n = b // n, n, b % n
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return  b, x0, y0

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def is_probprime(n):
    # ensure n is odd
    if n % 2 == 0:
        return False
    # write n-1 as 2**s * d
    # repeatedly try to divide n-1 by 2
    s = 0
    d = n-1
    while True:
        quotient, remainder = divmod(d, 2)
        if remainder == 1:
            break
        s += 1
        d = quotient
    assert(2**s * d == n-1)
    # test the base a to see whether it is a witness for the compositeness of n
    def try_composite(a):
        if pow(a, d, n) == 1:
            return False
        for i in range(s):
            if pow(a, 2**i * d, n) == n-1:
                return False
        return True # n is definitely composite
    for i in range(5):
        a = random.randrange(2, n)
        if try_composite(a):
            return False
    return True # no base tested showed n as composite

def compute_monty_coef(nn_p, p_bitsize):
    """
    Compute montgomery coeff r, r^2 and mpinv. p_bitsize is the size
    of p in bits. It is expected to be a multiple of word
    bit size.
    """
    r = (1 << p_bitsize) % nn_p
    r_square = (1 << (2 * p_bitsize)) % nn_p
    mpinv = 2**wlen - (modinv(nn_p, 2**wlen))
    return r, r_square, mpinv

def compute_div_coef(nn_p, p_bitsize):
    """
    Compute division coeffs p_normalized, p_shift and p_reciprocal.
    """
    tmp = nn_p
    cnt = 0
    while tmp != 0:
        tmp = tmp >> 1
        cnt += 1
    pshift = p_bitsize - cnt
    nn_pnorm = nn_p << pshift
    B = 2**wlen
    prec = B**3 / ((nn_pnorm >> (p_bitsize - 2*wlen)) + 1) - B
    return pshift, nn_pnorm, prec

def getbitlen(bint):
    """
    Returns the number of bits encoding an integer
    """
    return bint.bit_length()

def getwlenbitlen(bint, wlen):
    """
    Returns the number of bits encoding an integer
    """
    rounded_wlen_bitlen = ((getbitlen(bint) + wlen - 1) / wlen) * wlen
    if(rounded_wlen_bitlen == 0):
        rounded_wlen_bitlen = wlen
    return rounded_wlen_bitlen


def format_int_string(bint, wlen):
    """
    Returns the string format of an integer rounded to wlen
    """
    rounded_bytelen = (wlen/8) * ((getbitlen(bint) + wlen - 1) / wlen)
    # Special case of zero bit length
    if(rounded_bytelen == 0):
        rounded_bytelen = wlen/8
    return (("%%0%dx" % (2 * rounded_bytelen)) % bint)

def get_random_bigint(wlen, maxwlensize):
    nn_nwords = random.randint(1, maxwlensize)
    nn_maxval = 2 ** (nn_nwords * wlen) - 1
    return random.randint(0, nn_maxval)

if ((len(sys.argv) != 5) and (len(sys.argv) != 6)):
    sys.stderr.write("Usage: %s outfile wlen ntests [tests]\n" % sys.argv[0])
    sys.stderr.write("with\n")
    sys.stderr.write(" outfile: file in which generated tests will be stored\n")
    sys.stderr.write(" wlen   : target architecture word length in bits (64, 32 or 16)\n")
    sys.stderr.write(" maxlen : maximum bit length of tests (e.g. 521 bits, ...)\n")
    sys.stderr.write(" ntests : a multiplier for the number of tests to perform\n")
    sys.stderr.write(" tests  : (optional) specific tests to perform (regexp opcodes) OR\n")
    sys.stderr.write("          a '.c' file where to get the implemented tests. filename\n")
    sys.stderr.write("          is given using e.g. file=fp_pow.c\n")
    sys.exit(-1)

testfile = sys.argv[1]
wlen = int(sys.argv[2])
maxlen = int(sys.argv[3])
ntests = int(sys.argv[4])

nn_logical_tests = ["NN_SHIFT_RIGHT", "NN_SHIFT_LEFT", "NN_ROTATE_RIGHT", "NN_ROTATE_LEFT",
                    "NN_AND", "NN_XOR", "NN_OR", "NN_NOT"]
nn_addition_tests = ["NN_ADD", "NN_SUB", "NN_INC", "NN_DEC", "NN_MOD_ADD", "NN_MOD_SUB", "NN_MOD_INC", "NN_MOD_DEC"]
nn_mul_tests = ["NN_MUL", "NN_MUL_REDC1", "NN_COEF_REDC1", "NN_COEF_DIV" ]
nn_div_tests = ["NN_MOD", "NN_DIVREM", "NN_MODINV", "NN_MODINV_2EXP", "NN_XGCD", "NN_GCD"]

nn_tests = nn_logical_tests + nn_addition_tests + nn_mul_tests + nn_div_tests

fp_add_tests = ["FP_ADD", "FP_SUB"]
fp_mul_tests = ["FP_MUL", "FP_DIV", "FP_MUL_REDC1", "FP_POW"]

fp_tests = fp_add_tests + fp_mul_tests

all_tests = nn_tests + fp_tests

# Get optional specific parameters
asked_tests = all_tests
if (len(sys.argv) == 6):
    # Do we have a .c file given as input?
    if (sys.argv[5])[:5] == "file=":
        file_name = (sys.argv[5])[5:]
        # Open the .c file
        C_string = C_comment_remover(open(file_name, 'r').read())
        # Grep the interesting tests
        lines = C_string.split("\n")
        asked_tests = []
        for line in lines:
            if line[:13] == "GENERIC_TEST(":
                # Get second argument, which is the opcode
                the_test = line.split(",")[1].replace(" ", "")
                asked_tests += [the_test]
    # We have a list of opcode regexps
    else:
        def check_regexp(regexp, string):
            return re.match(regexp+"$", string)
        asked_tests = []
        asked_tests_regexps = ((sys.argv[5]).replace(" ", "")).split(",")
        # Check for regexps
        for regexp in asked_tests_regexps:
            # Asked operations must be known
            match = [x for x in all_tests if check_regexp(regexp, x)]
            if match == []:
                print "Warning: regexp matches no known operation ", regexp
            asked_tests += match

# Unnecessary test (we can keep it though)
if len(list(set(asked_tests) & set(all_tests))) != len(asked_tests):
    print "Error: unknown asked tests ", list(set(asked_tests) - set(all_tests))
    exit(-1)

# Delta to use on word boundaries.
WORD_BOUNDARY_DELTA=3

# Max size (in words) of input numbers (nn, fp) on which to perform tests
MAX_INPUT_PARAM_WLEN= ((maxlen + wlen - 1) / wlen)

test_funcs = { }

# Generate tests for NN_SHIFT_RIGHT and NN_SHIFT_LEFT operations.
def test_NN_SHIFT(op):
    nn_nwords = random.randint(1, MAX_INPUT_PARAM_WLEN)
    nn_maxval = 2 ** (nn_nwords * wlen) - 1
    nn_nbits = nn_nwords * wlen

    nn_val = random.randint(0, nn_maxval)

    res = []

    # try and consider all possible words boundary on input ...
    for boundary in range(0, (nn_nwords + 1) * wlen, wlen):
        # and generate shift for bitcount in an interval around
        # that boundary, i.e. [boundary - delta, boundary + delta]
        min_cnt = max(0, boundary - WORD_BOUNDARY_DELTA)
        max_cnt = min(nn_nbits, boundary + WORD_BOUNDARY_DELTA)
        cnt = random.randint(min_cnt, max_cnt);
        msk = nn_maxval

        # we try different bitlen for output
        for outbitlen in [boundary - wlen, boundary, boundary + wlen]:
            if outbitlen <= wlen:
                outbitlen = wlen

            # Depending on the type of shift operation we consider, 
            # we adapt the & mask
            if (op == "NN_SHIFT_RIGHT_FIXEDLEN"): # NN_SHIFT_RIGHT_FIXEDLEN
                msk = (2 ** outbitlen) - 1
                out = (nn_val >> cnt) & msk
            elif (op == "NN_SHIFT_LEFT_FIXEDLEN"): # NN_SHIFT_LEFT_FIXEDLEN
                msk = (2 ** outbitlen) - 1
                out = (nn_val << cnt) & msk
            elif (op == "NN_SHIFT_RIGHT"): # NN_SHIFT_RIGHT
                outbitlen = nn_nbits
                msk = (2 ** outbitlen) - 1
                out = (nn_val >> cnt) & msk 
            else: # NN_SHIFT_LEFT
                outbitlen = nn_nbits + cnt
		# Round the bit length to the word boundary
		outbitlen = ((outbitlen + wlen - 1) / wlen) * wlen
                msk = (2 ** outbitlen) - 1
                out = (nn_val << cnt) & msk

            fmt = "%s nnu %s %s %d\n"
            res.append(fmt % (op, format_int_string(out, wlen), format_int_string(nn_val, wlen), cnt))

    return res

test_funcs["NN_SHIFT_RIGHT_FIXEDLEN"] = test_NN_SHIFT
test_funcs["NN_SHIFT_LEFT_FIXEDLEN"]  = test_NN_SHIFT
test_funcs["NN_SHIFT_RIGHT"] = test_NN_SHIFT
test_funcs["NN_SHIFT_LEFT"]  = test_NN_SHIFT

# Generate tests for NN_ROTATE_LEFT and NN_ROTATE_RIGHT operations.
def test_NN_ROTATE(op):
    # random value for both input numbers
    nn_val = get_random_bigint(wlen, MAX_INPUT_PARAM_WLEN)
    bitlen = random.randint(1, getbitlen(nn_val))
    cnt = random.randint(0, bitlen-1)

    res = []

    if (op == "NN_ROTATE_LEFT"):  # NN_ROTATE_LEFT
        nn_exp_res = ((nn_val << cnt) ^ (nn_val >> (bitlen - cnt))) & (2**bitlen - 1)
    else: 			  # NN_ROTATE_RIGHT
        nn_exp_res = ((nn_val >> cnt) ^ (nn_val << (bitlen - cnt))) & (2**bitlen - 1)

    fmt = "%s nnuu %s %s %d %d\n"
    res.append(fmt % (op, format_int_string(nn_exp_res, wlen), format_int_string(nn_val, wlen), cnt, bitlen))

    return res

test_funcs["NN_ROTATE_LEFT"] = test_NN_ROTATE
test_funcs["NN_ROTATE_RIGHT"] = test_NN_ROTATE


# Generate tests for NN_XOR, NN_OR and NN_AND operations.
def test_NN_XOR_OR_AND(op):
    # random value for both input numbers
    nn1_val = get_random_bigint(wlen, MAX_INPUT_PARAM_WLEN)
    nn2_val = get_random_bigint(wlen, MAX_INPUT_PARAM_WLEN)

    res = []

    if (op == "NN_XOR"):  # NN_XOR
        nn_exp_res = nn1_val ^ nn2_val
    elif (op == "NN_OR"): # NN_OR
        nn_exp_res = nn1_val | nn2_val
    else:                 # NN_AND
        nn_exp_res = nn1_val & nn2_val

    fmt = "%s nnn %s %s %s\n"
    res.append(fmt % (op, format_int_string(nn1_val, wlen), format_int_string(nn2_val, wlen), format_int_string(nn_exp_res, wlen)))

    return res

test_funcs["NN_XOR"] = test_NN_XOR_OR_AND
test_funcs["NN_OR"]  = test_NN_XOR_OR_AND
test_funcs["NN_AND"]  = test_NN_XOR_OR_AND


def test_NN_NOT(op):
    """ Generate tests for NN_NOT """
    nn_val = get_random_bigint(wlen, MAX_INPUT_PARAM_WLEN)

    res = []

    # python sucks at computing logical not. It generates a two's complement
    # representation, which mays result in a negative value i.e. not what we
    # are looking for.
    nn_exp_res = ((2 ** getwlenbitlen(nn_val, wlen)) - 1) & (~nn_val)

    fmt = "%s nn %s %s\n"
    res.append(fmt % (op, format_int_string(nn_val, wlen), format_int_string(nn_exp_res, wlen)))

    return res

test_funcs["NN_NOT"] = test_NN_NOT


def test_NN_ADD_SUB(op):
    """ Generate tests for NN_ADD and NN_SUB """
    # Get two random big num
    nn_val1 = get_random_bigint(wlen, MAX_INPUT_PARAM_WLEN)
    nn_val2 = get_random_bigint(wlen, MAX_INPUT_PARAM_WLEN)

    # Compute the result depending on the operation
    if (op == "NN_ADD"):
        res = nn_val1 + nn_val2
    else:
        if (nn_val1 < nn_val2):
            tmp = nn_val1
            nn_val1 = nn_val2
            nn_val2 = tmp
        res = nn_val1 - nn_val2
    nn_exp_res = res

    fmt = "%s nnn %s %s %s\n"
    s = fmt % (op, format_int_string(nn_val1, wlen), format_int_string(nn_val2, wlen), format_int_string(nn_exp_res, wlen))

    return [ s ]

test_funcs["NN_ADD"] = test_NN_ADD_SUB
test_funcs["NN_SUB"] = test_NN_ADD_SUB


def test_NN_INC_DEC(op):
    """ Generate tests for NN_INC and NN_DEC """
    nn_val = get_random_bigint(wlen, MAX_INPUT_PARAM_WLEN)

    # Compute the result depending on the operation
    if (op == "NN_INC"):
        res = nn_val + 1
    else:
        res = nn_val - 1
    nn_exp_res = res

    fmt = "%s nn %s %s\n"
    s = fmt % (op, format_int_string(nn_val, wlen), format_int_string(nn_exp_res, wlen))

    return [ s ]

test_funcs["NN_INC"] = test_NN_INC_DEC
test_funcs["NN_DEC"] = test_NN_INC_DEC

def test_NN_MOD_ADD_SUB(op):
    """ Generate tests for modular NN_ADD and NN_SUB """
    # Get three random big num
    nn_mod = get_random_bigint(wlen, MAX_INPUT_PARAM_WLEN)
    nn_val1 = get_random_bigint(wlen, MAX_INPUT_PARAM_WLEN) % nn_mod
    nn_val2 = get_random_bigint(wlen, MAX_INPUT_PARAM_WLEN) % nn_mod

    # Compute the result depending on the operation
    if (op == "NN_MOD_ADD"):
        res = (nn_val1 + nn_val2) % nn_mod
    else:
        if (nn_val1 < nn_val2):
            tmp = nn_val1
            nn_val1 = nn_val2
            nn_val2 = tmp
        res = (nn_val1 - nn_val2) % nn_mod
    nn_exp_res = res

    fmt = "%s nnnn %s %s %s %s\n"
    s = fmt % (op, format_int_string(nn_val1, wlen), format_int_string(nn_val2, wlen), format_int_string(nn_mod, wlen), format_int_string(nn_exp_res, wlen))

    return [ s ]

test_funcs["NN_MOD_ADD"] = test_NN_MOD_ADD_SUB
test_funcs["NN_MOD_SUB"] = test_NN_MOD_ADD_SUB

def test_NN_MOD_INC_DEC(op):
    """ Generate tests for NN_MOD_INC and NN_MOD_DEC """
    nn_mod = get_random_bigint(wlen, MAX_INPUT_PARAM_WLEN)
    nn_val = get_random_bigint(wlen, MAX_INPUT_PARAM_WLEN) % nn_mod

    # Compute the result depending on the operation
    if (op == "NN_MOD_INC"):
        res = (nn_val + 1) % nn_mod
    else:
        if nn_val == 0:
            nn_val = nn_val + 1
        res = (nn_val - 1) % nn_mod
    nn_exp_res = res

    fmt = "%s nnn %s %s %s\n"
    s = fmt % (op, format_int_string(nn_val, wlen), format_int_string(nn_mod, wlen), format_int_string(nn_exp_res, wlen))

    return [ s ]

test_funcs["NN_MOD_INC"] = test_NN_MOD_INC_DEC
test_funcs["NN_MOD_DEC"] = test_NN_MOD_INC_DEC


def test_NN_MUL(op):
    """ Generate tests for NN_MUL """
    # random value for input numbers
    nn_in1 = get_random_bigint(wlen, MAX_INPUT_PARAM_WLEN)
    nn_in2 = get_random_bigint(wlen, MAX_INPUT_PARAM_WLEN)

    out = nn_in1 * nn_in2

    fmt = "%s nnnu %s %s %s\n"
    s = fmt % (op, format_int_string(out, wlen), format_int_string(nn_in1, wlen), format_int_string(nn_in2, wlen))

    return [ s ]

test_funcs["NN_MUL"] = test_NN_MUL

def test_NN_MOD(op):
    """ Generate tests for NN_MOD """
    # random value for input numbers
    nn_c = get_random_bigint(wlen, MAX_INPUT_PARAM_WLEN)
    nn_d = get_random_bigint(wlen, MAX_INPUT_PARAM_WLEN)

    nn_exp_r = nn_c % nn_d

    fmt = "%s nnn %s %s %s\n"
    s = fmt % (op, format_int_string(nn_exp_r, wlen), format_int_string(nn_c, wlen), format_int_string(nn_d, wlen))

    return [ s ]

test_funcs["NN_MOD"] = test_NN_MOD

def test_NN_DIVREM(op):
    """ Generate tests for NN_DIVREM """
    # random value for input numbers
    nn_c = get_random_bigint(wlen, MAX_INPUT_PARAM_WLEN)
    nn_d = get_random_bigint(wlen, MAX_INPUT_PARAM_WLEN)

    nn_exp_q = (nn_c / nn_d)
    nn_exp_r = nn_c % nn_d

    fmt = "%s nnnn %s %s %s %s\n"
    s = fmt % (op, format_int_string(nn_exp_q, wlen), format_int_string(nn_exp_r, wlen), format_int_string(nn_c, wlen), format_int_string(nn_d, wlen))

    return [ s ]

test_funcs["NN_DIVREM"] = test_NN_DIVREM

def test_NN_XGCD(op):
    """ Generate tests for NN_XGCD """
    # random value for input numbers
    nn_a = get_random_bigint(wlen, MAX_INPUT_PARAM_WLEN)
    nn_b = get_random_bigint(wlen, MAX_INPUT_PARAM_WLEN)

    (nn_exp_g, nn_exp_u, nn_exp_v) = egcd(nn_a, nn_b)
    # Check sign of u and v and adapt output
    if nn_exp_u < 0:
        sign = -1
        nn_exp_u = (((2 ** getbitlen(nn_exp_u)) - 1) & (~nn_exp_u)) + 1
    else:
        sign = 1
        nn_exp_v = (((2 ** getbitlen(nn_exp_v)) - 1) & (~nn_exp_v)) + 1
    fmt = "%s nnnnnu %s %s %s %s %s %d\n"
    s = fmt % (op, format_int_string(nn_exp_g, wlen), format_int_string(nn_exp_u, wlen), format_int_string(nn_exp_v, wlen), format_int_string(nn_a, wlen), format_int_string(nn_b, wlen), sign)

    return [ s ]

test_funcs["NN_XGCD"] = test_NN_XGCD

def test_NN_GCD(op):
    """ Generate tests for NN_GCD """
    # random value for input numbers
    nn_a = get_random_bigint(wlen, MAX_INPUT_PARAM_WLEN)
    nn_b = get_random_bigint(wlen, MAX_INPUT_PARAM_WLEN)

    (nn_exp_g, nn_exp_u, nn_exp_v) = egcd(nn_a, nn_b)

    fmt = "%s nnn %s %s %s\n"
    s = fmt % (op, format_int_string(nn_exp_g, wlen), format_int_string(nn_a, wlen), format_int_string(nn_b, wlen))

    return [ s ]

test_funcs["NN_GCD"] = test_NN_GCD

def test_NN_MODINV(op):
    """ Generate tests for NN_MODINV """
    # random value for input numbers
    nn_x = get_random_bigint(wlen, MAX_INPUT_PARAM_WLEN)
    nn_m = get_random_bigint(wlen, MAX_INPUT_PARAM_WLEN)

    try:
        nn_exp_v = modinv(nn_x, nn_m)
        exp_r = 1
    except Exception:
        nn_exp_v = 0
        exp_r = 0

    fmt = "%s nnnu %s %s %s %d\n"
    s = fmt % (op, format_int_string(nn_exp_v, wlen), format_int_string(nn_x, wlen), format_int_string(nn_m, wlen), exp_r)

    return [ s ]

test_funcs["NN_MODINV"] = test_NN_MODINV

def test_NN_MODINV_2EXP(op):
    """ Generate tests for NN_MODINV_2EXP """
    # random value for input number, must be odd
    nn_x = get_random_bigint(wlen, MAX_INPUT_PARAM_WLEN) | 1
    exp = random.randint(1, MAX_INPUT_PARAM_WLEN * wlen)

    nn_exp_v = modinv(nn_x, 2**exp)

    fmt = "%s nnuu %s %s %d %d\n"
    s = fmt % (op, format_int_string(nn_exp_v, wlen), format_int_string(nn_x, wlen), exp, 1)

    return [ s ]

test_funcs["NN_MODINV_2EXP"] = test_NN_MODINV_2EXP

def test_NN_MUL_REDC1(op):
    """ Generate tests for NN_MUL_REDC1 """
    # Odd modulus
    nn_mod = get_random_bigint(wlen, MAX_INPUT_PARAM_WLEN) | 1
    nn_r, nn_r_square, mpinv = compute_monty_coef(nn_mod, getwlenbitlen(nn_mod, wlen))

    # random value for input numbers modulo our random mod
    nn_in1 = get_random_bigint(wlen, MAX_INPUT_PARAM_WLEN) % nn_mod
    nn_in2 = get_random_bigint(wlen, MAX_INPUT_PARAM_WLEN) % nn_mod
 
    # Montgomery multiplication computes in1 * in2 * r^-1 (mod)
    out = (nn_in1 * nn_in2 * modinv(nn_r, nn_mod)) % nn_mod

    fmt = "%s nnnnu %s %s %s %s %d\n"
    s = fmt % (op, format_int_string(out, wlen), format_int_string(nn_in1, wlen), format_int_string(nn_in2, wlen), format_int_string(nn_mod, wlen), mpinv)

    return [ s ]

test_funcs["NN_MUL_REDC1"] = test_NN_MUL_REDC1

def test_NN_COEF_REDC1(op):
    """ Generate tests for NN_COEF_REDC1 """
    # Odd modulus
    nn_mod = get_random_bigint(wlen, MAX_INPUT_PARAM_WLEN) | 1
    # Get the results
    # Expand the modulus size if necessary
    if getwlenbitlen(nn_mod, wlen) == wlen:
        nn_r, nn_r_square, mpinv = compute_monty_coef(nn_mod, 2*getwlenbitlen(nn_mod, wlen))
    else:
        nn_r, nn_r_square, mpinv = compute_monty_coef(nn_mod, getwlenbitlen(nn_mod, wlen))
 
    fmt = "%s nnnu %s %s %s %d\n"
    s = fmt % (op, format_int_string(nn_r, wlen), format_int_string(nn_r_square, wlen), format_int_string(nn_mod, wlen), mpinv)

    return [ s ]

test_funcs["NN_COEF_REDC1"] = test_NN_COEF_REDC1

def test_NN_COEF_DIV(op):
    """ Generate tests for NN_COEF_DIV """
    # Odd modulus
    nn_mod = get_random_bigint(wlen, MAX_INPUT_PARAM_WLEN) | 1
    # Get the results
    # Expand the modulus size if necessary
    if getwlenbitlen(nn_mod, wlen) == wlen:
        pshift, nn_pnorm, prec = compute_div_coef(nn_mod, 2*getwlenbitlen(nn_mod, wlen))
    else:
        pshift, nn_pnorm, prec = compute_div_coef(nn_mod, getwlenbitlen(nn_mod, wlen))
 
    fmt = "%s nuun %s %d %d %s\n"
    s = fmt % (op, format_int_string(nn_pnorm, wlen), pshift, prec, format_int_string(nn_mod, wlen))

    return [ s ]

test_funcs["NN_COEF_DIV"] = test_NN_COEF_DIV


# Helper to compute and export an Fp context
def format_fp_context(nn_p, wlen):
    nn_nbits = getwlenbitlen(nn_p, wlen)
    if nn_nbits == wlen:
        nn_nbits = 2 * wlen
    nn_r, nn_r_square, mpinv = compute_monty_coef(nn_p, nn_nbits)
    pshift, nn_pnorm, prec = compute_div_coef(nn_p, nn_nbits)
    f = "%%0%dx" % ((nn_nbits / 8) * 2)
    fmpinv = "%%0%dx" % (((wlen / 8)) * 2)
    return ("%s%s%s%s%s%s%s" % (f % nn_p, f % nn_r, f % nn_r_square, fmpinv % mpinv,
               fmpinv % pshift, f % nn_pnorm, fmpinv % prec))

def test_FP_ADD_SUB(op):
    """ Generate tests for FP_ADD_SUB """ 
    # Get random prime
    #nn_p = random.randint(0, nn_maxval)
    #while not is_probprime(nn_p):
    #    nn_p = random.randint(0, nn_maxval)
    # Use random odd number for faster generation
    nn_p = get_random_bigint(wlen, MAX_INPUT_PARAM_WLEN) | 1

    # Get two random big num
    fp_val1 = get_random_bigint(wlen, MAX_INPUT_PARAM_WLEN) % nn_p
    fp_val2 = get_random_bigint(wlen, MAX_INPUT_PARAM_WLEN) % nn_p

    # Compute the result depending on the operation
    if (op == "FP_ADD"):
        fp_exp_res = (fp_val1 + fp_val2) % nn_p
    else:
        fp_exp_res = (fp_val1 - fp_val2) % nn_p

    fmt = "%s cfff %s %s %s %s\n"
    s = fmt % (op, format_fp_context(nn_p, wlen), format_int_string(fp_exp_res, wlen), format_int_string(fp_val1, wlen), format_int_string(fp_val2, wlen))

    return [ s ]

test_funcs["FP_ADD"] = test_FP_ADD_SUB
test_funcs["FP_SUB"] = test_FP_ADD_SUB


def test_FP_MUL_DIV(op):
    """ Generate tests for FP_MUL_DIV """ 
    # Get random prime
    #nn_p = random.randint(0, nn_maxval)
    #while not is_probprime(nn_p):
    #    nn_p = random.randint(0, nn_maxval)
    # Use random odd number for faster generation
    nn_p = get_random_bigint(wlen, MAX_INPUT_PARAM_WLEN) | 1

    # Get two random big num
    fp_val1 = get_random_bigint(wlen, MAX_INPUT_PARAM_WLEN) % nn_p
    fp_val2 = get_random_bigint(wlen, MAX_INPUT_PARAM_WLEN) % nn_p
    # p is not prime, so make sure fp_val2 is invertible
    if (op == "FP_DIV"):
        while egcd(fp_val2, nn_p)[0] != 1:
            fp_val2 = get_random_bigint(wlen, MAX_INPUT_PARAM_WLEN) % nn_p

    # Compute the result depending on the operation
    if (op == "FP_MUL"):
        fp_exp_res = (fp_val1 * fp_val2) % nn_p
    else:
        fp_exp_res = (fp_val1 * modinv(fp_val2, nn_p)) % nn_p

    fmt = "%s cfff %s %s %s %s\n"
    s = fmt % (op,format_fp_context(nn_p, wlen), format_int_string(fp_exp_res, wlen), format_int_string(fp_val1, wlen), format_int_string(fp_val2, wlen))

    return [ s ]

test_funcs["FP_MUL"] = test_FP_MUL_DIV
test_funcs["FP_DIV"] = test_FP_MUL_DIV


def test_FP_MUL_REDC1(op):
    """ Generate tests for FP_MUL_REDC1 """
    # Get random prime
    #while not is_probprime(nn_p):
    #    nn_p = random.randint(0, nn_maxval)
    # Use random odd number for faster generation
    nn_p = get_random_bigint(wlen, MAX_INPUT_PARAM_WLEN) | 1
    if getwlenbitlen(nn_p, wlen) == wlen:
        nn_r, nn_r_square, mpinv = compute_monty_coef(nn_p, 2*getwlenbitlen(nn_p, wlen))
    else:
        nn_r, nn_r_square, mpinv = compute_monty_coef(nn_p, getwlenbitlen(nn_p, wlen))

    # Get two random big num
    fp_val1 = get_random_bigint(wlen, MAX_INPUT_PARAM_WLEN) % nn_p
    fp_val2 = get_random_bigint(wlen, MAX_INPUT_PARAM_WLEN) % nn_p
    # representations of fp_val1 and fp_val2 in Montgomery's world
    fp_val1_mont = (fp_val1 * nn_r ) % nn_p
    fp_val2_mont = (fp_val2 * nn_r ) % nn_p

    fp_exp_res = (fp_val1_mont * fp_val2_mont * modinv(nn_r%nn_p, nn_p)) % nn_p

    fmt = "%s cfff %s %s %s %s\n"
    s = fmt % (op, format_fp_context(nn_p, wlen), format_int_string(fp_exp_res, wlen), format_int_string(fp_val1_mont, wlen), format_int_string(fp_val2_mont, wlen))

    return [ s ]

test_funcs["FP_MUL_REDC1"] = test_FP_MUL_REDC1


def test_FP_POW(op):
    """ Generate tests for FP_POW """
    # Instead of random prime, use random odd number for faster generation
    nn_p = get_random_bigint(wlen, MAX_INPUT_PARAM_WLEN) | 1

    # Get two random big num
    fp_val = get_random_bigint(wlen, MAX_INPUT_PARAM_WLEN) % nn_p
    nn_exp = get_random_bigint(wlen, MAX_INPUT_PARAM_WLEN) % nn_p

    fp_exp_res = pow(fp_val, nn_exp, nn_p)

    fmt = "%s cffn %s %s %s %s\n"
    s = fmt % (op, format_fp_context(nn_p, wlen), format_int_string(fp_exp_res, wlen), format_int_string(fp_val, wlen), format_int_string(nn_exp, wlen))

    return [ s ]

test_funcs["FP_POW"] = test_FP_POW


def do_test(sockfd, op, n):
    """
    Do given test and send back result on given socket
    before leaving.
    """
    res = []
    for k in range(n):
        res += test_funcs[op](op)
    remain = "".join(res)
    while (remain):
        cur = remain[:DEFBUFSIZE]
        sockfd.send(cur)
        remain = remain[DEFBUFSIZE:]
    sockfd.close()


# The way we make generation parallel is by splitting ntests equally
# on the number of proc we have.
signal.signal(signal.SIGINT, handler)

# ATM, we spawn as many processes as the number of tests we have.
# We adapt the output on stdout or regular file.
if testfile == "stdout":
    fd = sys.stdout
else:
    fd = open(testfile, "w")
numproc = get_cpu_count()
line = 0

sys.stderr.write("[+] Dispatching our %d tests on %d proc\n" % (ntests, numproc))

for test in asked_tests:
    socks = []

    # Before forking, we need to be sure there is no
    # remaining data in file fd buffers, otherwise
    # those will end up being flushed by out childs
    # and create duplicates in the file.
    fd.flush()

    n = max((ntests / numproc), 1)
    for k in range(0, ntests, n):
        # Create a pair of sockets for us and the child we'll spawn
        a, b = socket.socketpair()
        a.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, DEFBUFSIZE)
        b.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, DEFBUFSIZE)
        a.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, DEFBUFSIZE)
        b.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, DEFBUFSIZE)

        # keep track of our socket
        socks.append(a)

        # Double fork a helper to create the campaign for this specific
        # test.
        pid = os.fork()
        if pid != 0:
            os.waitpid(pid, 0)
        else:
            pid = os.fork()
            if pid != 0:
                sys.exit()
            else:
                a.close()
                do_test(b, test, n)
                sys.exit()

        b.close()

    # Now that we have fork all helpers, let's just wait until they are
    # done and read back the results to write them to file.
    while socks:
        tmp = select.select(socks, [], [])
        for s in tmp[0]:
            socks.remove(s)
            tmp = s.recv(DEFBUFSIZE)
            res = ""
            while tmp:
                res += tmp
                tmp = s.recv(DEFBUFSIZE)
            res = res.split('\n')[:-1]
            reslen = len(res)
            res = zip(range(reslen), res)
            fd.write("".join(map(lambda (x,y): "%d %s\n" % (x + line, y), res)))
            line += reslen

fd.close()
