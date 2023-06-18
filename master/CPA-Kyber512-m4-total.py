import numpy as np
import json
from multiprocessing import Pool, cpu_count, Value, Lock, shared_memory
import time

import warnings
warnings.filterwarnings("ignore")

KYBER_N = 256
KYBER_Q = 3329
QINV = -3327
qReg = 0xcff0d01
########## Functions for obtaining cipher text in ntt domain #############

def poly_unpackdecompress(a, i): #Testet viker i runtime :)
    r = [0] * KYBER_N
    for j in range(KYBER_N // 4):
        r[4 * j + 0] = (((a[320 * i + 5 * j + 0] | ((a[320 * i + 5 * j + 1] & 0x03) << 8)) * KYBER_Q) + 512) >> 10
        r[4 * j + 1] = (((a[320 * i + 5 * j + 1] >> 2) | ((a[320 * i + 5 * j + 2] & 0x0f) << 6)) * KYBER_Q + 512) >> 10
        r[4 * j + 2] = (((a[320 * i + 5 * j + 2] >> 4) | ((a[320 * i + 5 * j + 3] & 0x3f) << 4)) * KYBER_Q + 512) >> 10
        r[4 * j + 3] = (((a[320 * i + 5 * j + 3] >> 6) | ((a[320 * i + 5 * j + 4] & 0xff) << 2)) * KYBER_Q + 512) >> 10
    return r

zetas_ntt = [-1044,  -758,  -359, -1517,  1493,  1422,   287,   202,
        -171,   622,  1577,   182,   962, -1202, -1474,  1468,
        573, -1325,   264,   383,  -829,  1458, -1602,  -130,
        -681,  1017,   732,   608, -1542,   411,  -205, -1571,
        1223,   652,  -552,  1015, -1293,  1491,  -282, -1544,
        516,    -8,  -320,  -666, -1618, -1162,   126,  1469,
        -853,   -90,  -271,   830,   107, -1421,  -247,  -951,
        -398,   961, -1508,  -725,   448, -1065,   677, -1275,
        -1103,   430,   555,   843, -1251,   871,  1550,   105,
        422,   587,   177,  -235,  -291,  -460,  1574,  1653,
        -246,   778,  1159,  -147,  -777,  1483,  -602,  1119,
        -1590,   644,  -872,   349,   418,   329,  -156,   -75,
        817,  1097,   603,   610,  1322, -1285, -1465,   384,
        -1215,  -136,  1218, -1335,  -874,   220, -1187, -1659,
        -1185, -1530, -1278,   794, -1510,  -854,  -870,   478,
        -108,  -308,   996,   991,   958, -1460,  1522,  1628]



def montgomery_reduce(a: int, q: int = KYBER_Q) -> int:
    t = (a * QINV) % (1 << 16)
    t = (a - t * q) >> 16
    return t

def fqmul(a: int, b: int) -> int:
    #print(a, b, montgomery_reduce(a * b))
    return montgomery_reduce(a * b)

def ntt(r: list):
    k = 1
    len = 128
    while len >= 2:
        for start in range(0, KYBER_N, len * 2):
            zeta = zetas_ntt[k]
            k += 1
            for j in range(start, start + len):
                t = fqmul(zeta, r[j + len])
                r[j + len] = (r[j] - t) % KYBER_Q
                r[j] = (r[j] + t) % KYBER_Q
        len >>= 1

        
def poly_reduce(r):
    for i in range(len(r)):
        r[i] = barrett_reduce(r[i])
        
def barrett_reduce(a):
    v = ((1 << 26) + KYBER_Q // 2) // KYBER_Q

    t = ((v * a + (1 << 25)) >> 26) * KYBER_Q
    return a - t

def ctPoly(ct, iteration):
    poly=poly_unpackdecompress(ct, iteration)
    ntt(poly)
    poly_reduce(poly)
    always_positive(poly)
    return poly

def always_positive(r):
    for i in range(len(r)):
        r[i] = (r[i] % KYBER_Q + KYBER_Q) % KYBER_Q



##### Basemul asembly operations #######


def is_negative_twos_complement(num, bits):
    msb = (num >> (bits - 1)) & 1
    return msb == 1

def invert_twos_complement(num, bits):
    inverted_num = (~num) & ((1 << bits) - 1)
    inverted_num += 1
    return inverted_num

zetas_basemul = [2226, 430, 555, 843, 2078, 871, 1550, 105, 422, 587, 177, 3094, 3038, 2869,
1574, 1653, 3083, 778, 1159, 3182, 2552, 1483, 2727, 1119, 1739, 644, 2457, 349,
418, 329, 3173, 3254, 817, 1097, 603, 610, 1322, 2044, 1864, 384, 2114, 3193,
1218, 1994, 2455, 220, 2142, 1670, 2144, 1799, 2051, 794, 1819, 2475, 2459, 478,
3221, 3021, 996, 991, 958, 1869, 1522, 1628]


def smultt(a,b, poly):
    negative = False
    
    if (not poly):
        a = ((a >> 16) & 0xFFFF)
        b = (b & 0xFFFF)
    
    if is_negative_twos_complement(a, 16):
        negative = not negative
        a = invert_twos_complement(a, 16)
    
    if is_negative_twos_complement(b, 16):
        negative = not negative
        b = invert_twos_complement(b, 16)
    
    prod = a * b
    
    if negative:
        return invert_twos_complement(prod, 32)
    return prod

def smultb(a,b, poly):
    negative = False
    
    if (not poly):
        a = ((a >> 16) & 0xFFFF)
        b = (b & 0xFFFF)
    
    if is_negative_twos_complement(a, 16):
        negative = not negative
        a = invert_twos_complement(a, 16)
    
    if is_negative_twos_complement(b, 16):
        negative = not negative
        b = invert_twos_complement(b, 16)
    
    prod = a * b
    
    if negative:
        return invert_twos_complement(prod, 32)
    return prod
    

def smulbt(a,b, poly):
    negative = False
    
    if (not poly):
        a = (a & 0xFFFF)
        b = ((b >> 16) & 0xFFFF)
    
    if is_negative_twos_complement(a, 16):
        negative = not negative
        a = invert_twos_complement(a, 16)
    
    if is_negative_twos_complement(b, 16):
        negative = not negative
        b = invert_twos_complement(b, 16)
    
    prod = a * b
    
    if negative:
        return invert_twos_complement(prod, 32)
    return prod
    
def smlabb(a, b, c, poly):
    negative = False
    
    if (not poly):
        a = (a & 0xFFFF)
        b = (b & 0xFFFF)
    
    if is_negative_twos_complement(a, 16):
        negative = not negative
        a = invert_twos_complement(a, 16)
    
    if is_negative_twos_complement(b, 16):
        negative = not negative
        b = invert_twos_complement(b, 16)
    
    prod = a * b
    
    if negative:
        prod = invert_twos_complement(prod, 32)
      
    return (prod + c) & 0xFFFFFFFF



def smuadx(a_top, a_bottom, b_top, b_bottom):
    return (smulbt(a_bottom, b_top, True) + smultb(a_top, b_bottom, True)) & 0xFFFFFFFF  # Keep the result to 32 bits

def pkhtb(a, b):
    return (((a >> 16) & 0xFFFF) << 16) | ((b >> 16) & 0xFFFF)


#########Calculate hamming weight steg 2##########

def hw(n):
    return bin(n).count("1")

def getHammingSteg1(poly, keyguess, iteration):
    # top double base multiplication
    if ((iteration % 2) == 0):
        return hw(smultt(poly[1+4 * (iteration//2)], keyguess, True))
    
    # bottom double base multiplication
    return hw(smultt(poly[3+4 * (iteration//2)], keyguess, True))

def getHammingSteg2(poly, steg1key, keyguess, iteration):
    
    # top double base multiplication
    if ((iteration % 2) == 0):
        zeta = zetas_basemul[iteration // 2]
        ct_top = poly[1+4 * (iteration // 2)]
        ct_bottom = poly[4 * (iteration // 2)]

    # bottom double base multiplication
    else:
        zeta = invert_twos_complement(zetas_basemul[iteration // 2], 32)
        ct_top = poly[3+4* (iteration // 2)]
        ct_bottom = poly[2+4 * (iteration // 2)]
    
    tmp = smultt(ct_top, steg1key, True)
    tmp2 = smulbt(tmp, qReg, False)
    tmp2 = smlabb(qReg, tmp2, tmp, False)
    tmp2 = smultb(tmp2, zeta, False) 
    tmp2 = smlabb(ct_bottom, keyguess, tmp2, True)
    tmp = smulbt(tmp2, qReg, False)
    tmp = smlabb(qReg, tmp, tmp2, False)
    tmp2 = smuadx(ct_top, ct_bottom, steg1key, keyguess)
    tmp3 = smulbt(tmp2,qReg, False)
    tmp3 = smlabb(qReg, tmp3, tmp2, False)
    return hw(pkhtb(tmp3, tmp))


#########Correalation equations########

def mean(X):
    return np.sum(X, axis=0)/len(X)

def std_dev(X, X_bar):
    return np.sqrt(np.sum((X-X_bar)**2, axis=0))

def cov(X, X_bar, Y, Y_bar):
    return np.sum((X-X_bar)*(Y-Y_bar), axis=0)


####### Multiprocessing functions ############
counter = None

def init(args):
    global counter
    counter = args


def calculate_max_cpa_part_1(kguess_range, trace_arrays, cipher_texts, t_bar, o_t, k, byteNr):

    maxcpa_del1_local = []
    maxcpa_del1_index_local = []

    for kguess in kguess_range:
        hws = np.array([[getHammingSteg1(ctPoly(ct, k), kguess, byteNr) for ct in cipher_texts]]).transpose()
        hws_bar = mean(hws)
        o_hws = std_dev(hws, hws_bar)
        covariance = cov(trace_arrays, t_bar, hws, hws_bar)
        correlation = covariance/(o_t*o_hws)
        maxcpa_del1_local.append(max(abs(correlation)))
        maxcpa_del1_index_local.append(int(correlation.argmax()))
        """
        with counter.get_lock():
            counter.value += 1
            print(f"Progress del 1: {counter.value}/{KYBER_Q}", end='\r')
        """
    return maxcpa_del1_local, maxcpa_del1_index_local

def calculate_max_cpa_part_2(kguess_range, trace_arrays, cipher_texts, t_bar, o_t, steg1key, k, byteNr):

    maxcpa_del1_local = []
    maxcpa_del1_index_local = []

    for kguess in kguess_range:
        hws = np.array([[getHammingSteg2(ctPoly(ct, k), steg1key, kguess, byteNr) for ct in cipher_texts]]).transpose()
        hws_bar = mean(hws)
        o_hws = std_dev(hws, hws_bar)
        covariance = cov(trace_arrays, t_bar, hws, hws_bar)
        correlation = covariance/(o_t*o_hws)
        maxcpa_del1_local.append(max(abs(correlation)))
        maxcpa_del1_index_local.append(int(correlation.argmax()))
        """
        with counter.get_lock():
            counter.value += 1
            print(f"Progress del 2 for {hex(steg1key)}: {counter.value}/{KYBER_Q}", end='\r')
        """
    return maxcpa_del1_local, maxcpa_del1_index_local

####### Main ########

if __name__ == "__main__":
  
    for k in range(2):
         
        data = np.load(f'traces/kyber512-k{k}-24400.npy', allow_pickle=True)  # Limit amount of traces with [0:50], [0:200] etc.                          
        trace_arrays = [x[2] for x in data]
        cipher_texts = [x[1] for x in data]
    
        t_bar = mean(trace_arrays) 
        o_t = std_dev(trace_arrays, t_bar)

        for byteNr in range(0, KYBER_N // 2):
            print(f"k = {k}, byteNr = {byteNr}")
            start_time = time.time()
            
            #Del 1
            #counter = Value('i', 0)
            print(f"Del 1", end='\r' )
            with Pool(initializer=init, initargs=(counter, ), processes=cpu_count()) as pool:
                args = [(range(i, min(i + KYBER_Q // cpu_count(), KYBER_Q)), trace_arrays, cipher_texts, t_bar, o_t, k, byteNr) for i in range(0, KYBER_Q, KYBER_Q // cpu_count())]
                results = pool.starmap(calculate_max_cpa_part_1, args)

            maxcpa_del1 = [cpa for result in results for cpa in result[0]]
            maxcpa_del1_index = [index for result in results for index in result[1]]

            with open(f"results/maxcpa1000-k{k}-i{byteNr}-1", "w") as fp:
                        json.dump(maxcpa_del1, fp)


            #Del 2
            maxcpa_wrong_guess = []
            for index in np.argsort(maxcpa_del1)[::-1]:
                #counter = Value('i', 0)
                print(f"Del 2 for {hex(index)}", end='\r')
                with Pool(initializer=init, initargs=(counter, ), processes=cpu_count()) as pool:
                    args = [(range(i, min(i + KYBER_Q // cpu_count(), KYBER_Q)), trace_arrays, cipher_texts, t_bar, o_t, index, k, byteNr) for i in range(0, KYBER_Q, KYBER_Q // cpu_count())]
                    results = pool.starmap(calculate_max_cpa_part_2, args)

                maxcpa_del2 = [cpa for result in results for cpa in result[0]]
                maxcpa_del2_index = [index for result in results for index in result[1]]

                if (max(maxcpa_del2) > 0.90):
                    guess = [int(np.argmax(maxcpa_del2)), int(index)]
                    guess_index = [maxcpa_del2_index[guess[0]], maxcpa_del1_index[index]] 
                    elapsed_time = time.time() - start_time

                    with open(f"results/keyguess1000-k{k}-i{byteNr}", "w") as fp:
                        json.dump([guess, guess_index], fp)
                    with open(f"results/maxcpa1000-k{k}-i{byteNr}-2", "w") as fp:
                        json.dump(maxcpa_del2, fp)
                    with open(f"results/time1000-k{k}-i{byteNr}", "w") as fp:
                        json.dump(elapsed_time, fp)
                    with open(f"results/maxcpa-wrong-guess1000-k{k}-i{byteNr}", "w") as fp:
                        json.dump(maxcpa_wrong_guess, fp)

                    print("Key guess:", [hex(x) for x in guess])
                    print("Index:", guess_index)
                    print("Correalation:", maxcpa_del2[guess[0]])
                    print("time used:", elapsed_time)

                    break
                
                maxcpa_wrong_guess.append((int(np.argmax(maxcpa_del2)), int(index), maxcpa_del2[np.argmax(maxcpa_del2)]))
                print("maxcpa del2 for", hex(np.argmax(maxcpa_del2)), hex(index), "=", maxcpa_del2[np.argmax(maxcpa_del2)])

                
        