import numpy as np
from tqdm import tnrange
import json
from multiprocessing import Pool, cpu_count, Value, Lock

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
    poly=poly_unpackdecompress(ct, 0)
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


def getHammingSteg2(poly, steg1key, keyguess, iteration):
    
    zeta = zetas_basemul[iteration]
    
    tmp = smultt(poly[1+4*iteration], steg1key, True)
    tmp2 = smulbt(tmp, qReg, False)
    tmp2 = smlabb(qReg, tmp2, tmp, False)
    tmp2 = smultb(tmp2, zeta, False) 
    tmp2 = smlabb(poly[4*iteration], keyguess, tmp2, True)
    tmp = smulbt(tmp2, qReg, False)
    tmp = smlabb(qReg, tmp, tmp2, False)
    tmp2 = smuadx(poly[1+4*iteration], poly[4*iteration], steg1key, keyguess)
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

if __name__ == "__main__":

    data = np.load('dataNewTrigger.npy', allow_pickle=True)
    data_del_1 = data[0:1000]                               #Siden første nøkkel, skal være [index:index+1000 fra forige nøkkel]
    trace_array = [x[2] for x in data_del_1]
   
    t_bar = mean(trace_array) 
    o_t = std_dev(trace_array, t_bar)

    #Del 1
    maxcpa_del1 = []
    maxcpa_del1_index = []

    for kguess in range(KYBER_Q):
        hws = np.array([[getHammingSteg1(ctPoly(d[1], 0), kguess, 0) for d in data_del_1]]).transpose()
        hws_bar = mean(hws)
        o_hws = std_dev(hws, hws_bar)
        covariance = cov(trace_array, t_bar, hws, hws_bar)
        correlation = covariance/(o_t*o_hws)
        maxcpa_del1.append(max(abs(correlation)))
        maxcpa_del1_index.append(cpaoutput.argmax())
        
        
        print(f"Progress: {kguess}/{KYBER_Q}", end='\r')

    #Del 2
    for index in numpy.argsort(maxcpa_del1):
            data_del_2 = data[maxcpa_del1_index[index]:maxcpa_del1_index[index]+150] # Vil gå out of range mot de siste nøkklene
            trace_array = [x[2] for x in data_del_2]
   
            t_bar = mean(trace_array) 
            o_t = std_dev(trace_array, t_bar)

            maxcpa_del2 = []
            maxcpa_del2_index = []

            for kguess in range(KYBER_Q):
                hws = np.array([[getHammingSteg2(ctPoly(d[1], 0), index, kguess, 0) for d in data]]).transpose()
                hws_bar = mean(hws)
                o_hws = std_dev(hws, hws_bar)
                covariance = cov(trace_array, t_bar, hws, hws_bar)
                correlation = covariance/(o_t*o_hws)
                maxcpa_del2.append(max(abs(correlation)))
                maxcpa_del2_index.append(cpaoutput.argmax())

                if 
        
                print(f"Progress: {kguess}/{KYBER_Q}", end='\r')
            
                

    

    #Del 1
    with Pool(initializer=init, initargs=(counter, ), processes=cpu_count()) as pool:
        ranges = [range(i, i + 2**16 // cpu_count()) for i in range(0, 2**16, 2**16 // cpu_count())]
        results = pool.map(calculate_max_cpa, ranges)

    maxcpa_del1 = [result for sublist in results for result in sublist]

    #Del 2
    

    with Pool(initializer=init, initargs=(counter, ), processes=cpu_count()) as pool:
        ranges = [range(i, i + 2**16 // cpu_count()) for i in range(0, KYBER_Q, KYBER_Q // cpu_count())]
        results = pool.map(calculate_max_cpa, ranges)

      
    

    guess = np.argmax(maxcpa)
    guess_corr = max(maxcpa)

    print("Key guess: ", hex(guess))
    print("Correlation: ", guess_corr)
    print("Fasit", hex(0xa36), "corr:", maxcpa[0xa36])

    with open("maxcpa-steg2", "w") as fp:
        json.dump(maxcpa, fp)