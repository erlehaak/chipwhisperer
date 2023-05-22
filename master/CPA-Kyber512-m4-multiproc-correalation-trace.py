import numpy as np
from tqdm import tnrange
import json
from multiprocessing import Pool, cpu_count, Value, Lock

KYBER_N = 256
KYBER_Q = 3329
QINV = -3327

def hw(n):
    return bin(n).count("1")

def poly_unpackdecompress(a, i): #Testet viker i runtime :)
    r = [0] * KYBER_N
    for j in range(KYBER_N // 4):
        r[4 * j + 0] = (((a[320 * i + 5 * j + 0] | ((a[320 * i + 5 * j + 1] & 0x03) << 8)) * KYBER_Q) + 512) >> 10
        r[4 * j + 1] = (((a[320 * i + 5 * j + 1] >> 2) | ((a[320 * i + 5 * j + 2] & 0x0f) << 6)) * KYBER_Q + 512) >> 10
        r[4 * j + 2] = (((a[320 * i + 5 * j + 2] >> 4) | ((a[320 * i + 5 * j + 3] & 0x3f) << 4)) * KYBER_Q + 512) >> 10
        r[4 * j + 3] = (((a[320 * i + 5 * j + 3] >> 6) | ((a[320 * i + 5 * j + 4] & 0xff) << 2)) * KYBER_Q + 512) >> 10
    return r

zetas = [-1044,  -758,  -359, -1517,  1493,  1422,   287,   202,
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
            zeta = zetas[k]
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

def getHammingSteg1(poly, keyguess, iteration):
    return hw(poly[1+4*iteration]*keyguess)

def mean(X):
    return np.sum(X, axis=0)/len(X)

def std_dev(X, X_bar):
    return np.sqrt(np.sum((X-X_bar)**2, axis=0))

def cov(X, X_bar, Y, Y_bar):
    return np.sum((X-X_bar)*(Y-Y_bar), axis=0)

counter = None

def init(args):
    global counter
    counter = args

def calculate_max_cpa(kguess_range):
    data = np.load('dataNewTrigger.npy', allow_pickle=True)
    trace_array = [x[2][:1000] for x in data]
    # we don't need to redo the mean and std dev calculations 
    # for each key guess
    t_bar = mean(trace_array) 
    o_t = std_dev(trace_array, t_bar)
    
    localCorTrace = []
    for i, kguess in enumerate(kguess_range):
        hws = np.array([[getHammingSteg1(ctPoly(d[1][:1000], 0), kguess, 0) for d in data]]).transpose()
        hws_bar = mean(hws)
        o_hws = std_dev(hws, hws_bar)
        correlation = cov(trace_array, t_bar, hws, hws_bar)
        cpaoutput = correlation/(o_t*o_hws)
        localCorTrace.append(cpaoutput)
        
        #Printing progress
        with counter.get_lock():
            counter.value += 1
            print(f"Progress: {counter.value}/{2**16}", end='\r')


    return maxcpalocal

if __name__ == "__main__":
    counter = Value('i', 0)

    with Pool(initializer=init, initargs=(counter, ), processes=cpu_count()) as pool:
        ranges = [range(i, i + 2**16 // cpu_count()) for i in range(0, 2**16, 2**16 // cpu_count())]
        results = pool.map(calculate_max_cpa, ranges)

    CorTrace = [result for sublist in results for result in sublist]  
    
    np.save('Correalation-traces.npy', np.array(CorTrace, dtype=object), allow_pickle=True)