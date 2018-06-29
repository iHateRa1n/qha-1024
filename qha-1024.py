#!/usr/bin/python3

import sys

SECURITY = 0x10
junk = [
0x4d6d3e83, 
0xabdd0468, 
0x8cc61436, 
0x4d0ef5c, 
0x471ca56d, 
0xbc9aab3b, 
0x95ce8b60, 
0xcc46f66e, 
0x861b9f18, 
0x768912e, 
0x4dbf6a3f, 
0xc6ec17a5, 
0xfa481978, 
0xac9f5f05, 
0xe9ad7df1, 
0xbb34ef03, 
0x4b1bd4cf, 
0xb7c4c6d1, 
0x1e0c037c, 
0x71336740, 
0x1837a2cf, 
0x70a6425e, 
0xee93bd45, 
0xd971b3b7, 
0xa0293292, 
0xe3b2e3fd, 
0x22e58bf8, 
0x233c5437, 
0x1a28b1a7, 
0xe553834f, 
0xa12eb25c, 
0xcf25e9c7, 
0x777e6ad9, 
0x2cb90656, 
0xb498ba09, 
0x412f95ed, 
0x2c120384, 
0x31f0726, 
0x941798e1, 
0x3ad8ea3a, 
0xf7a1035e, 
0x46449c53, 
0xdad4df92, 
0x898b8f32, 
0xacbb0d9d, 
0xda3ee1aa, 
0xea1f7a76, 
0xe45bd4b5, 
0xc8725e31, 
0xa43e788d, 
0xc34f0996, 
0x56e34088, 
0x30b4d495, 
0xa0d605e4, 
0xc3126e1a, 
0x3d5d9098, 
0x5b9acb40, 
0xef05b4e2, 
0xe7da58d6, 
0xba97620e, 
0xd6fc64ad, 
0x8af15f84, 
0x55f3cdf5, 
0x68facff5, 
0x2d564cf8, 
0x8cc3ce4, 
0x4eabc70f, 
0x8095fd3d, 
0xa21b1732, 
0x5e598358, 
0x59166c7c, 
0x264577c1, 
0x944dbcc3, 
0x5d2d3011, 
0x8e4a5462, 
0xcc8ab425, 
0x37e2b20a, 
0x73efeef4, 
0x923bb794, 
0x3d9c7f50, 
0xa6d3c56b, 
0xe01770ab, 
0x929b6aec, 
0x6c219b31, 
0x18a06f0c, 
0x9d9b2239, 
0xa2bfe239, 
0xc9642ca2, 
0x6ffa822b, 
0xd9419e1a, 
0xfb39f5d8, 
0x395e3539, 
0xd2e41b1e, 
0x7b96b94a, 
0x9e3977d0, 
0x20fb87b8, 
0x2e11a318, 
0x13341c81, 
0xb0971f73, 
0xd8fcd268, 
0x81bb5c5e, 
0xf41dc3f7, 
0x70503c81, 
0x831766a2, 
0x249392ea, 
0x28b781cb, 
0x2719c61, 
0xbf0a2fbe, 
0x4cdbd8b0, 
0xccd6d6e5, 
0xeffcf3c, 
0x86592ad, 
0x602f08ec, 
0x1da297a0, 
0x81d2d4d2, 
0xfa5aaf07, 
0xc82ff6c3, 
0x3749da17, 
0xd3dfbefa, 
0xdd3e9878, 
0xa362df6d, 
0x8c610616, 
0xd4a2c0e5, 
0xdf268fcf, 
0x4f45a58e, 
0x4d496578, 
0x99ec8d67, 
0x6dc6d515]

def hash_raw(s):
    h = 0
    if type(s) != type(""):
        k = str(s)
    else:
        k = s
    n = 0
    for j in k:
        try:
            h += (ord(j) + junk[n % 128]) - (ord(k[n + 1]) * junk[(n % 128) + 0]) - (ord(k[n + 2]) * junk[(n % 128) + 1]) - (ord(k[n + 3]) * junk[(n % 128) + 2])
            h *= (junk[n % 128] ** 2) + (junk[(n % 128) + 1])
            h -= (ord(j) * junk[n % 128]) - (ord(j))
            h ^= ((junk[n % 128] ** 4) + (junk[(n + 1) % 128] ** 3) + (junk[(n + 2) % 128] ** 2) + (junk[(n + 3) % 128])) * (2**64) - 1
            h *= ((junk[n % 128] ** 4) + (junk[(n + 1) % 128] ** 3) + (junk[(n + 2) % 128] ** 2) + (junk[(n + 3) % 128])) * (junk[n % 128] ** 2) 
            h %= (2**1024)
        except:
            pass
    return h;

def hash(s):
    global SECURITY
    k = hash_raw(s)
    n = 0
    while n < SECURITY:
        k = hash_raw(hex(k)[2:])
        n += 1
    return k;

print(hex(hash(open(sys.argv[1], 'rb').read()))[2:-1])
