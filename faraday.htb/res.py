#!/usr/bin/python3
from itertools import product
import struct, string

flag = "FARADAY{d0ubl3_@nd_f1o@t_"

characters = string.ascii_lowercase + string.punctuation

for combination in product(characters, repeat=5):
    chars = "".join(combination).encode()
    value = b"_" + chars[:2] + b"}" + chars[2:] + b"@"
    result = 1665002837.488342 / struct.unpack("d", value)[0]

    if abs(result - 4088116.817143337) <= 0.0000001192092895507812:  
        value = chars[:2] + b"@" + chars[2:] + b"}"
        print(flag + value.decode())
        break
