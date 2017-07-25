import struct

# AK2I rom layout
# | offset | size   | desc                                        |
# | 0x0000 | 0x2000 | stage2 blowfish data(0x1048 bytes + padding |
# | 0x2000 | 0x1000 | nds header                                  |
# | 0x3000 | 0x1000 | padding                                     |
# | 0x4000 | 0x0400 | first 0x48 bytes of blowfish data + padding |
# | 0x4400 | 0x0BF0 | next 0xBF0 bytes of blowfish data           |
# | 0x5000 | 0x1000 | `FF00FF00AA555AA55` magic then ...          |
# | 0x6000 | 0x4000 | sec block                                   |
# | 0xA000 | ...    | data block                                  |
AK2I_BLOWFISH_OFFSET = 0x0000
AK2I_HEADER_OFFSET = 0x2000
AK2I_1ST_BLOWFISH_OFFSET = 0x4000
AK2I_2ND_BLOWFISH_OFFSET = 0x4400
AK2I_SEC_OFFSET = 0x6000
AK2I_SEC_END_OFFSET = AK2I_SEC_OFFSET + 0x4000
AK2I_DATA_OFFSET = 0xA000

def extract_key_from_boot11(fn):
    out = ''
    with open(fn, 'rb') as r:
        boot11 = r.read()
        buf = boot11[0xB498:0xB498 + 0x1000]
        #return buf
        out += boot11[0xC878:0xC878 + 0x800]
        out += buf[0x800:]
        #out = boot11[0xA450:0xA450 + 0x1048]
    return out

def make_blowfish_data(src, dest):
    # TODO: dev device use another method
    # ref: 0xFFFF98E8
    bf = [0] * 0x1048
    with open(src, 'rb') as r:
        buf = map(lambda x: ord(x), r.read())
        if len(buf) != 0x1000:
            # TODO error
            return
        for x in xrange(0x48):
            idx = 0x100 * (x % 16) + buf[x]
            #print idx, hex(idx), hex(buf[x]), hex(buf[idx])
            bf[x] = buf[idx]
    bf = bf[:0x48] + buf

    with open(dest, 'wb') as w:
        for c in bf:
            w.write(chr(c))

def int_list_to_buf(buf):
    ret = ''
    for x in buf:
        ret += struct.pack('<I', x)
    return ret

def buf_to_int_list(buf):
    ret = []
    for x in xrange(0, len(buf), 4):
        ret.append(struct.unpack('<I', buf[x:x + 4])[0])
    return ret

def to_int(n):
    return n & 0xFFFFFFFF

def crypt_up(hash_table, buf, offset=0):
    x = buf[1 + offset]
    y = buf[0 + offset]
    for i in xrange(0x10):
        z = to_int(hash_table[i] ^ x)
        x = to_int(hash_table[0x012 + ((z >> 24) & 0xFF)])
        x = to_int(hash_table[0x112 + ((z >> 16) & 0xFF)] + x)
        x = to_int(hash_table[0x212 + ((z >> 8) & 0xFF)] ^ x)
        x = to_int(hash_table[0x312 + ((z >> 0) & 0xFF)] + x)
        x = to_int(y ^ x)
        y = z
    buf[0 + offset] = to_int(x ^ hash_table[0x10])
    buf[1 + offset] = to_int(y ^ hash_table[0x11])

def crypt_down(hash_table, buf, offset=0):
    x = buf[1 + offset]
    y = buf[0 + offset]
    for i in xrange(0x11, 1, -1):
        z = to_int(hash_table[i] ^ x)
        x = to_int(hash_table[0x012 + ((z >> 24) & 0xFF)])
        x = to_int(hash_table[0x112 + ((z >> 16) & 0xFF)] + x)
        x = to_int(hash_table[0x212 + ((z >> 8) & 0xFF)] ^ x)
        x = to_int(hash_table[0x312 + ((z >> 0) & 0xFF)] + x)
        x = to_int(y ^ x)
        y = z
    buf[0 + offset] = to_int(x ^ hash_table[0x1])
    buf[1 + offset] = to_int(y ^ hash_table[0x0])

def inject_firm(blowfish, firm, buf):
    # secure block order will shuffled using 0xFFFFE184
    # ref: 0xFFFF9B70
    secure = ''
    for x in xrange(4):
        off = AK2I_SEC_OFFSET + 0x1000 * x
        # 0x7E00: firm header offset
        secure += buf[off:off + 0xE00] + firm[:0x200]

    buf = buf_to_int_list(
        blowfish +
        buf[0x1048:AK2I_1ST_BLOWFISH_OFFSET] +
        blowfish[:0x48] +
        buf[AK2I_1ST_BLOWFISH_OFFSET + 0x48:AK2I_2ND_BLOWFISH_OFFSET] +
        blowfish[0x48:0x48 + 0xBF0] +
        buf[AK2I_2ND_BLOWFISH_OFFSET + 0xBF0:AK2I_SEC_OFFSET] +
        secure +
        buf[AK2I_SEC_END_OFFSET:AK2I_DATA_OFFSET] +
        firm[0x200:] +
        buf[AK2I_DATA_OFFSET + len(firm) - 0x200:]
    )
    return int_list_to_buf(buf)

if __name__ == '__main__':
    import sys

    if sys.argv[1] == 'e':
        out = extract_key_from_boot11(sys.argv[2])
        open(sys.argv[3], 'wb').write(out)
        raise SystemExit(0)
    if sys.argv[1] == 'd':
        make_blowfish_data(sys.argv[2], sys.argv[3])
        raise SystemExit(0)
    if sys.argv[1] == 'x':
        out = inject_firm(
            open(sys.argv[2], 'rb').read(),
            open(sys.argv[3], 'rb').read(),
            open(sys.argv[4], 'rb').read(),
        )
        open(sys.argv[5], 'wb').write(out)
        raise SystemExit(0)
