import struct
from PyCRC.CRC16 import CRC16

# AK2I rom layout
# | offset  | size   | desc                                        |
# | 0x00000 | 0x2000 | lv2 blowfish data(0x1048 bytes + padding    |
# | 0x02000 | 0x1000 | nds header                                  |
# | 0x03000 | 0x1000 | padding                                     |
# | 0x04000 | 0x0400 | first 0x48 bytes of blowfish data + padding |
# | 0x04400 | 0x0BF0 | next 0xBF0 bytes of blowfish data           |
# | 0x05000 | 0x1000 | `FF00FF00AA555AA55` magic then ...          |
# | 0x06000 | 0x4000 | sec block                                   |
# | 0x0A000 | ...    | data block                                  |
# | 0x80000 | ...    | start fake rom parts, but b9 use this part  |
# | 0x80000 | 0x2000 | fake rom's lv2 blowfish data                |
# | 0x82000 | 0x1000 | nds header                                  |
# | 0x83600 | 0x48   | first 0x48 bytes of fake rom's blowfish     |
# | 0x84800 | 0x1000 | next 0xF78 bytes, but these not important   |
# | 0x86000 | 0x4000 | sec block                                   |
# | 0x8A000 | ...    | data block                                  |
AK2I_BLOWFISH_OFFSET = 0x80000
AK2I_HEADER_OFFSET = 0x82000
AK2I_1ST_BLOWFISH_OFFSET = 0x83600
AK2I_2ND_BLOWFISH_OFFSET = 0x84800
AK2I_SEC_OFFSET = 0x86000
AK2I_SEC_END_OFFSET = AK2I_SEC_OFFSET + 0x4000
AK2I_DATA_OFFSET = 0x8A000

def bswap32(n):
    return (
        ((n >> 24) & 0xFF) |
        (((n >> 16) & 0xFF) << 8) |
        (((n >> 8) & 0xFF) << 16) |
        ((n & 0xFF) << 24)
    )

def extract_keydata_from_boot11(b11_buf):
    # ref: 0xFFFF82D0 of b11
    return b11_buf[0xB498:0xB498 + 0x1000]

def make_blowfish_data(src_buf):
    # TODO: dev device use another method
    # ref: 0xFFFF98E8
    if len(src_buf) != 0x1000:
        # TODO error
        return
    bf = [0] * 0x1048
    buf = map(lambda x: ord(x), src_buf)
    for x in xrange(0x48):
        idx = 0x100 * (x % 16) + buf[x]
        bf[x] = buf[idx]
    bf = bf[:0x48] + buf
    return ''.join(map(lambda x: chr(x), bf))

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
    # zero fill will avoid encryption; gbatek.htm#dscartridgesecurearea
    # 0x7E00(0x9E00): firm header offset
    decrypted = '\x00' * 0xE00
    decrypted += firm[:0x200]
    secure = decrypted * 4
    secure_crc = CRC16(modbus_flag=True).calculate(secure)

    flags = [
        # normal card control register settings
        (
            0
            | (1 << 27)     # NTRCARD_CLK_SLOW
            #| (1 << 22)     # NTRCARD_SEC_CMD
            #| (0x18 << 16)  # NTRCARD_DELAY2(0x18)
            #| (1 << 14)     # NTRCARD_SEC_EN
            #| (1 << 13)     # NTRCARD_SEC_DAT
            | 0x18          # NTRCARD_DELAY1(0x18)
        ),
        # secure card control register settings
        (
            0
            | (1 << 27)     # NTRCARD_CLK_SLOW
            | (0x18 << 16)  # NTRCARD_DELAY2(0x18)
            | 0x8F8         # NTRCARD_DELAY1(0x8F8)
        ),
        #0, # icon banner offset
        struct.unpack(
            '<I',
            buf[AK2I_HEADER_OFFSET + 0x68:AK2I_HEADER_OFFSET + 0x68 + 4]
        )[0],
        #0, # low: secure area crc, high: secure transfer timeout
        (0x0D7E << 16) | secure_crc,
    ]

    firm_sections = buf_to_int_list(firm[0x200:])
    firm_sections = int_list_to_buf(firm_sections)

    header = (
        buf[AK2I_HEADER_OFFSET:AK2I_HEADER_OFFSET + 0x60] +
        int_list_to_buf(flags) +
        buf[AK2I_HEADER_OFFSET + 0x70:AK2I_HEADER_OFFSET + 0x15E]
    )
    header += struct.pack('<H', CRC16(modbus_flag=True).calculate(header))

    buf = buf_to_int_list(
        buf[:AK2I_BLOWFISH_OFFSET] +
        blowfish +
        buf[AK2I_BLOWFISH_OFFSET + 0x1048:AK2I_HEADER_OFFSET] +
        header +
        buf[AK2I_HEADER_OFFSET + 0x160:AK2I_1ST_BLOWFISH_OFFSET] +
        buf[:0x48] +
        buf[AK2I_1ST_BLOWFISH_OFFSET + 0x48:AK2I_2ND_BLOWFISH_OFFSET] +
        buf[0x48:0x48 + 0xBF0] +
        buf[AK2I_2ND_BLOWFISH_OFFSET + 0xBF0:AK2I_SEC_OFFSET] +
        secure +
        buf[AK2I_SEC_END_OFFSET:AK2I_DATA_OFFSET] +
        firm_sections +
        buf[AK2I_DATA_OFFSET + len(firm) - 0x200:]
    )
    return int_list_to_buf(buf)

def main():
    import argparse

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()
    blowfish_parser = subparsers.add_parser(
        'blowfish',
        description='Extract blowfish.bin from boot11'
    )
    blowfish_parser.set_defaults(mode='blowfish')
    blowfish_parser.add_argument('boot11_file', metavar='boot11.bin')
    blowfish_parser.add_argument('--out', default='blowfish.bin',
                                 help='out filename (default: blowfish.bin)')
    inject_parser = subparsers.add_parser(
        'inject',
        description='Inject boot9strap to ak2i flash file'
    )
    inject_parser.set_defaults(mode='inject')
    inject_parser.add_argument('blowfish_file', metavar='blowfish.bin')
    inject_parser.add_argument('boot9strap_file', metavar='boot9strap_ntr.bin')
    inject_parser.add_argument('ak2i_flash_file', metavar='ak2i_flash.bin')
    inject_parser.add_argument('--out', default='ak2i_patch.bin',
                               help='out filename (default: ak2i_patch.bin)')
    args = parser.parse_args()
    #print args

    if args.mode == 'blowfish':
        with open(args.boot11_file, 'rb') as b11:
            initial_keydata = extract_keydata_from_boot11(b11.read())
            out = make_blowfish_data(initial_keydata)
            with open(args.out, 'wb') as w:
                w.write(out)
            raise SystemExit(0)
    if args.mode == 'inject':
        with open(args.blowfish_file, 'rb') as bf, \
            open(args.boot9strap_file, 'rb') as firm, \
            open(args.ak2i_flash_file, 'rb') as flash:
            out = inject_firm(bf.read(), firm.read(), flash.read())
            with open(args.out, 'wb') as w:
                w.write(out)
            raise SystemExit(0)
    # something wrong
    raise SystemExit(1)

if __name__ == '__main__':
    main()
