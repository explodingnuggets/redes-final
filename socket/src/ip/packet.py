import struct


class Packet():
    FLAG_MF = 1 << 0
    FLAG_DF = 1 << 1

    PROTO_TCP = 0x06

    def __init__(self, version, ihl, dscp, ecn, total_len, ident, flags,
                 frag_offset, ttl, proto, checksum, src_addr, dst_addr,
                 payload):
        self.version = version
        self.ihl = ihl
        self.dscp = dscp
        self.ecn = ecn
        self.total_len = total_len
        self.ident = ident
        self.flags = flags
        self.frag_offset = frag_offset
        self.ttl = ttl
        self.proto = proto
        self.checksum = checksum
        self.src_addr = src_addr
        self.dst_addr = dst_addr
        self.payload = payload


    @classmethod
    def _addr2str(cls, addr):
        return '%d.%d.%d.%d' % tuple(int(x) for x in addr)


    @classmethod
    def parse(cls, raw_data):
        version = raw_data[0] >> 4
        ihl = raw_data[0] & 0xf
        dscp = raw_data[1] >> 2
        ecn = raw_data[1] & 0x3
        total_len, ident = struct.unpack('!HH', raw_data[2:6])
        flags = raw_data[6] >> 5
        frag_offset = struct.unpack('!H', raw_data[6:8])[0] & 0x1fff
        ttl = raw_data[8]
        proto = raw_data[9]
        checksum, = struct.unpack('!H', raw_data[10:12])
        src_addr = cls._addr2str(raw_data[12:16])
        dst_addr = cls._addr2str(raw_data[16:20])
        payload = raw_data[4*ihl:]

        return Packet(version, ihl, dscp, ecn, total_len, ident, flags,
                      frag_offset, ttl, proto, checksum, src_addr, dst_addr,
                      payload)
