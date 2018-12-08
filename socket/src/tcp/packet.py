import struct


class Packet():
    FLAG_FIN = 1 << 0
    FLAG_SYN = 1 << 1
    FLAG_RST = 1 << 2
    FLAG_ACK = 1 << 4


    def __init__(self, src_addr, src_prt, dst_addr, dst_prt, seq_no, ack_no,
                 flags, win_size, checksum, urg_ptr, data=b''):
        self.src_addr = src_addr
        self.src_prt = src_prt
        self.dst_addr = dst_addr
        self.dst_prt = dst_prt
        self.seq_no = seq_no
        self.ack_no = ack_no
        self.flags = flags
        self.win_size = win_size
        self.checksum = checksum
        self.urg_ptr = urg_ptr
        self.data = data


    @classmethod
    def _addr2str(cls, addr):
        return '%d.%d.%d.%d' % tuple(int(x) for x in addr)


    @classmethod
    def _str2addr(cls, addr):
        return bytes(int(x) for x in addr.split('.'))


    @classmethod
    def _parse_ipv4_header(cls, packet):
        """
        Parse IPV4 header, and returns source IP, destination IP and payload
        Also asserts if it is a IPV4 header, and not a IPV6 one
        """
        version = packet[0] >> 4
        ihl = packet[0] & 0xf
        assert version == 4
        src_ip = cls._addr2str(packet[12:16])
        dst_ip = cls._addr2str(packet[16:20])
        data = packet[ihl*4:]

        return (src_ip, dst_ip, data)


    @classmethod
    def _calc_checksum(cls, segment):
        """
        Calculate the checksum from a TCP segment, aligning if the segment
        length is not multiple of two
        """
        if len(segment) % 2 == 1:
            segment += b'\x00'
        checksum = 0
        for i in range(0, len(segment), 2):
            x, = struct.unpack('!H', segment[i:i+2])
            checksum += x
            while checksum > 0xffff:
                checksum = (checksum & 0xffff) + 1
        checksum = ~checksum

        return checksum & 0xffff


    def _fix_checksum(self, segment):
        pseudohdr = self._str2addr(self.src_addr) + \
            self._str2addr(self.dst_addr) + \
            struct.pack('!HH', 0x0006, len(segment))

        seg = bytearray(segment)
        self.checksum = self._calc_checksum(pseudohdr + segment)


    @classmethod
    def _parse_tcp_header(cls, packet):
        return struct.unpack('!HHIIHHHH', packet[:20])


    @classmethod
    def parse(cls, packet):
        """
        Parses a raw bytes tcp packet, returning a Packet object with all the
        information parsed
        """
        src_addr, dst_addr, data = cls._parse_ipv4_header(packet)
        src_prt, dst_prt, seq_no, ack_no, flags, win_size, checksum, urg_ptr = (
            cls._parse_tcp_header(data))

        data_off = flags >> 12
        data = data[data_off*4:]
        flags = flags & 0x1ff

        return cls(src_addr, src_prt, dst_addr, dst_prt, seq_no, ack_no, flags,
                   win_size, checksum, urg_ptr, data)


    def _pack_bytes(self):
        return struct.pack('!HHIIHHHH', self.src_prt, self.dst_prt, self.seq_no,
                           self.ack_no, (5<<12)|self.flags, self.win_size,
                           self.checksum, self.urg_ptr) + self.data

    
    def to_bytes(self):
        self.checksum = 0
        self._fix_checksum(self._pack_bytes())

        return self._pack_bytes()
