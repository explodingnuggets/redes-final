import struct


from ip import ipv4


class Ethernet():
    ETH_P_IP = 0x0800

    def __init__(self, src_mac, dst_mac, fd):
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.proto = ipv4.IPV4(self)
        self.fd = fd


    @classmethod
    def _addr2str(cls, addr):
        return '%s:%s:%s:%s:%s:%s' % tuple('{:02x}'.format(x) for x in addr)


    @classmethod
    def _str2addr(cls, addr):
        return bytes(int('0x' + x, 16) for x in addr.split(':'))


    def send(self, raw_data, proto):
        header = self._str2addr(self.dst_mac) + self._str2addr(self.src_mac)\
                    + struct.pack('!H', proto)
        self.fd.send(header + raw_data)


    def check_packet(self, raw_packet):
        src_mac = self._addr2str(raw_packet[0:6])
        proto, = struct.unpack('!H', raw_packet[12:14])

        if src_mac == self.src_mac and proto == self.ETH_P_IP:
            #print('Received Ethernet packet')
            self.proto.check_packet(raw_packet[14:])
