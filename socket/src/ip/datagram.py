import struct


class Datagram():
    def __init__(self, src_addr, dst_addr, proto, fragment_sz):
        self.src_addr = src_addr
        self.dst_addr = dst_addr
        self.proto = proto

        self.fragments = {}
        self.fragment_sz = int(fragment_sz)
        self.received_last = False
        self.callback = None


    @classmethod
    def _str2addr(cls, addr):
        return bytes(int(x) for x in addr.split('.'))


    def _pack_partial_header(self):
        return b'\x45' + b'\x00'*11 + self._str2addr(self.src_addr)\
                + self._str2addr(self.dst_addr)

    
    def push_fragment(self, frag_off, data):
        self.fragments[frag_off] = data


    def reassemble(self):
        if self.received_last:
            data = b''
            failed = False
            last_offset = sorted(self.fragments.keys())[-1]

            for i in range(0, last_offset+1, self.fragment_sz):
                if i in self.fragments:
                    data += self.fragments[i]
                else:
                    failed = True

            if not failed:
                return self._pack_partial_header() + data
