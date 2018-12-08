from ip.datagram import Datagram
from ip.packet import Packet


class IPV4():
    def __init__(self, proto):
        self.proto = proto
        self.datagrams = {}


    @classmethod
    def _get_dgram_id(cls, packet):
        return (packet.src_addr, packet.ident)


    def check_packet(self, raw_data):
        packet = Packet.parse(raw_data)

        if packet.proto == Packet.PROTO_TCP:
            dgram_id = self._get_dgram_id(packet)

            print(packet.flags, packet.frag_offset)

            if packet.flags & Packet.FLAG_MF:  
                if dgram_id in self.datagrams:
                    dgram = self.datagrams[dgram_id]
                else:
                    frag_sz = (packet.total_len - 4 * packet.ihl) / 8
                    dgram = Datagram(frag_sz)

                dgram.push_fragment(packet.frag_offset, packet.payload)

                print('hi')
            else:
                if dgram_id in self.datagrams:
                    pass
                else:
                    self.proto.check_packet(raw_data)
            
