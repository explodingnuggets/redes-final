import asyncio


from ip.datagram import Datagram
from ip.packet import Packet
from tcp import tcp


class IPV4():
    REASSEMBLY_TIMEOUT = 3


    def __init__(self, eth):
        self.proto = tcp.TCP(5000, eth, self)
        self.datagrams = {}

        self.cur_id = 0


    @classmethod
    def _get_dgram_id(cls, packet):
        return (packet.src_addr, packet.ident)


    def get_packet_id(self):
        """
        Increments ipv4 packet counter, and returns the previous value
        """
        self.cur_id = (self.cur_id + 1) & 0xffff
        return (self.cur_id - 1) & 0xffff


    def _callback(self, dgram_id):
        dgram = self.datagrams[dgram_id]

        if dgram.callback is not None:
            dgram.callback.cancel()

        dgram.callback = asyncio.get_event_loop()\
                            .call_later(self.REASSEMBLY_TIMEOUT,
                                        self._try_dgram, dgram_id)


    def _reassemble(self, dgram_id):
        """
        Try to reassembly the fragmented packet, and if it's successful, sends
        the packet to the protocol instance
        """
        dgram = self.datagrams[dgram_id]

        if dgram.received_last:
            packet = dgram.reassemble()

            if packet is not None:
                print('Reassembled fragmented packet [Total of %d bytes]' %
                    len(packet))
                if dgram.proto == Packet.PROTO_TCP:
                    self.proto.check_packet(packet)


    def _try_dgram(self, dgram_id):
        """
        If timer expired, tries to reassemble and then removes the datagram from
        the dictionary
        """
        self._reassemble(dgram_id)

        self.datagrams.pop(dgram_id)


    def check_packet(self, raw_data):
        packet = Packet.parse(raw_data)

        dgram_id = self._get_dgram_id(packet)

        if packet.flags & Packet.FLAG_MF:
            if dgram_id in self.datagrams:
                dgram = self.datagrams[dgram_id]
            else:
                frag_sz = (packet.total_len - 4 * packet.ihl) / 8
                self.datagrams[dgram_id] = dgram = Datagram(packet.src_addr,
                                                            packet.dst_addr,
                                                            packet.proto, 
                                                            frag_sz)

            # Adds fragment and schedules reassemble
            dgram.push_fragment(packet.frag_offset, packet.payload)
            self._callback(dgram_id)

            self._reassemble(dgram_id)
        else:
            if dgram_id in self.datagrams:
                dgram = self.datagrams[dgram_id]
                dgram.push_fragment(packet.frag_offset, packet.payload)
                dgram.received_last = True

                self._callback(dgram_id)

                self._reassemble(dgram_id)
            else:
                if packet.proto == Packet.PROTO_TCP:
                    self.proto.check_packet(raw_data)
            
