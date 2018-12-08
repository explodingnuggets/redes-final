import asyncio
import random
import socket


from tcp.packet import Packet


class Connection():
    CONNECTING = 0
    CONNECTED = 1
    DISCONNECTING = 2
    DISCONNECTED = 3

    MSS = 1440


    def __init__(self, src_addr, src_prt, dst_addr, dst_prt, ack_no):
        self.status = self.CONNECTING
        self.fd = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                socket.IPPROTO_TCP)
        
        self.buffer = bytes()
        self.buflen = 4096

        self.send_queue = bytes()

        self.src_addr = src_addr
        self.src_prt = src_prt
        self.dst_addr = src_addr
        self.dst_prt = dst_prt
        self.seq_no = random.randint(0, 0xffffffff)
        self.ack_no = ack_no

        self.rto = 3

        self.cwnd = self.MSS

        self.callback = asyncio.get_event_loop()\
                            .call_soon(self._handshake_synack)

    
    @classmethod
    def from_packet(cls, packet):
        return cls(packet.dst_addr, packet.dst_prt, packet.src_addr,
                   packet.src_prt, packet.seq_no)


    def _conn_info_str(self):
        return '[%s:%d] -> [%d]' % (self.dst_addr, self.dst_prt, self.src_prt)


    def _window_size(self):
        bufcap = self.buflen - len(self.buffer)
        return bufcap if bufcap > 0 else 0


    def _send_to(self, packet):
        self.fd.sendto(packet.to_bytes(), (self.dst_addr, self.dst_prt))


    def _push_buffer(self, data):
        if self._window_size() - len(data) >= 0:
            self.buffer += data
            self.ack_no += len(data)

            return True

        return False


    def _pack_packet(self, flags=Packet.FLAG_ACK, data=b''):
        seq_no = self.seq_no + len(data)

        return Packet(self.src_addr, self.src_prt, self.dst_addr, self.dst_prt,
                      seq_no, self.ack_no, (5<<12)|flags, self._window_size(),
                      0, 0, data)


    def _send_ack(self, ack_no=None):
        packet = self._pack_packet()

        if ack_no is not None:
            packet.ack_no = ack_no

        self._send_to(packet)

        print(self.buffer)


    def _send_finack(self):
        packet = self._pack_packet(flags=(Packet.FLAG_ACK|Packet.FLAG_FIN))

        self._send_to(packet)


    def _handshake_synack(self):
        packet = self._pack_packet(flags=(Packet.FLAG_SYN|Packet.FLAG_ACK))
        packet.ack_no += 1

        self._send_to(packet)

        self.callback = asyncio.get_event_loop().call_later(self.rto,
            self._handshake_synack)


    def _send_next_queue(self):
        data = self.send_queue[:self.cwnd]
        packet = self._pack_packet(data=data)

        self._send_to(packet)


    def send(self, data):
        """
        Adds data to the end of the send_queue, and if there's no current
        callback for sending data, start one
        If the the connection is pending or closed, raise a OSError exception
        """
        if self.status == self.CONNECTED:
            self.send_queue += data

            if self.callback is None:
                self.callback = asyncio.get_event_loop()\
                                    .call_soon(self._send_next_queue)

        elif self.status == self.CONNECTING:
            raise OSError('Connection pending')
        else:
            raise OSError('Connection closed')    


    def received_packet(self, packet):
        """
        Finishes connection handshake, enabling this connection to receive data
        """
        if self.status == self.CONNECTING:
            if packet.flags & Packet.FLAG_ACK:
                print('Finished connection handshake', self._conn_info_str())

                self.status = self.CONNECTED
                self.ack_no += 1
                self.seq_no += 1
                self.callback.cancel()

        elif self.status == self.CONNECTED:
            """
            Checks if client is requesting an end of connectio, and if it's,
            send a FIN ACK packet

            If it's not a FIN packet and connection seq_no is equal to packet
            ack_no, this packet is not an ACK packet, so it has new data. We
            could check flag PSH, but there's no guarantee of this behaviour
            from all clients
            """
            if packet.flags & Packet.FLAG_FIN:
                print('Closing connection', self._conn_info_str())
                # TODO: Send FIN ACK packet

                self.status = self.DISCONNECTING
            elif self.seq_no == packet.ack_no:
                """
                If connection ack_no is greater than packet seq_no, just try to
                retransmit ACK, else check if buffer has space for the payload
                and if it has, append payload to buffer, increment connection
                ack_no and send ACK
                """
                if self.ack_no > packet.seq_no:
                    print('Received retransmission', self._conn_info_str())
                    self._send_ack(ack_no=packet.seq_no+len(packet.data))

                elif self._push_buffer(packet.data):
                    print('Received new packet', self._conn_info_str())
                    self._send_ack()            
