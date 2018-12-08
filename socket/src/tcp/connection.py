import asyncio
import random
import socket
import time


from tcp.packet import Packet


class Connection():
    CONNECTING = 0
    CONNECTED = 1
    DISCONNECTING = 2
    DISCONNECTED = 3

    MSS = 1440

    HTTP_DATA = b'HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n'\
                    + b'TCP Testing'*1000

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

        self.sent_time = None
        self.rto = 3
        self.srtt = None
        self.rttvar = None

        self.cwnd = self.MSS
        self.rwnd = None
        self.sshtresh = float("inf")

        self.callback = asyncio.get_event_loop()\
                            .call_soon(self._handshake_synack)

    
    @classmethod
    def from_packet(cls, packet):
        return cls(packet.dst_addr, packet.dst_prt, packet.src_addr,
                   packet.src_prt, packet.seq_no)


    def _cancel_callback(self):
        self.callback.cancel()
        self.callback = None


    def _call_send_loop(self):
        self.seq_no += self._sent_size()
        self.send_queue = self.send_queue[self._sent_size():]

        if len(self.send_queue) > 0:
            self.callback = asyncio.get_event_loop()\
                                .call_soon(self._send_next_queue)


    def _set_time(self):
        if self.sent_time is None:
            self.sent_time = time.time()
        else:
            self.rto *= 2
            self.sent_time = False


    def _set_cwnd(self):
        if self.sent_time is not None and self.sent_time != False:
            if self.cwnd < self.sshtresh:
                self.cwnd += min(self._sent_size(), self.MSS)
        else:
            self.sshtresh = max(self.cwnd/2, 2*self.MSS)
            self.cwnd = self.MSS


    def _calc_rto(self):
        # 1 <= RTO <= 60
        return max(min(self.srtt + max(3, 4 * self.rttvar), 60), 1)


    def _set_rtt(self):
        if self.sent_time is not None and self.sent_time != False:
            rtt = time.time() - self.sent_time

            if self.srtt is None and self.rttvar is None:
                self.srtt = rtt
                self.rttvar = rtt/2
            else:
                self.rttvar = (3/4) * self.rttvar + (1/4) * abs(self.srtt - rtt)
                self.srtt = (7/8) * self.srtt + (1/8) * rtt

            self.rto = self._calc_rto()

        self.sent_time = None


    def _conn_info_str(self):
        return '[%s:%d] -> [%d]' % (self.dst_addr, self.dst_prt, self.src_prt)


    def _window_size(self):
        bufcap = self.buflen - len(self.buffer)
        return bufcap if bufcap > 0 else 0


    def _sent_size(self):
        return min(len(self.send_queue), self.cwnd, self.rwnd)


    def _send_to(self, packet):
        self.fd.sendto(packet.to_bytes(), (self.dst_addr, self.dst_prt))


    def _push_buffer(self, data):
        if self._window_size() - len(data) >= 0:
            self.buffer += data
            self.ack_no += len(data)

            return True

        return False


    def _pack_packet(self, flags=Packet.FLAG_ACK, data=b''):
        return Packet(self.src_addr, self.src_prt, self.dst_addr, self.dst_prt,
                      self.seq_no, self.ack_no, (5<<12)|flags,
                      self._window_size(), 0, 0, data)


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
        data = self.send_queue[:self._sent_size()]

        print(self.cwnd)

        for i in range(0, len(data), self.MSS):
            packet = self._pack_packet(data=data[i:i+self.MSS])
            packet.seq_no += i

            self._send_to(packet)

        self._set_time()

        self.callback = asyncio.get_event_loop()\
                            .call_later(self.rto, self._send_next_queue)


    def close(self):
        self._send_finack()

        self.status = self.DISCONNECTING


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
        self.rwnd = packet.win_size

        """
        Finishes connection handshake, enabling this connection to receive data
        """
        if self.status == self.CONNECTING:
            if packet.flags & Packet.FLAG_ACK:
                print('Finished connection handshake', self._conn_info_str())

                self.status = self.CONNECTED
                self.ack_no += 1
                self.seq_no += 1
                self._cancel_callback()

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

                    self.send(self.HTTP_DATA)
            elif self.seq_no + self._sent_size() == packet.ack_no:
                print('Received ACK', self._conn_info_str())
                self._cancel_callback()

                self._call_send_loop()
                self._set_cwnd()
                self._set_rtt()

                if len(self.send_queue) == 0:
                    self.close()
        elif self.status == self.DISCONNECTING:
            if packet.flags & Packet.FLAG_FIN:
                self._send_ack()
                self.status = self.DISCONNECTED
