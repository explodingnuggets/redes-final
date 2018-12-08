from tcp.connection import Connection
from tcp.packet import Packet


class TCP():
    connections = {}


    def __init__(self, port):
        self.port = port


    @classmethod
    def _connection_id(cls, packet):
        return (packet.src_addr, packet.src_prt, packet.dst_prt)


    def check_packet(self, raw_data):
        packet = Packet.parse(raw_data)

        if packet.dst_prt == self.port:
            conn_id = self._connection_id(packet)

            if conn_id not in self.connections:
                print('New connection [%s:%d] -> [%d]' % conn_id)
                self.connections[conn_id] = Connection.from_packet(packet)
            else:
                conn = self.connections[conn_id]
                conn.received_packet(packet)
            
