# sudo iptables -I OUTPUT -p tcp --tcp-flags RST RST -j DROP
import asyncio
import socket


from ip import ipv4
from tcp import tcp


ETH_P_IP = 0x0800


def raw_recv(fd, proto):
    raw_data = fd.recv(102400)

    proto.check_packet(raw_data)


if __name__ == '__main__':
    fd = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM,
                       socket.htons(ETH_P_IP))
    proto_tcp = tcp.TCP(5000)
    proto_ip = ipv4.IPV4(proto_tcp)

    loop = asyncio.get_event_loop()
    loop.add_reader(fd, raw_recv, fd, proto_ip)
    loop.run_forever()