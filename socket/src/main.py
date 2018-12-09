# sudo iptables -I OUTPUT -p tcp --tcp-flags RST RST -j DROP
import asyncio
import socket


from ethernet import eth
from ip import ipv4
from tcp import tcp

ETH_P_ALL = 0x0003

SRC_MAC = '5c:93:a2:d2:ad:d1'

DST_MAC = 'a4:2b:b0:a5:40:5a'

IF_NAME = 'wlp2s0'


def raw_recv(fd, proto):
    raw_data = fd.recv(102400)

    proto.check_packet(raw_data)


if __name__ == '__main__':
    fd = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                       socket.htons(ETH_P_ALL))
    fd.bind((IF_NAME, 0))

    proto_eth = eth.Ethernet(SRC_MAC, DST_MAC, fd)

    loop = asyncio.get_event_loop()
    loop.add_reader(fd, raw_recv, fd, proto_eth)
    loop.run_forever()