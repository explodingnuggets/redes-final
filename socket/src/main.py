# sudo iptables -I OUTPUT -p tcp --tcp-flags RST RST -j DROP
import asyncio
import socket


from tcp import tcp


def raw_recv(fd, proto):
    raw_data = fd.recv(102400)

    proto.check_packet(raw_data)


if __name__ == '__main__':
    fd = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    proto = tcp.TCP(5000)

    loop = asyncio.get_event_loop()
    loop.add_reader(fd, raw_recv, fd, proto)
    loop.run_forever()