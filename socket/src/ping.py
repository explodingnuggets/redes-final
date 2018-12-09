import asyncio
import socket
import struct

ETH_P_IP = 0x0800

DEST_ADDR = '192.168.1.1'

def calc_checksum(segment):
    if len(segment) % 2 == 1:
        segment += b'\x00'
    checksum = 0
    for i in range(0, len(segment), 2):
        x, = struct.unpack('!H', segment[i:i+2])
        checksum += x
        while checksum > 0xffff:
            checksum = (checksum & 0xffff) + 1
    checksum = ~checksum
    return checksum & 0xffff


def send_ping(fd):
    print('Enviango ping')

    msg = bytearray(b"\x08\x00\x00\x00" + 5000*b"\xba\xdc\x0f\xfe")
    msg[2:4] = struct.pack('!H', calc_checksum(msg))
    fd.sendto(msg, (DEST_ADDR, 0))

    asyncio.get_event_loop().call_later(1, send_ping, fd)


sock_send = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

loop = asyncio.get_event_loop()
loop.call_later(1, send_ping, sock_send)
loop.run_forever()