import argparse
import socket
import sys
import time

from utils import icmp_requests as requests
import struct

protocol_name = "icmp"


class Packet:
    def __init__(self, version="bbHHh", m_type=requests['echo request'],
                 checksum=0, id_f=0, sequence=1):
        self.version = version
        self.type = m_type
        self.checksum = checksum
        self.id = id_f
        self.sequence = sequence

    def _bin_packet(self):
        """forming a raw packet with 0 checksum,
        just for further computation of checksum based on prepared binary data"""
        return struct.pack(self.version, self.type, self.checksum, self.id, self.sequence)

    @classmethod
    def check_sum_forming(cls, word):
        word = bytearray(word)
        csum = 0
        countTo = (len(word) // 2) * 2

        for count in range(0, countTo, 2):
            thisVal = word[count + 1] * 256 + word[count]
            csum += thisVal
            csum &= 0xffffffff

        if countTo < len(word):
            csum = csum + word[-1]
            csum &= 0xffffffff

        csum = (csum >> 16) + (csum & 0xffff)
        csum += csum >> 16
        answer = ~csum
        answer &= 0xffff
        answer = answer >> 8 | (answer << 8 & 0xff00)
        return answer

    def bin_packet(self, time_id):
        raw_header = self._bin_packet()
        word = struct.pack('d', time.time())  # 8 byte
        pack_checksum = self.check_sum_forming(raw_header + word)  # 8 byte

        packet = Packet(checksum=pack_checksum, id_f=time_id)
        return packet._bin_packet()


def get_arg_parser():
    parser = argparse.ArgumentParser(description="traceroute utility")
    parser.add_argument("destination", help="routing address")
    parser.add_argument("-t", "--ttl", help="custom ttl bound", default=25, type=int)

    return parser

def traceroute(parser):
    try:
        end_point = socket.gethostbyname(parser.destination)
    except socket.gaierror as s_error:
        print(s_error.args)
        pass
if __name__ == "__main__":
    arg_parser = get_arg_parser().parse_args()
    print(arg_parser)
    # traceroute(arg_parser.parse_args())
    # print(socket.gethostbyname("dubrovin"))
    # print(socket.gethostbyname_ex("yandex.ru"))
    # print(socket.gethostbyaddr('yandex.ru'))
    # print(socket.getprotobyname(protocol_name))


