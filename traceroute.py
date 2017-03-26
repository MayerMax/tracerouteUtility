import argparse
import os
import random
import socket
import sys
import time

import select

from utils import icmp_requests as requests
import struct

protocol_name = "icmp"


class Packet:
    def __init__(self, m_type=requests['echo request'], code=0,
                 checksum=0, id_f=0, sequence=1):
        self.type = m_type
        self.code = code
        self.checksum = checksum
        self.id = id_f
        self.sequence = sequence

    def _bin_packet(self):
        """forming a raw packet with 0 checksum,
        just for further computation of checksum based on prepared binary data"""
        return struct.pack('bbHHh', self.type, self.code,
                           self.checksum, self.id, self.sequence)

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

    def form_packet(self, s_id):
        raw_header = self._bin_packet()
        data = []
        value = 0x42
        for i in range(55):
            data += [value]
        data = bytes(data)

        check_sum = self.check_sum_forming(raw_header + data)
        check_sum = socket.htons(check_sum)

        header = Packet(checksum=check_sum, id_f=s_id)._bin_packet()
        send_packet = header + data
        return send_packet


def get_arg_parser():
    parser = argparse.ArgumentParser(description="traceroute utility")
    parser.add_argument("destination", help="routing address")
    parser.add_argument("-t", "--ttl", help="custom ttl bound", default=25, type=int)

    return parser


def prepare_socket(ttl):
    query_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                 socket.getprotobyname(protocol_name))

    query_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

    # query_socket.settimeout() for further progress
    return query_socket


def traceroute(dest, max_hops):
    try:
        end_point = socket.gethostbyname(dest)
        step = 1
        while step < max_hops:

            sending_socket = prepare_socket(step)
            packet = Packet(id_f=os.getpid() & 0xFFFF).form_packet(os.getpid() & 0xFFFF)

            # sending our packet
            sending_socket.sendto(packet, (end_point, 1))
            info = receive_packet_timeout(sending_socket, timeout=1)

            print(info)
            step += 1
            sending_socket.close()

    except socket.gaierror as s_error:
        print(s_error.args)


def receive_packet_timeout(sock, timeout=1):
    start_time = time.time()
    while True:
        reading, _, _ = select.select([sock], [], [], 4)
        if len(reading) == 0:
            return
        icmp_message, addr = sock.recvfrom(1024)
        icmp_header = icmp_message[20:28]

        icmpType, code, checksum, packetID, sequence = struct.unpack('bbHHh', icmp_header)
        if icmpType == requests['ttl_expired'] and code == 0:
            return addr, None
        if icmpType == requests['echo reply'] and code == 0:
            return addr, 1


if __name__ == "__main__":
    # arg_parser = get_arg_parser().parse_args()
    traceroute("google.com", 20)

