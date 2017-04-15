import argparse
import os
import socket
import select
from utils import icmp_requests as requests, answer_formatting as answer_format
from utils import ip_addr_is_private
from whoisUtility import algorithm_on_searching
from struct import unpack, pack
import sys

protocol_name = "icmp"
ASTERISK = "*"

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
        return pack('bbHHh', self.type, self.code,
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
    parser.add_argument("destination", help="routing address, numeric value or dns name")
    parser.add_argument("-t", "--ttl", help="custom ttl bound", default=25, type=int)

    return parser


def prepare_socket(ttl):
    query_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                 socket.getprotobyname(protocol_name))

    query_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

    return query_socket


def traceroute(dest, max_hops):
    try:
        end_point = socket.gethostbyname(dest)
        step = 1
        print(step, socket.gethostbyname("localhost"))
        print('local\r\n')
        while step < max_hops:

            sending_socket = prepare_socket(step)
            packet = Packet(id_f=os.getpid() & 0xFFFF).form_packet(os.getpid() & 0xFFFF)

            # sending our packet
            sending_socket.sendto(packet, (end_point, 1))
            current_ip, is_reached = receive_packet_timeout(sending_socket)
            if current_ip and not ip_addr_is_private(current_ip[0]):
                info = answer_format(algorithm_on_searching(current_ip[0]))
                print(step, current_ip[0])
                print(info)
            elif not current_ip:
                print(step, ASTERISK)
                print('\r\n')
            if is_reached:
                print('traceroute is completed')
                sending_socket.close()
                break
            step += 1
            sending_socket.close()

    except socket.gaierror as s_error:
        print(s_error.args)


def receive_packet_timeout(sock, delay=0.5):
    reading, _, _ = select.select([sock], [], [], delay)
    if len(reading) == 0:
        return None, False
    icmp_message, addr = sock.recvfrom(1024)
    icmp_header = icmp_message[20:28]

    icmpType, code, checksum, packetID, sequence = unpack('bbHHh', icmp_header)
    if icmpType == requests['ttl_expired'] and code == 0:
        return addr, False
    if icmpType == requests['echo reply'] and code == 0:
        return addr, True
    return None, False


def host_value(host):
    try:
        val = socket.gethostbyname(host)
        return val
    except socket.gaierror:
        try:
            val = socket.gethostbyaddr(host)
            return val
        except socket.gaierror:
            print("{} is invalid".format(str(host)))
            sys.exit()

if __name__ == "__main__":
    try:
        args = get_arg_parser().parse_args()
        host = host_value(args.destination)
        traceroute(host, args.ttl)
    except (OSError, socket.error) as e:
        if isinstance(e, OSError):
            print('Seem like not enough administrative permissions, below the error')
            print(e)
        else:
            print('Some troubleshooting with network')
