import select
import socket
import re

# all queries stars with this server
DEFAULT_WHOIS_INFROMER = 'whois.arin.net'

# tcp constants for an answer awaiting
SOCKET_CONNECT_TIMEOUT = 1
SOCKET_POLLING_PERIOD = 0.25

# receive size
BUFFER_SIZE = 4 * 1024

WHOIS_PORT = 43

BREAK = "\r\n"

regions_dict = {
    "RIPE": "whois.ripe.net",
    "ARIN": "whois.arin.net",
    "LACNIC" : "whois.lacnic.net",
    "APNIC" : "whois.apnic.net",
    "AFRINIC" : "whois.afrinic.net"
}

def receive_info_from_socket(sock):
    info = b''
    while select.select([sock], [], [], SOCKET_POLLING_PERIOD)[0]:
        try:
            data = sock.recv(BUFFER_SIZE)
            if len(data) == 0:
                break
            info += data
        except socket.error:
            return info
    return info


def receive_who_is(aim, server_addr):
    with socket.socket() as sock:
        sock.settimeout(SOCKET_CONNECT_TIMEOUT)
        sock.connect((server_addr, WHOIS_PORT))
        sock.setblocking(0)

        res = receive_info_from_socket(sock).decode()
        sock.sendall((aim + BREAK).encode())

        res += receive_info_from_socket(sock).decode()

    return res


def arin_describer(arin_dict):
    if arin_dict["OrgId"] in regions_dict.keys() and arin_dict["OrgId"] != "ARIN":
        return "Neighbour", arin_dict["OrgId"]

    list_of_interest = ["Country", 'OriginAS', "NetName"]
    got_info = dict()
    for q in list_of_interest:
        if q in arin_dict.keys():
            got_info[q] = arin_dict[q]
    if got_info.keys():
        return "Allocated", got_info
    return "Undefined", None


def pattern_function(request):
    info = dict()
    pattern = re.compile('([a-zA-z]+):\s+([a-zA-z1-9]+)')
    request = request.split("\n")
    for line in request:
        matcher = pattern.match(line)
        if matcher:
            info[matcher.group(1)] = matcher.group(2)
    return arin_describer(info)


def algorithm_on_searching(target):
    # first ask arin to figure out if it has any info about address
    res = receive_who_is(target, DEFAULT_WHOIS_INFROMER)
    # print(res)
    state, info = pattern_function(res)
    if state == "Neighbour":
        print(state, info)
        pass # put here logic to ask others
    if state == "Allocated":
        print(info)
        return info
    if state == "Undefined":
        return None


# yandex - 77.88.55.70
# google com - 209.85.233.100
# facebook - 31.13.92.36
# print(socket.gethostbyname("www.japan.go.jp"))
# brazil gov - 189.9.39.243
# japan gov -202.32.211.142
algorithm_on_searching("202.32.211.142")


