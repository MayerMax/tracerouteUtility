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

regions_dict = dict(RIPE="whois.ripe.net", ARIN="whois.arin.net",
                    LACNIC="whois.lacnic.net", APNIC="whois.apnic.net",
                    AFRINIC="whois.afrinic.net")


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
    if len(arin_dict.keys()) == 0:
        return "Undefined", None

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


def pattern_function(request, to_arin=False):
    information = dict()
    pattern = re.compile(r"([a-zA-z\-'\. ]+):\s+([a-zA-z1-9\-'\. ]+)")
    request = request.split("\n")
    for line in request:
        matcher = pattern.match(line)
        if matcher:
            information[matcher.group(1)] = matcher.group(2)

    if to_arin:
        return arin_describer(information)

    else:
        return information


def ask_neighbour(word_descr, reply_dict, target):
    return base_parsing(
        pattern_function(
            receive_who_is(
                target, regions_dict[reply_dict]
            )
        ), target=target
    )


def throw_info_back(word_descr, reply_dict, target):
    return reply_dict


def polling_others(word_descr, reply_dict, target):
    for regisry in regions_dict:
        if regisry != 'ARIN':
            expected_res = base_parsing(
                pattern_function
                    (
                    receive_who_is
                    (target, regions_dict[regisry])
                )
            )
            if len(expected_res.keys()) != 0:
                return expected_res
    return dict()


# clarify info about the right address
def base_parsing(zone_info, target=None):
    info = dict()
    if len(zone_info.keys()) == 0 and target:
        return polling_others(None, None, target)
    list_of_interest = ['country', 'origin', 'netname', 'aut-num', 'nic-hdl']
    for q in list_of_interest:
        if q in zone_info.keys():
            info[q] = zone_info[q]
    return info


state_dict = {
    "Neighbour": ask_neighbour,
    "Allocated": throw_info_back,
    "Undefined": polling_others
}


def algorithm_on_searching(target):
    # first ask arin to figure out if it has any info about address
    state, info = pattern_function(
        receive_who_is(target,
                       DEFAULT_WHOIS_INFROMER),
        to_arin=True)
    print(state)
    return state_dict[state](state, info, target)


# yandex - 77.88.55.70
# google com - 209.85.233.100
# facebook - 31.13.92.36
# print(socket.gethostbyname("gouvernement.fr"))
# brazil gov - 189.9.39.243
# japan gov -202.32.211.142
# nigeria gov - 41.222.211.231
# france gov - 185.11.125.117
print(algorithm_on_searching("202.32.211.142"))
