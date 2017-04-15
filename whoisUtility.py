import select
import socket
import re
from collections import OrderedDict

# all queries stars with this server
DEFAULT_WHOIS_INFROMER = 'whois.arin.net'

# tcp constants for an answer awaiting
SOCKET_CONNECT_TIMEOUT = 1
SOCKET_POLLING_PERIOD = 0.25

# receive size
BUFFER_SIZE = 4 * 1024

WHOIS_PORT = 43

BREAK = "\r\n"

regions_dict = OrderedDict(
    IANA='whois.iana.org',
    RIPE="whois.ripe.net",
    APNIC="whois.apnic.net",
    AFRINIC="whois.afrinic.net",
    LACNIC="whois.lacnic.net",
)

reserved_words = ['IANA-NETBLOCK-8', 'NON-RIPE-NCC-MANAGED-ADDRESS-BLOCK', 'IANA1',
                  'EU', 'EU ']


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


def filter_result(collected_reply):
    desired_list = ['country', 'netname', 'aut-num', 'origin']
    sum_res = dict()
    for reply in collected_reply:
        for key in reply:
            if key in desired_list and reply[key] not in reserved_words and \
                            'IANA' not in reply[key]:
                sum_res[key] = reply[key]
    return sum_res

def pure_answer(query):
    for key in query:
        if query[key] in reserved_words:
            return False
    return True

def polling_others(word_descr, reply_dict, target):
    polling_list = []
    for registrar in regions_dict:
        expected_res = base_parsing(
            pattern_function(
                receive_who_is
                (target, regions_dict[registrar])
            )
        )
        if len(expected_res.keys()) != 0:
            if pure_answer(expected_res):
                return expected_res
            polling_list.append(expected_res)
    if len(polling_list) > 0:
        return filter_result(polling_list)
    return dict()


# clarify info about the right address
def base_parsing(zone_info, target=None):
    info = dict()
    if len(zone_info.keys()) == 0 and target:
        return polling_others(None, None, target)
    list_of_interest = ['country', 'origin', 'netname', 'aut-num', 'nic-hdl',
                        "OrgId", 'OriginAS', "NetName"]
    for q in list_of_interest:
        if q in zone_info.keys() and zone_info[q] != 'EU':
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
    return state_dict[state](state, info, target)


