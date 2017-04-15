import ipaddress

icmp_requests = {
    "echo reply": 0,
    "error reply": 3,
    "echo request": 8,
    "route discovery": 9,
    "route request": 10,
    "ttl_expired": 11,

}


def ip_addr_is_private(string_ip):
    return ipaddress.ip_address(string_ip).is_private


def answer_formatting(dict_of_values):
    net_name = dict_of_values.get("NetName", dict_of_values.get('netname', " "))
    country = dict_of_values.get("Country", dict_of_values.get('country', " "))
    as_point = dict_of_values.get('OriginAs',  dict_of_values.get('origin', " "))
    if len(as_point) > 2:
        as_point = " " + as_point[2:] + " "
    return net_name + as_point + country + "\r\n"


# {'nic-hdl': 'YNDX1-RIPE', 'origin': 'AS13238', 'netname': 'YANDEX-77-88-55', 'country': 'RU'}
# {'NetName': 'GOOGLE', 'Country': 'US', 'OriginAS': ' '}