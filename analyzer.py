from checks import check_internal_address, check_sensitive_port, check_package_size, check_time


def analyzer_internal_address(data_list):
    return [line[1] for line in data_list if check_internal_address(line)]


def analyzer_sensitive_port(data_list):
    return [line for line in data_list if check_sensitive_port(line)]


def analyzer_package_size(data_list):
    return [line for line in data_list if check_package_size(line)]


def analyzer_time(data_list):
    return [line for line in data_list if check_package_size(line)]


def labeling_package_size(data_list):
    return [line.append("LARGE") if check_package_size(line) else line.append("NORMAL") for line in data_list]


def request_count_IP1(data_list):
    address_IP = [line[1] for line in data_list]
    return {ip: address_IP.count(ip) for ip in set(address_IP)}


def port_for_protocol_labeling(data_list):
    return {line[3]: line[4] for line in data_list}
