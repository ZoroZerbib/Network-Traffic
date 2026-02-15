from checks import check_internal_address, check_sensitive_port, check_package_size, check_time, check_hour_rescue


def analyzer_internal_address(data_list):
    return [line[1] for line in data_list if check_internal_address(line)]


def analyzer_sensitive_port(data_list):
    return [line for line in data_list if check_sensitive_port(line)]


def analyzer_package_size(data_list):
    return [line for line in data_list if check_package_size(line)]


def analyzer_time(data_list):
    return [line for line in data_list if check_time(line)]


def labeling_package_size(data_list):
    return [line.append("LARGE") if check_package_size(line) else line.append("NORMAL") for line in data_list]


def request_count_IP1(data_list):
    address_IP = [line[1] for line in data_list]
    return {ip: address_IP.count(ip) for ip in set(address_IP)}


def port_for_protocol_labeling(data_list):
    return {line[3]: line[4] for line in data_list}


def identifying_suspicions_for_each_IP(data_list):
    suspicions_dict = {}

    def add_dic(ip, condition):
        if ip not in suspicions_dict: suspicions_dict[ip] = []
        if condition not in suspicions_dict[ip]: suspicions_dict[ip].append(condition)

    for line in data_list:
        ip_new = line[1]
        if check_internal_address(line): add_dic(ip_new, "IP_EXTERNAL")
        if check_sensitive_port(line): add_dic(ip_new, "PORT_SENSITIVE")
        if check_package_size(line): add_dic(ip_new, "PACKET_LARGE")
        if check_time(line): add_dic(ip_new, "ACTIVITY_NIGHT")
    return suspicions_dict


def filtering_suspicion_dictionary(data_list):
    return {k: v for k, v in identifying_suspicions_for_each_IP(data_list).items() if len(v) >= 2}

def analyzer_check_time(data_list):
    return list(map(lambda line:check_hour_rescue(line),data_list ))
