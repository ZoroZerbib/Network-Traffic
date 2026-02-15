from checks import check_internal_address, check_sensitive_port, check_package_size, check_time, check_hour_rescue, \
    package_size_conversion


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
    return list(map(lambda line: check_hour_rescue(line), data_list))


def analyzer_package_size_conversion(data_list):
    return list(map(lambda line: package_size_conversion(line), data_list))


def analyzer_filter_rows_by_port(data_list):
    return list(filter(check_sensitive_port, data_list))


def analyzer_night_activity_filtering(data_list):
    return list(filter(check_time, data_list))
# d = [["2024-01-15 00:00:29", "10.0.0.8", "10.0.0.7", "80", "HTTP", "762"],
#      ["2024-01-15 02:00:29", "10.0.0.8", "10.0.0.7", "443", "HTTPS", "762"],
#      ["2024-01-15 08:08:29", "18.0.0.8", "10.0.0.7", "443", "HTTPS", "762"],
#      ["2024-01-15 07:00:29", "18.0.0.8", "10.0.0.7", "3389", "HTTP", "762"],
#      ["2024-01-15 08:03:29", "10.0.0.8", "10.0.0.7", "80", "HTTP", "762"],
#      ["2024-01-15 08:00:29", "10.0.0.8", "10.0.0.7", "22", "SSH", "10000"],
#      ["2024-01-15 09:00:29", "10.5.0.8", "10.0.0.7", "22", "SSH", "42422"],
#      ["2024-01-15 05:00:29", "20.0.0.8", "10.0.0.7", "80", "HTTP", "8765"],
#      ]
#
# print(analyzer_night_activity_filtering(d))
