from checks import check_internal_address, check_sensitive_port, check_package_size


def analyzer_internal_address(data_list):
    return [line[1] for line in data_list if check_internal_address(line)]


def analyzer_sensitive_port(data_list):
    return [line for line in data_list if check_sensitive_port(line)]


def analyzer_package_size(data_list):
    return [line for line in data_list if check_package_size(line)]
