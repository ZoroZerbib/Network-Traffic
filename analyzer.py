from checks import check_internal_address,check_sensitive_port

def analyzer_internal_address(data_list):
    return  [line[1] for line in data_list if check_internal_address(line)]
def analyzer_sensitive_port(data_list):
    return  [line[3] for line in data_list if check_sensitive_port(line)]
