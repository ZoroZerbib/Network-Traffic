from checks import internal_address_check

def external_IP_check(data_list):
    return  [line[1] for line in data_list if internal_address_check(line)]