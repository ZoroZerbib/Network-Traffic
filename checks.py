from config import EXTERNAL_IP, SENSITIVE_PORT, PACKET_LARGE


def check_internal_address(line):
    if not any(line[1].startswith(ip) for ip in EXTERNAL_IP):
        return True
    return False


def check_sensitive_port(line):
    if line[3] in SENSITIVE_PORT:
        return True
    return False


def check_package_size(line):
    if line[5] > PACKET_LARGE:
        return True
    return False
