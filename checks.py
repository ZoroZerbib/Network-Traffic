from config import EXTERNAL_IP

def internal_address_check(line):
    is_external = any(line[1].startswith(ip) for ip in EXTERNAL_IP)
    return not is_external
