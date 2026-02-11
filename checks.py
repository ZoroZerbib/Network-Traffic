from config import EXTERNAL_IP, SENSITIVE_PORT

def check_internal_address(line):
    is_external = any(line[1].startswith(ip) for ip in EXTERNAL_IP)
    return not is_external

def check_sensitive_port(line):
    if line[3] in SENSITIVE_PORT:
        return True
    return False