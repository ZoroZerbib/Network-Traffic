from config import EXTERNAL_IP, SENSITIVE_PORT, PACKET_LARGE, NIGHT_ACTIVITY
from datetime import datetime


def check_internal_address(line):
    if not any(line[1].startswith(ip) for ip in EXTERNAL_IP):
        return True
    return False


def check_sensitive_port(line):
    if line[3] in SENSITIVE_PORT:
        return True
    return False


def check_package_size(line):
    if int(line[5]) > PACKET_LARGE:
        return True
    return False


def check_time(line):
    def sum_min(time):
        return (time.hour * 60) + time.minute

    dt_object = datetime.strptime(line[0], "%Y-%m-%d %H:%M:%S")
    early_hour = datetime.strptime(NIGHT_ACTIVITY[0], "%H:%M")
    late_hour = datetime.strptime(NIGHT_ACTIVITY[1], "%H:%M")
    if sum_min(early_hour) <= sum_min(dt_object) < sum_min(late_hour):
        return True
    return False


def check_hour_rescue(line):
    dt_object = datetime.strptime(line[0], "%Y-%m-%d %H:%M:%S")
    return dt_object.hour


def package_size_conversion(line):
    return round(int(line[5]) / 1024, 1)
