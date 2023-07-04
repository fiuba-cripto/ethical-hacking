import logging

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from args import parse_arguments, parse_ports
from constants import TCP_STEALTH, TCP_CONNECT, TCP_NULL, TCP_FIN, TCP_XMAS, UDP_SCAN, OPEN, CLOSED, FILTERED, \
    OPEN_OR_FILTERED, UNKNOWN

summary = {}


def print_summary(states, protocol, separator="\t\t"):
    ports = list(states.keys())
    ports.sort()
    print(f"{'PORT':^10}{separator}STATE")
    for port in ports:
        print(f"{port:>5}/{protocol}{separator}{states[port]}")


def tcp_stealth_scan(target_ip, port, **kwargs):
    ip = IP(dst=target_ip)
    tcp = TCP(sport=RandShort(), dport=port, flags="S")
    # send SYN package and wait for response
    response = sr1(ip / tcp, timeout=3, verbose=0)

    logging.debug(f"response {response}")
    if response is None:
        summary[port] = FILTERED
    elif response.haslayer(TCP):
        if response.getlayer(TCP).flags == 0x12:  # SYN+ACK
            summary[port] = OPEN
        elif response.getlayer(TCP).flags == 0x14:  # RST+ACK
            summary[port] = CLOSED
        else:
            summary[port] = UNKNOWN
    elif response.haslayer(ICMP) and int(response.getlayer(ICMP).type) == 3 and int(
            response.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]:
        summary[port] = FILTERED
    else:
        summary[port] = UNKNOWN

    return summary[port]


def tcp_connect_scan(target_ip, port, **kwargs):
    ip = IP(dst=target_ip)
    tcp = TCP(sport=RandShort(), dport=port, flags="S")
    # send SYN package and wait for response
    response = sr1(ip / tcp, timeout=3, verbose=0)

    logging.debug(f"response {response}")
    if response is None:
        summary[port] = CLOSED
    elif response.haslayer(TCP):
        if response.getlayer(TCP).flags == 0x12:  # SYN+ACK
            new_tcp_reset = TCP(sport=RandShort(), dport=port, flags="R")
            _ = sr1(ip / new_tcp_reset, timeout=3)
            summary[port] = OPEN
        elif response.getlayer(TCP).flags == 0x14:  # RST+ACK
            summary[port] = CLOSED
        else:
            summary[port] = UNKNOWN
    else:
        summary[port] = UNKNOWN

    return summary[port]


def udp_scan(target_ip, port, max_retries, retransmission=False):
    ip = IP(dst=target_ip)
    udp = UDP(sport=RandShort(), dport=port)
    # send UDP package and wait for responses
    response = sr1(ip / udp, timeout=3, verbose=0)

    logging.debug(f"response {response}")
    if response is None:
        summary[port] = OPEN_OR_FILTERED
        if not retransmission:
            for i in range(max_retries):
                logging.debug(f"retry number {i}")
                state = udp_scan(target_ip, port, max_retries, True)
                if state != OPEN_OR_FILTERED:
                    summary[port] = state
                    break
    elif response.haslayer(UDP):
        summary[port] = OPEN
    elif response.haslayer(ICMP) and int(response.getlayer(ICMP).type) == 3:
        if int(response.getlayer(ICMP).code) == 3:
            summary[port] = CLOSED
        if int(response.getlayer(ICMP).code) in [1, 2, 9, 10, 13]:
            summary[port] = FILTERED
    else:
        summary[port] = UNKNOWN

    return summary[port]


def common_scan_analysis(scan_func, response, target_ip, port, max_retries, retransmission=False):
    if response is None:
        summary[port] = OPEN_OR_FILTERED
        if not retransmission:
            for i in range(max_retries):
                logging.debug(f"retry number {i}")
                state = scan_func(target_ip, port, max_retries, True)
                if state != OPEN_OR_FILTERED:
                    summary[port] = state
                    break
    elif response.haslayer(TCP):
        if response.getlayer(TCP).flags == 0x14:  # RST+ACK
            summary[port] = CLOSED
        else:
            summary[port] = UNKNOWN
    elif response.haslayer(ICMP) and int(response.getlayer(ICMP).type) == 3:
        if int(response.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]:
            summary[port] = FILTERED
    else:
        summary[port] = UNKNOWN

    return summary[port]


def tcp_null_scan(target_ip, port, max_retries, retransmission=False):
    ip = IP(dst=target_ip)
    tcp = TCP(sport=RandShort(), dport=port)
    # send SYN package and wait for response
    response = sr1(ip / tcp, timeout=3, verbose=0)

    logging.debug(f"response {response}")
    return common_scan_analysis(tcp_null_scan, response, target_ip, port, max_retries, retransmission)


def tcp_fin_scan(target_ip, port, max_retries, retransmission=False):
    ip = IP(dst=target_ip)
    tcp = TCP(sport=RandShort(), dport=port, flags="F")
    # send SYN package and wait for response
    response = sr1(ip / tcp, timeout=3, verbose=0)

    logging.debug(f"response {response}")
    return common_scan_analysis(tcp_fin_scan, response, target_ip, port, max_retries, retransmission)


def tcp_xmas_scan(target_ip, port, max_retries, retransmission=False):
    ip = IP(dst=target_ip)
    tcp = TCP(sport=RandShort(), dport=port, flags="FPU")
    # send SYN package and wait for response
    response = sr1(ip / tcp, timeout=3, verbose=0)

    logging.debug(f"response {response}")
    return common_scan_analysis(tcp_xmas_scan, response, target_ip, port, max_retries, retransmission)


def get_scan_type_func(scan_type):
    if scan_type == TCP_STEALTH:
        return tcp_stealth_scan
    if scan_type == TCP_CONNECT:
        return tcp_connect_scan
    if scan_type == TCP_NULL:
        return tcp_null_scan
    if scan_type == TCP_FIN:
        return tcp_fin_scan
    if scan_type == TCP_XMAS:
        return tcp_xmas_scan
    if scan_type == UDP_SCAN:
        return udp_scan


def get_protocol_from_scan_type(scan_type):
    if scan_type == UDP_SCAN:
        return "udp"
    return "tcp"


def main():
    args = parse_arguments()

    logging.basicConfig(level=args.loglevel)
    logging.debug("Arguments parsed")

    target_ip = args.target
    ports = args.ports
    scan_type = args.scan_type
    max_retries = args.max_retries

    logging.info(f"Target IP address: {target_ip}")
    logging.info(f"Target ports: {ports}")

    parsed_ports = parse_ports(ports)

    scan = get_scan_type_func(scan_type)
    protocol = get_protocol_from_scan_type(scan_type)

    logging.debug(f"function => {scan}")

    for port in parsed_ports:
        scan(target_ip, port, max_retries=max_retries)

    print_summary(summary, protocol)


if __name__ == "__main__":
    main()
