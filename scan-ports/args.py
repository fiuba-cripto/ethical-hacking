import argparse
import logging
import sys
from constants import *


def parse_arguments():
    arg_parser = argparse.ArgumentParser(
        prog='scan-ports.py', description='Basic nmap clone'
    )

    group = arg_parser.add_mutually_exclusive_group()
    group.add_argument(
        '-v',
        '--verbose',
        help='increase output verbosity',
        action="store_const",
        dest="loglevel",
        const=logging.DEBUG,
        default=DEFAULT_LOGGING_LEVEL,
    )
    group.add_argument(
        '-q',
        '--quiet',
        help='decrease output verbosity',
        action="store_const",
        dest="loglevel",
        const=logging.ERROR,
        default=DEFAULT_LOGGING_LEVEL,
    )

    scan_type = arg_parser.add_mutually_exclusive_group()
    scan_type.add_argument(
        '-sS',
        '--tcp-stealth',
        help='select TCP Stealth scan',
        action="store_const",
        dest="scan_type",
        const=logging.DEBUG,
        default=DEFAULT_SCAN_TYPE,
    )
    scan_type.add_argument(
        '-sT',
        '--tcp-connect',
        help='select TCP Connect scan',
        action="store_const",
        dest="scan_type",
        const=TCP_CONNECT,
        default=DEFAULT_SCAN_TYPE,
    )
    scan_type.add_argument(
        '-sN',
        '--tcp-null',
        help='select TCP Null scan',
        action="store_const",
        dest="scan_type",
        const=TCP_NULL,
        default=DEFAULT_SCAN_TYPE,
    )
    scan_type.add_argument(
        '-sF',
        '--tcp-fin',
        help='select TCP Fin scan',
        action="store_const",
        dest="scan_type",
        const=TCP_FIN,
        default=DEFAULT_SCAN_TYPE,
    )
    scan_type.add_argument(
        '-sX',
        '--tcp-xmas',
        help='select TCP Xmas scan',
        action="store_const",
        dest="scan_type",
        const=TCP_XMAS,
        default=DEFAULT_SCAN_TYPE,
    )
    scan_type.add_argument(
        '-sU',
        '--udp',
        help='select UDP scan',
        action="store_const",
        dest="scan_type",
        const=UDP_SCAN,
        default=DEFAULT_SCAN_TYPE,
    )

    arg_parser.add_argument(
        'target',
        type=str,
        help='target IP address',
        default=DEFAULT_TARGET_IP,
        metavar='ADDRESS',
    )
    arg_parser.add_argument(
        '-p', '--ports', help='comma separated ports, port-range e.g. 1-80', default=DEFAULT_PORTS
    )
    arg_parser.add_argument(
        '-max', '--max-retries', type=int, help='max retries when no response in UDP Scan', default=DEFAULT_MAX_RETRIES
    )

    return arg_parser.parse_args()


def parse_ports(ports: str):
    split = ports.split(',')
    parsed = []

    for x in split:
        if '-' in x:
            port_range = [int(p) for p in x.split('-', 1)]
            start_port = port_range[0]
            end_port = port_range[1]
            if start_port > end_port:
                print(f"End port must be greater than start port (start: {start_port} - end: {end_port})")
                sys.exit(1)
            parsed.extend(range(start_port, end_port + 1))
        else:
            parsed.append(int(x))

    parsed.sort()
    return parsed
