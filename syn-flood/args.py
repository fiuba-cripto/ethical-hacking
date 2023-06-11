import argparse
import logging

DEFAULT_LOGGING_LEVEL = logging.INFO
DEFAULT_SERVER_IP = "127.0.0.1"
DEFAULT_SERVER_PORT = 80


def parse_arguments():
    arg_parser = argparse.ArgumentParser(
        prog='syn-flood', description='Make a SYN Flooding attack to a given server'
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

    arg_parser.add_argument(
        '-H',
        '--host',
        type=str,
        help='server IP address',
        default=DEFAULT_SERVER_IP,
        metavar='ADDR',
    )
    arg_parser.add_argument(
        '-p', '--port', type=int, help='server port', default=DEFAULT_SERVER_PORT
    )

    return arg_parser.parse_args()
