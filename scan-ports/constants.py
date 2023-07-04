import logging

DEFAULT_LOGGING_LEVEL = logging.INFO
DEFAULT_TARGET_IP = "127.0.0.1"
DEFAULT_PORTS = "1-100"
DEFAULT_MAX_RETRIES = 3
TCP_STEALTH = "TCP_STEALTH"
TCP_CONNECT = "TCP_CONNECT"
TCP_NULL = "TCP_NULL"
TCP_FIN = "TCP_FIN"
TCP_XMAS = "TCP_XMAS"
UDP_SCAN = "UDP_SCAN"
DEFAULT_SCAN_TYPE = TCP_STEALTH

OPEN = "open"
CLOSED = "closed"
FILTERED = "filtered"
OPEN_OR_FILTERED = "open|filtered"
UNKNOWN = "unknown"