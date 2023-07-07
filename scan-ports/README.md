# Ports scanning

## Installation

```bash
pip3 install -r requirements.txt
```

## Basic Usage

```bash
python3 scan-ports.py 127.0.0.1 -p 22-24,80,113
```

For more info on scan types and options:

```bash
python3 scan-ports.py -h
```


## How does nmap works


What Nmap does is a port scanning of a target by sending packets and see how the target reacts.

### TCP Stealth Scan
The most common scan it's called TCP Stealth scan, which it's Nmap default.


![TCP Stealth Open](https://nmap.org/book/images/ereet/Ereet_Packet_Trace_Syn_Open.png)

As this example shows, Nmap starts by sending a TCP packet with the SYN flag set to port 22. This is the first step in the TCP three-way handshake that any legitimate connection attempt takes. Since the target port is open, the target takes the second step by sending a response with the SYN and ACK flags back. In a normal connection, the client machine would complete the three-way handshake by sending an ACK packet acknowledging the SYN/ACK. Nmap does not need to do this, since the SYN/ACK response already told it that the port is open. If Nmap completed the connection, it would then have to worry about closing it. This usually involves another handshake, using FIN packets rather than SYN. So an ACK is a bad idea, yet something still has to be done. If the SYN/ACK is ignored completely, the target will assume it was dropped and keep re-sending it. The proper response, since we don't want to make a full connection, is a RST packet as shown in the diagram. This tells the target to forget about (reset) the attempted connection. Nmap could send this RST packet easily enough, but it actually doesn't need to. The OS running on krad also receives the SYN/ACK, which it doesn't expect because Nmap crafted the SYN probe itself. So the OS responds to the unexpected SYN/ACK with a RST packet. All RST packets described in this chapter also have the ACK bit set because they are always sent in response to (and acknowledge) a received packet. So that bit is not shown explicitly for RST packets. Because the three-way handshake is never completed, SYN scan is sometimes called half-open scanning.

![TCP Stealth Closed](https://nmap.org/book/images/ereet/Ereet_Packet_Trace_Syn_Closed.png)

The figure above shows how Nmap determines that port 113 is closed. This is even simpler than the open case. The first step is always the same—Nmap sends the SYN probe to Scanme. But instead of receiving a SYN/ACK back, a RST is returned. That settles it—the port is closed. No more communication regarding this port is necessary.

![TCP Stealth Filtered](https://nmap.org/book/images/ereet/Ereet_Packet_Trace_Syn_Filtered.png)

Finally, this example shows us how a filtered port appears to Nmap. The initial SYN is sent first, as usual, but Nmap sees no reply. The response could simply be slow. From previous responses (or timing defaults), Nmap knows how long to wait and eventually gives up on receiving one. A non-responsive port is usually filtered (blocked by a firewall device, or perhaps the host is down), but this one test is not conclusive. Perhaps the port is open but the probe or response were simply dropped. Networks can be flaky. So Nmap tries again by resending the SYN probe. After yet another timeout period, Nmap gives up and marks the port filtered. In this case, only one retransmission was attempted.

Nmap will also consider a port filtered if it receives certain ICMP error messages back.

We could map these response analysis to the following table:

| Probe Response | Assigned State |
|:---:|:---:|
| TCP SYN/ACK Response | open |
| TCP RST Response | closed |
| No response received (event after retransmissions) | filtered |
| ICMP unreachable error (type 3, code 1, 2, 3, 9, 10, or 13) | filtered |

The following scan will be explained by tables.


### TCP Connect Scan

TCP connect scan is the default TCP scan type when SYN scan is not an option. This is the case when a user does not have raw packet privileges or is scanning IPv6 networks. Instead of writing raw packets as most other scan types do, Nmap asks the underlying operating system to establish a connection with the target machine and port by issuing the connect system call. This is the same high-level system call that web browsers, P2P clients, and most other network-enabled applications use to establish a connection.

When SYN scan is available, it is usually a better choice. Nmap has less control over the high level connect call than with raw packets, making it less efficient. The system call completes connections to open target ports rather than performing the half-open reset that SYN scan does. Not only does this take longer and require more packets to obtain the same information, but target machines are more likely to log the connection. A decent IDS will catch this behaviour.

| Probe Response | Assigned State |
|:---:|:--------------:|
| No response received (event after retransmissions) |     closed     |
| TCP SYN/ACK Response |      open      |
| TCP RST Response |     closed     |



### TCP Null/Fin/Xmas Scan

These three scan types (even more are possible with the --scanflags option described in the next section) exploit a subtle loophole in the TCP RFC to differentiate between open and closed ports. Page 65 of RFC 793 says that “if the [destination] port state is CLOSED .... an incoming segment not containing a RST causes a RST to be sent in response.” Then the next page discusses packets sent to open ports without the SYN, RST, or ACK bits set, stating that: “you are unlikely to get here, but if you do, drop the segment, and return.”

When scanning systems compliant with this RFC text, any packet not containing SYN, RST, or ACK bits will result in a returned RST if the port is closed and no response at all if the port is open. As long as none of those three bits are included, any combination of the other three (FIN, PSH, and URG) are OK. Nmap exploits this with three scan types:

- Null scan: Does not set any bits (TCP flag header is 0)

- FIN scan: Sets just the TCP FIN bit.

- Xmas scan: Sets the FIN, PSH, and URG flags.


| Probe Response | Assigned State  |
|:---:|:---------------:|
| No response received (event after retransmissions) | open / filtered |
| TCP RST Response |     closed      |
| ICMP unreachable error (type 3, code 1, 2, 3, 9, 10, or 13) |    filtered     |


### UDP Scan

UDP scan works by sending a UDP packet to every targeted port. For most ports, this packet will be empty (no payload), but for a few of the more common ports a protocol-specific payload will be sent. Based on the response, or lack thereof, the port is assigned to one of four states:

| Probe Response | Assigned State  |
|:---:|:---------------:|
| Any UDP response from target port (unusual) |      open       |
| No response received (event after retransmissions) | open / filtered |
| ICMP port unreachable error (type 3, code 3) |     closed      |
| Other ICMP unreachable errors (type 3, code 1, 2, 9, 10, or 13) |    filtered     |



## TCP Flags

| Flags | Decimal value | Hexdecimal value |
|:---:|:---:|:----------------:|
| NULL | 0 |       0x00       |
| FIN | 1 |       0x01       |
| SYN | 2 |       0x02       |
| RST | 4 |       0x04       |
| PSH | 8 |       0x08       |
| ACK | 16 |       0x10       |
| URG | 32 |       0x20       |
| ECE | 64 |       0x40       |
| CWR | 128 |       0x80       |
| NS | 256 |      0x100       |

## ICMP Error codes

| Code |                      Description                       |
|:----:|:------------------------------------------------------:|
|  0   |                  Network unreachable                   |
|  1   |                    Host unreachable                    |
|  2   |                  Protocol unreachable                  |
|  3   |                    Port unreachable                    |
|  4   |    Fragmentation needed but don't-fragment bit set     |
|  5   |                  Source route failed                   |
|  6   |              Destination network unknown               |
|  7   |                Destination host unknown                |
|  8   |            Source host isolated (obsolete)             |
|  9   |    Destination network administratively prohibited     |
|  10  |      Destination host administratively prohibited      |
|  11  |     Network unreachable for type of service (TOS)      |
|  12  |                Host unreachable for TOS                |
|  13  | Communication administratively prohibited by filtering |
|  14  |               Host precedence violation                |
|  15  |              Precedence cutoff in effect               |


## Bibliography

For more information, please visit the following links:

- https://nmap.org/book/scan-methods.html
- https://resources.infosecinstitute.com/topic/port-scanning-using-scapy/
- https://thepacketgeek.com/scapy/building-network-tools/part-10/


