# SYN Flooding Attack

## Installation

```bash
pip3 install -r requirements.txt
```

## What is a SYN Flood Attack

![SYN Flood Attack](https://www.thepythoncode.com/media/articles/syn-flooding-attack-using-scapy-in-python/3-way-tcp-handshake.png)

When a client wants to establish a connection to a server via TCP protocol, the client and server exchange a series of messages:

- The client requests a connection by sending a SYN message to the server.
- The server responds with a SYN-ACK message (acknowledges the request).
- The client responds back with an ACK, and then the connection is started.

SYN flood attack involves a malicious user that sends SYN packets repeatedly without responding with ACK, and often with different source ports, which makes the server unaware of the attack and responds to each attempt with a SYN-ACK packet from each port (The red and green part of the above image). In this way, the server will quickly be unresponsive to legitimate clients.


## Sample server

Initialize a sample server to test these attacks

```bash
python3 -m http.server 8080
```

## Basic Usage

```bash
python3 main.py -H 127.0.0.1 -p 8080
```

## Try connection

```bash
curl localhost:8080
```

After a few tries, server saturates and results in no connection




