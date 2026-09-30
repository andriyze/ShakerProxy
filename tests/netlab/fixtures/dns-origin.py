#!/usr/bin/env python3
import socket
import struct
import threading


def question_name(message):
    labels = []
    offset = 12
    while message[offset] != 0:
        length = message[offset]
        offset += 1
        labels.append(message[offset:offset + length].decode("ascii"))
        offset += length
    return ".".join(labels)


def answer(query):
    question_end = 12
    while query[question_end] != 0:
        question_end += query[question_end] + 1
    question_end += 5
    header = query[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
    record = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("203.0.113.9")
    return header + query[12:question_end] + record


def receive_exact(connection, length):
    result = b""
    while len(result) < length:
        part = connection.recv(length - len(result))
        if not part:
            raise ConnectionError("DNS client closed before the complete message arrived")
        result += part
    return result


def udp_server():
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind(("10.81.0.53", 53))
    query, peer = listener.recvfrom(4096)
    listener.sendto(answer(query), peer)
    print("udp-query=" + question_name(query), flush=True)
    listener.close()


def tcp_server():
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("10.81.0.53", 53))
    listener.listen(1)
    connection, _ = listener.accept()
    length = struct.unpack("!H", receive_exact(connection, 2))[0]
    query = receive_exact(connection, length)
    response = answer(query)
    connection.sendall(struct.pack("!H", len(response)) + response)
    print("tcp-query=" + question_name(query), flush=True)
    connection.close()
    listener.close()


threads = [threading.Thread(target=udp_server), threading.Thread(target=tcp_server)]
for thread in threads:
    thread.start()
for thread in threads:
    thread.join()
