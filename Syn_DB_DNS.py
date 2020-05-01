#-------------------------------------------------------------------
# v01.2020
# test_request_DNS server
# answer update DNS servers( config hostDNS, hostDNS2)
#-------------------------------------------------------------------

import binascii
import socket
from config import  host_DNS2, host_DNS


def str2hex(s):
    return binascii.hexlify(bytes(str.encode(s)))


def hex2str(h):
    return binascii.unhexlify(h)


def send_udp_message(message, address, port):
    #send_udp_message sends a message to UDP server

    #message should be a hexadecimal encoded string

    server_address = (address, port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        print("message :", server_address)
        sock.sendto(binascii.unhexlify(message), server_address)
        sock.settimeout(10)
        data, _ = sock.recvfrom(1024)
    except socket.error:
        sock.close()
        print('socket error')
    else:
        sock.close()
       # print(binascii.hexlify(data).decode("utf-8"))
        return binascii.hexlify(data).decode("utf-8")

List_call = "F5F5010000010000000000000764796e686f7374026d6c0000010001"

response = send_udp_message(List_call, host_DNS2, 53)

