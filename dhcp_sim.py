# -*- coding: utf8 -*-
import argparse, random, socket, sys, datetime
import uuid
import DHCPpkt
from time import asctime

BUF_SIZE = 65535

def setClientSocket():
    csock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    csock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    csock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    csock.bind(("0.0.0.0", 68))
    return csock
    
def setServerSocket():
    ssock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ssock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    ssock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ssock.bind(("0.0.0.0", 67))
    return ssock
    
def server():
    ssock = setServerSocket()
    print("Listening for incoming request......")
    
    while True:
        data, address = ssock.recvfrom(BUF_SIZE)
        if data[242] == 1:
            print(data[242])
            ssock.sendto(DHCPpkt.Offer(), ("255.255.255.255", 68))
        elif data[242] == 3:
            print(data[242])
            ssock.sendto(DHCPpkt.Ack(), ("255.255.255.255", 68))
    ssock.close()
         
def client():
    while True:
        csock = setClientSocket()
        csock.sendto(DHCPpkt.Discover(), ("255.255.255.255", 67))

        while True:
            data, address = csock.recvfrom(BUF_SIZE)
            if data[242] == 2:
                print(data[242])
                csock.sendto(DHCPpkt.Request(), ("255.255.255.255", 67))
            elif data[242] == 5:
                print(data[242])
                print("My address  : {}.{}.{}.{}".format(data[16],data[17],data[18],data[19]))
                break
        csock.close()

        if(input('Continue？（Yes/No）') == 'No'):
            break

if __name__ == '__main__':
    #Choose Role
    choices = {'client': client, 'server': server}
    parser = argparse.ArgumentParser(description='DHCP Simulation')
    parser.add_argument('role', choices=choices, help='which role to take')
    args = parser.parse_args()

    #Set Function
    function = choices[args.role]
    function()
