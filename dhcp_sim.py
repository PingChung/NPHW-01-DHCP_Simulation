# -*- coding: utf8 -*-
import argparse, random, socket, sys, datetime
import uuid

BUF_SIZE = 65535

def getMacAddr():
    s = ''.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0,8*6,8)][::-1])
    return s

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
    
def DHCPDISCOVER():
    packet = b''
    packet += b'\x01'   #Message type: Boot Request (1)
    packet += b'\x01'   #Hardware type: Ethernet
    packet += b'\x06'   #Hardware address length: 6
    packet += b'\x00'   #Hops: 0 
    packet += b'\x39\x03\xf3\xfa'       #Transaction ID
    packet += b'\x00\x00'    #Seconds elapsed: 0
    packet += b'\x00\x00'   #Bootp flags: 0x8000 (Broadcast) + reserved flags
    packet += b'\x00\x00\x00\x00'   #Client IP address: 0.0.0.0
    packet += b'\x00\x00\x00\x00'   #Your (client) IP address: 0.0.0.0
    packet += b'\x00\x00\x00\x00'   #Next server IP address: 0.0.0.0
    packet += b'\x00\x00\x00\x00'   #Relay agent IP address: 0.0.0.0

    
    #packet += getMacAddr().encode('utf-8')
    packet += b'\x00\x26\x9e\x04\x1e\x9b'   #Client MAC address: 00:26:9e:04:1e:9b
    packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'   #Client hardware address padding: 00000000000000000000
    packet += b'\x00' * 64  #Server host name not given
    packet += b'\x00' * 128 #Boot file name not given
    packet += b'\x63\x82\x53\x63'   #Magic cookie: DHCP
    packet += b'\x35\x01\x01'   #Option: (t=53,l=1) DHCP Message Type = DHCP Discover
    packet += b'\x3d\x07\x01\x00\x26\x9e\x04\x1e\x9b'
    packet += b'\x32\x04\x00\x00\x00\x00'   #Option: (t=55,l=3) Parameter Request List
    packet += b'\x37\x04\x00\x00\x00\x00'
    packet += b'\xff'   #End Option
    packet += b'\x00' * 7
    return packet

def DHCPOFFER():
    packet = b''
    packet += b'\x02'   #Message type: Boot Request (1)
    packet += b'\x01'   #Hardware type: Ethernet
    packet += b'\x06'   #Hardware address length: 6
    packet += b'\x00'   #Hops: 0 
    packet += b'\x39\x03\xf3\xfa'       #Transaction ID
    packet += b'\x00\x00'    #Seconds elapsed: 0
    packet += b'\x00\x00'   #Bootp flags: 0x8000 (Broadcast) + reserved flags
    packet += b'\x00\x00\x00\x00'   #Client IP address: 0.0.0.0
    packet += b'\xc0\xa8\x00\x0a'   #Your (client) IP address: 0.0.0.0
    packet += b'\xc0\xa8\x00\x01'   #Next server IP address: 0.0.0.0
    packet += b'\x00\x00\x00\x00'   #Relay agent IP address: 0.0.0.0
    packet += b'\x00\x26\x9e\x04\x1e\x9b'   #Client MAC address: 00:26:9e:04:1e:9b
    packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'   #Client hardware address padding: 00000000000000000000

    packet += b'\x00' * 64  #Server host name not given
    packet += b'\x00' * 128 #Boot file name not given
    packet += b'\x63\x82\x53\x63'   #Magic cookie: DHCP
    packet += b'\x35\x01\x02'   #DHCP Message Type = DHCP Discover
    packet += b'\x01\x04\xff\xff\xff\x00'
    packet += b'\x3a\x04\x00\x00\x07\x08'
    packet += b'\x3b\x04\x00\x00\x0c\x4e'
    packet += b'\x33\x04\x00\x00\x0e\x10'
    packet += b'\x36\x04\x7f\x00\x00\x01'
    packet += b'\xff'
    packet += b'\x00' * 26 #end padding
    return packet
    
def DHCPREQUEST():
    packet = b''
    packet += b'\x01'   #Message type: Boot Request (1)
    packet += b'\x01'   #Hardware type: Ethernet
    packet += b'\x06'   #Hardware address length: 6
    packet += b'\x00'   #Hops: 0 
    packet += b'\x39\x03\xf3\xfb'       #Transaction ID

    packet += b'\x00\x00'    #Seconds elapsed: 0
    packet += b'\x80\x00'   #Bootp flags: 0x8000 (Broadcast) + reserved flags
    packet += b'\x00\x00\x00\x00'   #Client IP address: 0.0.0.0
    packet += b'\xC0\xA8\x01\x64'   #Your (client) IP address: 0.0.0.0
    packet += b'\x00\x00\x00\x00'   #Next server IP address: 0.0.0.0
    packet += b'\x00\x00\x00\x00'   #Relay agent IP address: 0.0.0.0
    packet += b'\x00\x26\x9e\x04\x1e\x9b'   #Client MAC address: 00:26:9e:04:1e:9b
    packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'   #Client hardware address padding: 00000000000000000000

    packet += b'\x00' * 64  #Server host name not given
    packet += b'\x00' * 128 #Boot file name not given
    packet += b'\x63\x82\x53\x63'   #Magic cookie: DHCP
    packet += b'\x35\x01\x03'   #Option: (t=53,l=1) DHCP Message Type = DHCP Discover
    packet += b'\x3d\x07\x01\x00\x26\x9e\x04\x1e\x9b'
    packet += b'\x32\x04\xc0\xa8\x00\x0a'   #Option: (t=55,l=3) Parameter Request List
    packet += b'\x36\x04\xc0\xa8\x00\x01'
    packet += b'\x37\x04\x01\x03\x06\x2a'
    packet += b'\xff'   #End Option
    packet += b'\x00'
    return packet

def DHCPACK():
    packet = b''
    packet += b'\x02'   #Message type: Boot Request (1)
    packet += b'\x01'   #Hardware type: Ethernet
    packet += b'\x06'   #Hardware address length: 6
    packet += b'\x00'   #Hops: 0 
    packet += b'\x39\x03\xf3\xfb'       #Transaction ID
    packet += b'\x00\x00'    #Seconds elapsed: 0
    packet += b'\x00\x00'   #Bootp flags: 0x8000 (Broadcast) + reserved flags
    packet += b'\x00\x00\x00\x00'   #Client IP address: 0.0.0.0
    packet += b'\xc0\xa8\x00\x0a'   #Your (client) IP address: 0.0.0.0
    packet += b'\x00\x00\x00\x00'   #Next server IP address: 0.0.0.0
    packet += b'\x00\x00\x00\x00'   #Relay agent IP address: 0.0.0.0
    packet += b'\x00\x26\x9e\x04\x1e\x9b'   #Client MAC address: 00:26:9e:04:1e:9b
    packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'   #Client hardware address padding: 00000000000000000000

    packet += b'\x00' * 64  #Server host name not given
    packet += b'\x00' * 128 #Boot file name not given
    packet += b'\x63\x82\x53\x63'   #Magic cookie: DHCP
    packet += b'\x35\x01\x05'   #Option: (t=53,l=1) DHCP Message Type = DHCP Discover
    packet += b'\x3a\x04\x00\x00\x07\x08'
    packet += b'\x3b\x04\x00\x00\x0c\x4e'
    packet += b'\x33\x04\x00\x00\x0e\x10'
    packet += b'\x36\x04\x7f\x00\x00\x01'
    packet += b'\x01\x04\xff\xff\xff\x00'
    packet += b'\xff'
    packet += (b'\x00' * 26)   #End Option
    return packet

def server():
    print(datetime.date.today())
    ssock = setServerSocket()
    print("Listening for incoming request......")
    
    while True:
        data, address = ssock.recvfrom(BUF_SIZE)
        if data[242] == 1:
            print(data[242])
            ssock.sendto(DHCPOFFER(), ("255.255.255.255", 68))
        elif data[242] == 3:
            print(data[242])
            ssock.sendto(DHCPACK(), ("255.255.255.255", 68))
            break
    ssock.close()

def client():
    csock = setClientSocket()
    print("Sending DHCPDISCOVER......")
    csock.sendto(DHCPDISCOVER(), ("255.255.255.255", 67))

    while True:
        data, address = csock.recvfrom(BUF_SIZE)
        if data[242] == 2:
            print(data[242])
            csock.sendto(DHCPREQUEST(), ("255.255.255.255", 67))
        elif data[242] == 5:
            print(data[242])
            print("My address  : {}.{}.{}.{}".format(data[16],data[17],data[18],data[19]))
            break

    csock.close()

if __name__ == '__main__':
    #Choose Role
    choices = {'client': client, 'server': server}
    parser = argparse.ArgumentParser(description='DHCP Simulation')
    parser.add_argument('role', choices=choices, help='which role to take')
    args = parser.parse_args()

    #Set Function
    function = choices[args.role]
    function()
