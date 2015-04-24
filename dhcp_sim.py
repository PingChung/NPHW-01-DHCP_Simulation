# -*- coding: utf8 -*-
import argparse, random, socket, sys, datetime
import uuid
from time import asctime

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
    
def encodeDiscover():
    OP =     (1).to_bytes(1, 'big')      # client to server
    HTYPE =  (1).to_bytes(1, 'big')      # hardware type; 1 for Ethernet
    HLEN =   (6).to_bytes(1, 'big')      # hardware address length; 6 Bytes
    HOPS =   (0).to_bytes(1, 'big')      # how many hops pass
    XID =    (0).to_bytes(4, 'big')      # transection id
    SECS =   (0).to_bytes(2, 'big')      # seconds elapsed
    FLAGS =  (0).to_bytes(2, 'big')      # Bootp flags
    CIADDR = socket.inet_aton("0.0.0.0") # client IP address
    YIADDR = socket.inet_aton("0.0.0.0") # your (client) IP address
    SIADDR = socket.inet_aton("0.0.0.0") # next server IP address
    GIADDR = socket.inet_aton("0.0.0.0") # relay agent IP address
    CHADDR = (112233).to_bytes(6, 'big') + (0).to_bytes(10, 'big') # client MAC address + padding
    SNAME =     (0).to_bytes(64, 'big')  # server host name
    BOOTFILE =  (0).to_bytes(128, 'big') # boot file name
    MAGIC_COOKIE = (0x63825363).to_bytes(4, 'big') # magic cookie: DHCP
    # option
    CLASS =  (53).to_bytes(1, 'big') # 53: DHCP type
    LENGTH = (1).to_bytes(1, 'big')  # 1: length
    TYPE =   (1).to_bytes(1, 'big')  # 1: DHCP discover
    END =    (255).to_bytes(1, 'big')

    packet = OP + HTYPE + HLEN + HOPS + XID + \
             SECS + FLAGS + \
             CIADDR + YIADDR + SIADDR + GIADDR + \
             CHADDR + SNAME + BOOTFILE + MAGIC_COOKIE + \
             CLASS + LENGTH + TYPE + END

    return packet

def encodeOffer():
    OP =     (1).to_bytes(1, 'big')      # client to server
    HTYPE =  (1).to_bytes(1, 'big')      # hardware type; 1 for Ethernet
    HLEN =   (6).to_bytes(1, 'big')      # hardware address length; 6 Bytes
    HOPS =   (0).to_bytes(1, 'big')      # how many hops pass
    XID =    (0).to_bytes(4, 'big')      # transection id
    SECS =   (0).to_bytes(2, 'big')      # seconds elapsed
    FLAGS =  (0).to_bytes(2, 'big')      # Bootp flags
    CIADDR = socket.inet_aton("0.0.0.0") # client IP address
    YIADDR = socket.inet_aton("0.0.0.0") # your (client) IP address
    SIADDR = socket.inet_aton("0.0.0.0") # next server IP address
    GIADDR = socket.inet_aton("0.0.0.0") # relay agent IP address
    CHADDR = (112233).to_bytes(6, 'big') + (0).to_bytes(10, 'big') # client MAC address + padding
    SNAME =     (0).to_bytes(64, 'big')  # server host name
    BOOTFILE =  (0).to_bytes(128, 'big') # boot file name
    MAGIC_COOKIE = (0x63825363).to_bytes(4, 'big') # magic cookie: DHCP
    # option
    CLASS =  (53).to_bytes(1, 'big') # 53: DHCP type
    LENGTH = (1).to_bytes(1, 'big')  # 1: length
    TYPE =   (1).to_bytes(1, 'big')  # 1: DHCP discover
    END =    (255).to_bytes(1, 'big')

    packet = OP + HTYPE + HLEN + HOPS + XID + \
             SECS + FLAGS + \
             CIADDR + YIADDR + SIADDR + GIADDR + \
             CHADDR + SNAME + BOOTFILE + MAGIC_COOKIE + \
             CLASS + LENGTH + TYPE + END

    return packet
    
def encodeAck():
    OP =     (2).to_bytes(1, 'big')      # Server to Client
    HTYPE =  (1).to_bytes(1, 'big')      # Hardware type; 1 for Ethernet
    HLEN =   (6).to_bytes(1, 'big')      # Hardware address length; 6 Bytes
    HOPS =   (0).to_bytes(1, 'big')      # How many hops pass
    XID =    (0).to_bytes(4, 'big')      # Transection id
    SECS =   (0).to_bytes(2, 'big')      # Seconds elapsed
    FLAGS =  (0).to_bytes(2, 'big')      # Bootp flags
    CIADDR = socket.inet_aton("0.0.0.0") # Client IP address
    YIADDR = socket.inet_aton("0.0.0.0") # Your (client) IP address
    SIADDR = socket.inet_aton("0.0.0.0") # Next server IP address
    GIADDR = socket.inet_aton("0.0.0.0") # Relay agent IP address
    CHADDR = (112233).to_bytes(6, 'big') + (0).to_bytes(10, 'big') # Client MAC address + padding
    SNAME =     (0).to_bytes(64, 'big')  # Server host name
    BOOTFILE =  (0).to_bytes(128, 'big') # Boot file name
    MAGIC_COOKIE = (0x63825363).to_bytes(4, 'big') # Magic cookie: DHCP
    # option
    CLASS =  (53).to_bytes(1, 'big') # 53: DHCP type
    LENGTH = (1).to_bytes(1, 'big')  # 1: length
    TYPE =   (1).to_bytes(1, 'big')  # 1: DHCP discover
    END =    (255).to_bytes(1, 'big')

    packet = OP + HTYPE + HLEN + HOPS + XID + \
             SECS + FLAGS + \
             CIADDR + YIADDR + SIADDR + GIADDR + \
             CHADDR + SNAME + BOOTFILE + MAGIC_COOKIE + \
             CLASS + LENGTH + TYPE + END

    return packet

def encodeRequest():
    OP =     (1).to_bytes(1, 'big')      # Client to server
    HTYPE =  (1).to_bytes(1, 'big')      # Hardware type; 1 for Ethernet
    HLEN =   (6).to_bytes(1, 'big')      # Hardware address length; 6 Bytes
    HOPS =   (0).to_bytes(1, 'big')      # How many hops pass
    XID =    (0).to_bytes(4, 'big')      # Transection id
    SECS =   (0).to_bytes(2, 'big')      # Seconds elapsed
    FLAGS =  (0).to_bytes(2, 'big')      # Bootp flags
    CIADDR = socket.inet_aton("0.0.0.0") # Client IP address
    YIADDR = socket.inet_aton("0.0.0.0") # Your (client) IP address
    SIADDR = socket.inet_aton("0.0.0.0") # Next server IP address
    GIADDR = socket.inet_aton("0.0.0.0") # Relay agent IP address
    CHADDR = (112233).to_bytes(6, 'big') + (0).to_bytes(10, 'big') # Client MAC address + padding
    SNAME =     (0).to_bytes(64, 'big')  # Server host name
    BOOTFILE =  (0).to_bytes(128, 'big') # Boot file name
    MAGIC_COOKIE = (0x63825363).to_bytes(4, 'big') # Magic cookie: DHCP
    # option
    CLASS =  (53).to_bytes(1, 'big') # 53: DHCP type
    LENGTH = (1).to_bytes(1, 'big')  # 1: length
    TYPE =   (1).to_bytes(1, 'big')  # 1: DHCP discover
    END =    (255).to_bytes(1, 'big')

    packet = OP + HTYPE + HLEN + HOPS + XID + \
             SECS + FLAGS + \
             CIADDR + YIADDR + SIADDR + GIADDR + \
             CHADDR + SNAME + BOOTFILE + MAGIC_COOKIE + \
             CLASS + LENGTH + TYPE + END

    return packet

def rawPacket():
    packet = b''
    packet += b'\x00'             # Message type: Boot Request (1 or 2)
    packet += b'\x00'             # Hardware type: Ethernet
    packet += b'\x00'             # Hardware address length: 6
    packet += b'\x00'             # Hops: 0 
    packet += b'\x00\x00\x00\x00' # Transaction ID
    packet += b'\x00\x00'         # Seconds elapsed: 0
    packet += b'\x00\x00'         # Bootp flags: 0x8000 (Broadcast) + reserved flags
    packet += b'\x00\x00\x00\x00' # Client IP address: 0.0.0.0
    packet += b'\xC0\xA8\x01\x64' # Your (client) IP address: 0.0.0.0
    packet += b'\x00\x00\x00\x00' # Next server IP address: 0.0.0.0
    packet += b'\x00\x00\x00\x00' # Relay agent IP address: 0.0.0.0
    packet += b'\x00\x00\x00\x00\x00\x00' # Client MAC address: 00:26:9e:04:1e:9b
    packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' #Client hardware address padding: 00000000000000000000
    packet += b'\x00' * 64        # Server host name not given
    packet += b'\x00' * 128       # Boot file name not given
    packet += b'\x63\x82\x53\x63' #Magic cookie: DHCP
    packet += b'\x35\x01\x03'     # Option: (t=53,l=1) DHCP Message Type = DHCP Discover
    packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    packet += b'\x32\x04\x00\x00\x00\x00' #Option: (t=55,l=3) Parameter Request List
    packet += b'\x36\x04\x00\x00\x00\x01'
    packet += b'\x37\x00\x00\x00\x00\x00'
    packet += b'\xff'   #End Option
    packet += b'\x00'

    return packet

def DHCPACK(ip_pool):
    ip = ip_pool.pop(0)

    packet = b''
    packet += b'\x02'   #Message type: Boot Request (1)
    packet += b'\x01'   #Hardware type: Ethernet
    packet += b'\x06'   #Hardware address length: 6
    packet += b'\x00'   #Hops: 0 
    packet += b'\x39\x03\xf3\xfb'       #Transaction ID
    packet += b'\x00\x00'    #Seconds elapsed: 0
    packet += b'\x00\x00'   #Bootp flags: 0x8000 (Broadcast) + reserved flags
    packet += b'\x00\x00\x00\x00'   #Client IP address: 0.0.0.0
    packet += ip
    #packet += b'\xc0\xa8\x00\x0a'   #Your (client) IP address: 0.0.0.0
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

    ip_pool.append(ip)
    
    return packet

def server():
    #settings
    ip_pool = [b'\xc0\xa8\x00\x0a', b'\xc0\xa8\x00\x0b', b'\xc0\xa8\x00\x0c']

    print(datetime.date.today())
    ssock = setServerSocket()
    print("Listening for incoming request......")
    
    while True:
        data, address = ssock.recvfrom(BUF_SIZE)
        if data[242] == 1:
            print(data[242])
            ssock.sendto(encodeOffer(), ("255.255.255.255", 68))
        elif data[242] == 3:
            print(data[242])
            ssock.sendto(DHCPACK(ip_pool), ("255.255.255.255", 68))
            #break
    ssock.close()

          
def client():
    while True:
        csock = setClientSocket()
        print("Sending DHCPDISCOVER......")
        csock.sendto(encodeDiscover(), ("255.255.255.255", 67))

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
        if(input('繼續？（Yes/No）') == 'No'):
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
