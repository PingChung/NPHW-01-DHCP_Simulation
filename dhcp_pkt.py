import socket


def discover():
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

def offer():
    OP =     (2).to_bytes(1, 'big')      # server to client
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
    TYPE =   (2).to_bytes(1, 'big')  # 1: DHCP offer
    END =    (255).to_bytes(1, 'big')

    packet = OP + HTYPE + HLEN + HOPS + XID + \
             SECS + FLAGS + \
             CIADDR + YIADDR + SIADDR + GIADDR + \
             CHADDR + SNAME + BOOTFILE + MAGIC_COOKIE + \
             CLASS + LENGTH + TYPE + END

    return packet

def request():
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
    TYPE =   (3).to_bytes(1, 'big')  # 1: DHCP request
    END =    (255).to_bytes(1, 'big')

    packet = OP + HTYPE + HLEN + HOPS + XID + \
             SECS + FLAGS + \
             CIADDR + YIADDR + SIADDR + GIADDR + \
             CHADDR + SNAME + BOOTFILE + MAGIC_COOKIE + \
             CLASS + LENGTH + TYPE + END

    return packet

def ack():
    OP =     (2).to_bytes(1, 'big')      # Server to Client
    HTYPE =  (1).to_bytes(1, 'big')      # Hardware type; 1 for Ethernet
    HLEN =   (6).to_bytes(1, 'big')      # Hardware address length; 6 Bytes
    HOPS =   (0).to_bytes(1, 'big')      # How many hops pass
    XID =    (0).to_bytes(4, 'big')      # Transection id
    SECS =   (0).to_bytes(2, 'big')      # Seconds elapsed
    FLAGS =  (0).to_bytes(2, 'big')      # Bootp flags
    CIADDR = socket.inet_aton("0.0.0.0") # Client IP address
    YIADDR = socket.inet_aton("192.168.0.1") # Your (client) IP address
    SIADDR = socket.inet_aton("0.0.0.0") # Next server IP address
    GIADDR = socket.inet_aton("0.0.0.0") # Relay agent IP address
    CHADDR = (112233).to_bytes(6, 'big') + (0).to_bytes(10, 'big') # Client MAC address + padding
    SNAME =     (0).to_bytes(64, 'big')  # Server host name
    BOOTFILE =  (0).to_bytes(128, 'big') # Boot file name
    MAGIC_COOKIE = (0x63825363).to_bytes(4, 'big') # Magic cookie: DHCP
    # option
    CLASS =  (53).to_bytes(1, 'big') # 53: DHCP type
    LENGTH = (1).to_bytes(1, 'big')  # 1: length
    TYPE =   (5).to_bytes(1, 'big')  # 1: DHCP ack
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