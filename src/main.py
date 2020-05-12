import socket
import struct

main()

def main():
    # the public network interface
    HOST = socket.gethostbyname(socket.gethostname())
    # create a raw socket and bind it to the public interface
    rawSocket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    rawSocket.bind((HOST, 0))
    # Include IP headers
    rawSocket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    # receive all packages
    rawSocket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    switcher = {
            1: analyze_ICMP,
            6: analyze_TCP,
            17: analyze_UDP,
        }

    print("Sniffer started please introduce number of packages you wan to capture");
    print("Number of packages:", end="") 
    packagesNumber = input()

    for i in range(packagesNumber):
        print('############### {} Package ###############'.format(i))
        rawData = rawSocket.recvfrom(65535)
        etherProtocol, etherData = analyze_Ethernet(rawData)

        if etherProtocol == 8:
            ipProtocol, ipData = analyze_IP(etherData)
            
            if ipProtocol == 1:
                analyze_ICMP(ipData)

            if ipProtocol == 6:
                dns, tcpData = analyze_TCP(ipData)

                if dns: analyze_DNS(tcpData)

            if ipProtocol == 17:
                dns, udpData = analyze_UDP(ipData)

                if dns: analyze_DNS(udpData)

            

    
#### analyze region ####

def analyze_Ethernet(rawData):
    ethernetHeader = struct.unpack("!6s6sH", rawData[:14])
    destMAC = ethernetHeader[0]
    sourMAC = ethernetHeader[1]
    protocol = ethernetHeader[2] >> 8

    print('############### ETHERNET ###############')
    print('Destination MAC: {}, Source MAC: {}, Protocol: {}'.format(destMAC, sourMAC, protocol))

    return protocol, rawData[14:]

def analyze_IP(rawData):
    ipHeader = struct.unpack("!2B 3H 2B H 2L", rawData[:20])
    version = ipHeader[0] >> 4
    ihl = ipHeader[0] & 0xF
    ToS = ipHeader[1]
    totalLength = ipHeader[2]
    identity = ipHeader[3]
    noFragFlag = ipHeader[4] & 0x8000
    moreFrag = ipHeader[4] & 0x4000
    fragOffset = ipHeader[4] & 0x1FFF 
    ttl = ipHeader[5]
    protocol = ipHeader[6]
    checksum = ipHeader[7]
    sourAddress = format_IPv4Address(ipHeader[8])
    destAddress = format_IPv4Address(ipHeader[9])

    print('###############    IP    ###############')
    print('Version: {}, IHL: {}, ToS: {}, Total Length: {}'.format(version, ihl, ToS, totalLength))
    print('Identity: {}, Fragment Flag: {}, More Fragments Flag: {}, Fragment Offset: {}'.format(identity, noFragFlag, moreFrag, fragOffset))
    print('TTL: {}, Protocol: {}, Checksum: {}'.format(ttl, protocol, checksum))
    print('Source Address: ', sourAddress)
    print('Destination Address: ', destAddress)


    return protocol, rawData[20:]

def analyze_ICMP(rawData):
    icmpType, code, checksum = struct.unpack('! 2B H', rawData[:4])
    print('###############   ICMP   ###############')
    print('type: {}, code: {}, checksum: {}'.format(icmpType, code, checksum))

def analyze_TCP(rawData):
    tcpHeader = struct.unpack('! 2H 2L 4H', rawData[:20])
    sourcePort = tcpHeader[0] 
    destPort = tcpHeader[1] 
    seqNumber = tcpHeader[2] 
    ack = tcpHeader[3] 
    offset_reserved_flags = tcpHeader[4]
    offset = tcpHeader[4]  & 0xF000
    reserved = tcpHeader[4] & 0xE00
    nsFlag = tcpHeader[4] & 0x100
    cwrFlag = tcpHeader[4] & 0x80
    eceFlag = tcpHeader[4] & 0x40
    urgFlag = tcpHeader[4] & 0x20
    ackFlag = tcpHeader[4] & 0x10
    pshFlag = tcpHeader[4] & 0x8
    rstFlag = tcpHeader[4] & 0x4
    synFlag = tcpHeader[4] & 0x2
    finFlag = tcpHeader[4] & 0x1
    window = tcpHeader[5] 
    checksum = tcpHeader[6] 
    urgentPointer = tcpHeader[7]

    print('###############   TCP   ###############')
    print('Source Port: {}, Destination Port: {}'.format(sourcePort, destPort))
    print('Sequence Number: {}, Acknoledgement: {}'.format(seqNumber, ack))
    print('Offset: {}, Reserved: {}'.format(offset, reserved))
    print('Flags: {}, Reserved: {}'.format(offset, reserved))
    print('Window: {}, Checksum: {}, Urgent Pointer: {}'.format(window, checksum, urgentPointer))

    return (sourcePort | destPort) == 53, rawData[20:]


def analyze_UDP(rawData):
    udpHeader = struct.unpack('!4H', rawData[:8])
    sourcePort = udpHeader[0]
    destPort = udpHeader[1]
    length = udpHeader[2]
    checksum = udpHeader[3]

    print('###############   UDP   ###############')
    print('Source Port: {}, Destination Port: {}, length: {}, checksum: {}'.format(sourcePort, destPort, length, checksum))

    return (sourcePort | destPort) == 53, rawData[8:]

def analyze_DNS(rawData):

    print('###############   DNS   ###############')
    print('Not ready')

#### END analyze region ####

def format_IPv4Address(address):
    return '.'.join(map(str, address))

def format_MACAdress(address):
    return ':'.join(map('{:02x}'.format, address))

    
