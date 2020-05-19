import socket
import struct


def main():
    # create a raw socket and bind it to the public interface
    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.htons(0x0800))

    print("Sniffer started please introduce number of packages you wan to capture")
    print("Number of packages: ", end="")
    packages_number = int(input())

    for i in range(packages_number):
        print('############### {} Package ###############'.format(i))
        raw_data = raw_socket.recvfrom(65535)
        ether_protocol, ether_data = analyze_ethernet(raw_data)

        if ether_protocol == 8:
            ip_protocol, ip_data = analyze_ip(ether_data)

            if ip_protocol == 1:
                analyze_icmp(ip_data)

            if ip_protocol == 6:
                analyze_tcp(ip_data)

            if ip_protocol == 17:
                dns, udp_data = analyze_udp(ip_data)

                if dns:
                    analyze_dns(udp_data)


def analyze_ethernet(raw_data):
    ethernet_header = struct.unpack("!6s6sH", raw_data[:14])
    dest_mac = ethernet_header[0]
    sour_mac = ethernet_header[1]
    protocol = ethernet_header[2] >> 8

    print('############### ETHERNET ###############')
    print('Destination MAC: {}, Source MAC: {}, Protocol: {}'.format(dest_mac, sour_mac, protocol))

    return protocol, raw_data[14:]


def analyze_ip(raw_data):
    ip_header = struct.unpack("!2B 3H 2B H 2L", raw_data[:20])
    version = ip_header[0] >> 4
    ihl = ip_header[0] & 0xF
    tos = ip_header[1]
    total_length = ip_header[2]
    identity = ip_header[3]
    no_frag_flag = ip_header[4] & 0x8000
    more_frag = ip_header[4] & 0x4000
    frag_offset = ip_header[4] & 0x1FFF
    ttl = ip_header[5]
    protocol = ip_header[6]
    checksum = ip_header[7]
    sour_address = format_ipv4_address(ip_header[8])
    dest_address = format_ipv4_address(ip_header[9])

    print('###############    IP    ###############')
    print('Version: {}, IHL: {}, ToS: {}, Total Length: {}'.format(version, ihl, tos, total_length))
    print('Identity: {}, Fragment Flag: {}, More Fragments Flag: {}, Fragment Offset: {}'.format(identity, no_frag_flag,
                                                                                                 more_frag,
                                                                                                 frag_offset))
    print('TTL: {}, Protocol: {}, Checksum: {}'.format(ttl, protocol, checksum))
    print('Source Address: ', sour_address)
    print('Destination Address: ', dest_address)

    return protocol, raw_data[20:]


def analyze_icmp(raw_data):
    icmp_type, code, checksum = struct.unpack('! 2B H', raw_data[:4])
    print('###############   ICMP   ###############')
    print('type: {}, code: {}, checksum: {}'.format(icmp_type, code, checksum))


def analyze_tcp(raw_data):
    tcp_header = struct.unpack('! 2H 2L 4H', raw_data[:20])
    source_port = tcp_header[0]
    dest_port = tcp_header[1]
    seq_number = tcp_header[2]
    ack = tcp_header[3]
    offset = tcp_header[4] & 0xF000
    reserved = tcp_header[4] & 0xE00
    ns_flag = tcp_header[4] & 0x100
    cwr_flag = tcp_header[4] & 0x80
    ece_flag = tcp_header[4] & 0x40
    urg_flag = tcp_header[4] & 0x20
    ack_flag = tcp_header[4] & 0x10
    psh_flag = tcp_header[4] & 0x8
    rst_flag = tcp_header[4] & 0x4
    syn_flag = tcp_header[4] & 0x2
    fin_flag = tcp_header[4] & 0x1
    window = tcp_header[5]
    checksum = tcp_header[6]
    urgent_pointer = tcp_header[7]

    print('###############   TCP   ###############')
    print('Source Port: {}, Destination Port: {}'.format(source_port, dest_port))
    print('Sequence Number: {}, Acknoledgement: {}'.format(seq_number, ack))
    print('Offset: {}, Reserved: {}'.format(offset, reserved))
    print('Flags: {}'.format(ns_flag, cwr_flag, ece_flag, urg_flag, ack_flag, psh_flag, rst_flag, syn_flag, fin_flag))
    print('Window: {}, Checksum: {}, Urgent Pointer: {}'.format(window, checksum, urgent_pointer))

    return (source_port | dest_port) == 53, raw_data[20:]


def analyze_udp(raw_data):
    udp_header = struct.unpack('!4H', raw_data[:8])
    source_port = udp_header[0]
    dest_port = udp_header[1]
    length = udp_header[2]
    checksum = udp_header[3]

    print('###############   UDP   ###############')
    print('Source Port: {}, Destination Port: {}, length: {}, checksum: {}'.format(source_port, dest_port, length,
                                                                                   checksum))

    return (source_port | dest_port) == 53, raw_data[8:]


def analyze_dns(raw_data):
    dns_header = struct.unpack('!6H', raw_data[:12])
    ident = dns_header[0]
    qr = dns_header[1] & 0x8000
    op_code = dns_header[1] & 0x7800
    aa_flag = dns_header[1] & 0x0400
    tc_flag = dns_header[1] & 0x0200
    rd_flag = dns_header[1] & 0x0100
    ra_flag = dns_header[1] & 0x0080
    z_flag = dns_header[1] & 0x0040
    ad_flag = dns_header[1] & 0x0020
    cd_flag = dns_header[1] & 0x0001
    rcode = dns_header[1] & 0xF
    total_quest = dns_header[2]
    total_ans = dns_header[3]
    authority = dns_header[4]

    print('###############   DNS   ###############')
    print('Identity: ', ident)
    print('Questions: ', total_quest)
    print('Flags: {}'.format(qr, op_code, aa_flag, tc_flag, rd_flag, ra_flag, z_flag, ad_flag, cd_flag, rcode))
    print('Answers: ', total_ans)
    print('Authority: ', authority)


def format_ipv4_address(address):
    return '.'.join(map(str, address))


def format_mac_address(address):
    return ':'.join(map('{:02x}'.format, address))


if __name__ == '__main__':
    main()
