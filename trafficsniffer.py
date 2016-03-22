#!/usr/bin/python

import socket
import struct
import binascii

# create Try and except statement to try create raw socket object if any except print error
try:
    rawSocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
except socket.error, msg:
    print 'Socket could be created. Error Code: ' + str(msg[0]) + ' Error Message: ' + msg[1]
# If the raw socket is created run the else code below
else:
    try:
        while(1):
            # variable to hold any packets recieved
            recvPkt = rawSocket.recvfrom(65565)
            
            # creating variable to hold the packets from each header, ethernet, ip, tcp, application
            ethernetHeader = recvPkt[0][0:14]
            ipHeader = recvPkt[0][14:34]
            tcpHeader = recvPkt[0][34:54]
            data = recvPkt[0][54: ]
            
            # Ethernet packet
            unpack_eth_hdr = struct.unpack("!6s6s2s", ethernetHeader)
            
            # converts string from to hex then stores in variable uf_dest_mac
            uf_dest_mac = binascii.hexlify(unpack_eth_hdr[0])
            
            # var formats uf_dest_mac from '00000000' to '00:00:00:00' how mac address would look
            dest_mac = ':'.join(uf_dest_mac[i:i+2] for i in range(0, len(uf_dest_mac), 2))
 
            # Source Mac Address
            uf_src_mac = binascii.hexlify(unpack_eth_hdr[1])
            
            # var formats uf_src_mac from '00000000' to '00:00:00:00' how mac address would look
            src_mac = ':'.join(uf_src_mac[i:i+2] for i in range(0, len(uf_src_mac), 2))
            
            # Protocol type
            ether_type = binascii.hexlify(unpack_eth_hdr[2])

            # IP Header
            unpack_ip_hdr = struct.unpack("!BBHHHBBH4s4s", ipHeader)
            
            # var Length of the packet in bytes
            ip_total_length = unpack_ip_hdr[2]
            
            # var holds the packets ID number which unique ID's a packet
            ip_id = unpack_ip_hdr[3]

            # var holds the packets time to live
            ip_ttl = unpack_ip_hdr[5]
            
            # var holds the protocol which will be either IPv4 or IPv6 depends on the traffic
            ip_protocol = unpack_ip_hdr[6]
            
            # var holds the sources IP Address such as Google 8.8.8.8
            ip_source = socket.inet_ntoa(unpack_ip_hdr[8])

            # var holds the destination IP Address which is mine. Example 127.0.0.4
            ip_destination = socket.inet_ntoa(unpack_ip_hdr[9])

            # TCP Header
            unpack_tcp_hdr = struct.unpack("!HHLLBBHHH", tcpHeader)

            # var holds the source port
            src_port = unpack_tcp_hdr[0]

            # var holds the destination port
            dest_port = unpack_tcp_hdr[1]

            # varibel holds sequence number which track how much data is sent
            sequenceNum = unpack_tcp_hdr[2]

            # variable holds ack or confirmation all prior byes were recieved 
            ack = unpack_tcp_hdr[3]

            # variable holds flags or confirmation from host it recieved TCP segment with ECE Flags
            flags = unpack_tcp_hdr[5]
            
            # variable window indicates maximum data your trying to recieve
            window = unpack_tcp_hdr[6]

            # variable holds check sum
            checkSum = unpack_tcp_hdr[7]

            # variable urgent pointer tells how bytes of data is urgent in the tcp segment to arrive
            urgentPointer = unpack_tcp_hdr[8]

            print '######################################'
            print 'Ethernet frame'
            print '\t - Destination Mac Address: %s \n\t - Source Mac Address: %s \n\t - Ether Type: %s' % (dest_mac, src_mac, ether_type)
            print 'ID Header:'
            print '\t - Total Length: %s ID: %s Time To Live: %s' % (ip_total_length, ip_id, ip_ttl)
            print '\t - Protocol: IPv%s Source IP: %s Destination IP: %s' % (ip_protocol, ip_source, ip_destination)
            print 'TCP Header:'
            print '\t - Source Port: %s Destination Port: %s Sequence #: %s' % (src_port, dest_port, sequenceNum)
            print '\t - ACK: %s Flags: %s Window: %s Check Sum: %s Urgent Pointer: %s ' % (ack, flags, window, checkSum, urgentPointer)
            print binascii.hexlify(data)
            print '#####################################'
            print ''

    except KeyboardInterrupt:
        print ' Interrupted sniffer exited'
    finally:
        print 'Done sniffing traffic'
