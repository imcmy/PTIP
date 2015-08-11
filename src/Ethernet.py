'''
Ethernet.py
Author: imcmy

API VARIABLE:
ETH_HEADER_LEN:            The length of the ethernet header including source
                           MAC address, destination MAC address and upper layer
                           protocol type.
ETH_PAYLOAD_MIN_LEN:       The minimum length of the ethernet paylod.
ETH_PAYLOAD_MAX_LEN:       The maximum length of the ethernet paylod, also known
                           as MTU.

ETH_TYPE:                  Dictionary containing the mapping of protocol and
                           corresponding number. And now it supports three
                           protocols: IPv4, IPv6 and ARP.

ETH_OK:                    Everything is OK!
ETH_ERR_HEADER:            Header length is not equal to ETH_HEADER_LEN.     
ETH_ERR_TYPE_NOT_FOUND:    Payload type is not supported!
ETH_ERR_PAYLOAD_OVERFLOW:  Payload length is greater than MTU.
'''

import scapy.all
import binascii
import struct

ETH_HEADER_LEN = 14
ETH_PAYLOAD_MIN_LEN = 46
ETH_PAYLOAD_MAX_LEN = 1500

ETH_TYPE = {'ipv4': b'\x08\x00', 'arp': b'\x08\x06', 'ipv6': b'\x86\xDD'}

ETH_OK = 0
ETH_ERR_HEADER = -1
ETH_ERR_TYPE_NOT_FOUND = -2
ETH_ERR_PAYLOAD_OVERFLOW = -3

class Ethernet(Object):
    '''
    Ehternet Module. The implementation of link layer protocol, Ethernet v2.
    The module is used for receiving the upper layer datagram, packing it and
    sending it out.
    Use Scapy to send ethernet frame TEMPORARY!

    eth = Ethernet(src_addr, dest_addr, type, payload)
    eth.send()

    ARGS:
        src_addr:  MAC address of the sender.
        dest_addr: MAC address of the next receiver, usually the gateway.
        type:      Payload type.
        payload:   Already packed payload.
    '''

    self.pkt_format_template = '!6s6s2s%ds%dx4s'


    def __init__(self, src_addr, dest_addr, type, payload):
        self.src_addr = bytes(src_addr)
        self.dest_addr = bytes(dest_addr)
        self.type = type
        self.payload = payload


    def pre_format(self):
        '''
        Check the type and the length of the palyload.
        Calculate the padding length, filling the format template.

        RETURN:
            The check and preformat result.

            If the header length is not equal to ETH_HEADER_LEN, return
                ETH_ERR_HEADER.
            If the passed type is not IPv4, IPv6 or ARP, return
                ETH_ERR_TYPE_NOT_FOUND.
            If the passed payload length is greater than MTU, return
                ETH_ERR_PAYLOAD_OVERFLOW.
            Everything goes right, return
                ETH_OK.
        '''

        if len(self.src_addr)  + len(self.dest_addr) + len(self.type)
            != ETH_HEADER_LEN:
            return ETH_ERR_HEADER

        if self.type not in ETH_TYPE.values():
            return ETH_ERR_TYPE_NOT_FOUND

        payload_len = len(self.payload)
        if payload_len > ETH_PAYLOAD_MAX_LEN:
            return ETH_ERR_PAYLOAD_OVERFLOW

        padding_len = max(0, ETH_PAYLOAD_MIN_LEN - payload_len)
        self.pkt_format = self.pkt_format_template % (payload_len, padding_len)
        return ETH_OK


    def send(self):
        '''
        Send out the ethernet frame.
        First check and pre format the frame payload, and then calculate the CRC
        of the frame.
        Use struct to pack all the data, and use scapy to send it out.
        '''
        pre_format_res = self.pre_format()
        if pre_format_res != ETH_OK:
            return pre_format
        
        self.frame = self.src_addr + self.dest_addr + self.type + self.payload
        crc = binascii.crc32(self.frame) & 0xffffffff

        pkg = struct.pack(self.pkg_format, self.src_addr, self.dest_addr,
            self.type, self.payload, crc)

        scapy.all.sendp(pkg)