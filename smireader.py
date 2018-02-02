#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import struct
from datetime import datetime
from math import ceil
import argparse
import logging

gsm = ("@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞ\x1bÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ`¿abcdefghijklmnopqrstuvwxyzäöñüà")

class SmiFile(object):

    SMI_VERSION_SL4X, SMI_VERSION_X55, SMI_VERSION_X65 = range(3)
    SMS_TYPE_RECEIVED = 0; SMS_TYPE_SENT = 3
    SMS_STATUS_READ, SMS_STATUS_UNREAD, SMS_STATUS_SENT, SMS_STATUS_UNSENT = range(4)

    def __init__(self, file):
        logging.debug("Reading smi/smo file")
        # Detect version based on signature
        self.signature = struct.unpack("ccccc", file.read(5))
        if self.signature == (b'\x0b', b'\x0b', b'\x00', b'\x00', b'\x00'):
            self.version = self.SMI_VERSION_SL4X
            logging.debug("Version detected: SL4X")
        elif self.signature == (b'\x0b', b'\x0b', b'\x01', b'\x01', b'\x00'):
            self.version = self.SMI_VERSION_X55
            logging.debug("Version detected: X55")
        elif self.signature == (b'\x0b', b'\x0b', b'\x02', b'\x0c', b'\x00'):
            self.version = self.SMI_VERSION_X65
            logging.debug("Version detected: X65")
        else:
            logging.error("Unknown signature found or version not supported.")
            raise ValueError('Unknown signature found', self.signature)

        # Skip some fields that aren't present if handling SL4X version        
        if self.version != self.SMI_VERSION_SL4X:
            # Number of parts
            self.parts_expected = struct.unpack("B", file.read(1))[0]
            logging.debug("Expected parts: {}".format(self.parts_expected))
            self.parts_stored = struct.unpack("B", file.read(1))[0]
            logging.debug("Stored parts: {}".format(self.parts_stored))
            if self.parts_expected != self.parts_stored:
                logging.warning("Warning, the file has missing parts ({0} of {1} parts available)".format(
                    self.parts_stored,
                    self.parts_expected,
                ))
            
            # SMS type
            self.sms_type = struct.unpack("B", file.read(1))[0]
            logging.debug("SMS type: {}".format(self.sms_type))
            if self.sms_type not in [self.SMS_TYPE_RECEIVED, self.SMS_TYPE_SENT]:
                logging.error("Unknown SMS type detected")
                raise ValueError('Unknown SMS type detected', self.sms_type)
            
            # SMS status
            self.sms_status = struct.unpack("B", file.read(1))[0]
            logging.debug("SMS status: {}".format(self.sms_status))
            if self.sms_status not in [0,1,3,4]:
                logging.error("Unknown SMS status detected")
                raise ValueError('Unknown SMS status detected', self.sms_status)

            #Timestamp
            self.timestamp = Timestamp(file)
        else:
            self.parts_stored = 1 # No multipart support in this version of file
        
        if self.version == self.SMI_VERSION_X65:
            file.read(1) # Drop waste byte
            logging.debug("Dropped waste byte")

        # Read all the segments
        self.segments = [SmsSegment(file) for _ in range(self.parts_stored)]

class SmsSegment(object):
    
    SMS_STATUS_READ, SMS_STATUS_UNREAD, SMS_STATUS_SENT, SMS_STATUS_UNSENT = range(4)
    SMS_TYPE_SENT, SMS_TYPE_RECEIVED = range(2)
    SMS_VPFT_RELATIVE, SMS_VPFT_ENHACED, SMS_VPFT_ABSOLUTE = range(3)
    
    def __init__(self, file):
        logging.debug("Reading segment")
        # SMS segment status
        status = struct.unpack("B", file.read(1))[0]
        bytes_read = 1
        logging.debug("Segment status: {}".format(status))
        if status == 1: self.status = self.SMS_STATUS_READ
        elif status == 3: self.status = self.SMS_STATUS_UNREAD
        elif status == 5: self.status = self.SMS_STATUS_SENT
        elif status == 7: self.status = self.SMS_STATUS_UNSENT
        else:
            raise ValueError('Unknown segment status detected', status)
        
        # SMSC address
        self.smsc_address = Address(file, smsc=True)
        bytes_read += self.smsc_address.bytes

        # First octet
        self.first_octet = struct.unpack("B", file.read(1))[0]
        bytes_read += 1
        if (self.first_octet & 3):
            self.segment_type = self.SMS_TYPE_SENT
            logging.debug("Segment type: Sent")
        else:
            self.segment_type = self.SMS_TYPE_RECEIVED
            logging.debug("Segment type: Received")

        if self.segment_type == self.SMS_TYPE_SENT:
            vpf = self.first_octet & 24 # bits 4,3
            if vpf == 0:
                self.vp_present = False
                self.vp_length = 0
                logging.debug("Validity period not present in segment")
            else:
                if vpf == 16:
                    self.vp_format = self.SMS_VPFT_RELATIVE
                    self.vp_length = 1
                    logging.debug("Segment validity period defined in relative format.")
                if vpf == 8:
                    self.vp_format = self.SMS_VPFT_ENHACED
                    self.vp_length = 7
                    logging.debug("Segment validity period defined in enhanced format.")
                if vpf == 24:
                    self.vp_format = self.SMS_VPFT_ABSOLUTE
                    self.vp_length = 7
                    logging.debug("Segment validity period defined in absolute format.")
                self.vp_present = True

            self.tp_message_reference = struct.unpack("B", file.read(1))[0]
            bytes_read += 1
            logging.debug("TP message reference byte read")

        # sender/receiver address
        self.address = Address(file, smsc=False)
        bytes_read += self.address.bytes

        # Protocol / coding scheme 
        self.protocol_identifier = struct.unpack("B", file.read(1))[0]
        logging.debug("Segment protocol identifier: {}".format(self.protocol_identifier))
        self.data_coding_scheme = struct.unpack("B", file.read(1))[0]
        logging.debug("Segment data coding scheme: {}".format(self.data_coding_scheme))
        bytes_read += 2

        # Validity period TODO: parse this
        if self.segment_type == self.SMS_TYPE_SENT and  self.vp_present:
            self.validity = struct.unpack(
                "B" * self.vp_length, 
                file.read(self.vp_length))
            bytes_read += self.vp_length
            logging.debug("Segment validity period header read ({} bytes)".format(self.vp_length))

        # Timestamp
        if self.segment_type == self.SMS_TYPE_RECEIVED:
            self.timestamp = Timestamp(file)
            bytes_read += self.timestamp.bytes

        # User data length
        self.udl = struct.unpack("B", file.read(1))[0]
        bytes_read += 1
        logging.debug("Segment user data length: {}".format(self.udl))

        
        binary = []
        for _ in range(176 - bytes_read): # SMI files have PDUs padded to 176 bytes
            byte = file.read(1)
            if byte == b'':
                logging.error("Unexpected EOF while reading segment")
                raise IOError("Unexpected EOF while reading segment!")
            if byte != b'\xff': # if not padding
                binary.insert(0, "{:08b}".format(ord(byte)))
        pdu_bin = ''.join(binary)
        pdu_bin = pdu_bin[(len(pdu_bin)%7):] # drop extra bits
        pdu_txt = []
        for septet in zip(*[iter(pdu_bin)]*7):
            pdu_txt.append(
                gsm[(int(''.join(septet),2))]
            )
        pdu_txt.reverse()
        self.text = "".join(pdu_txt)

class Address(object):
    def __init__(self, file, smsc=True):
        address_length = struct.unpack("B", file.read(1))[0]
        logging.debug("Reading address{} (length: {})".format(
            " of SMSC" if smsc else "",
            address_length))
        if address_length:
            address_type = struct.unpack("B", file.read(1))[0]
            logging.debug("Address type: {}".format(address_type))
            address_prefix = ""
            if smsc:
                address_length -= 1
            else:
                address_length = int(address_length/2) + address_length % 2
                if address_type == 145:
                    address_prefix = "+"
                elif address_type == 161:
                    address_prefix = "0" #TODO: Not sure actually

            number = [
                "{:02X}".format(x)[::-1] for x in 
                struct.unpack("B"*address_length, file.read(address_length))
            ]
            self.type = address_type
            self.prefix = address_prefix
            self.address = "".join(map(str,number))
            logging.debug("Address address part: {}".format(self.address))
            self.bytes = address_length + 2
        else: # zero length address
            logging.warning("Zero length address")
            self.bytes = 1
        self.smsc = smsc

class Timestamp(object):
    def __init__(self, file):
        (year, month, day, hour, minute, second, offset) = (
            (x & 15) * 10 + (x >> 4) for x in struct.unpack("BBBBBBB", file.read(7)))

        logging.debug("Reading raw timestamp year:{}, month:{}, day:{}, hour:{}, minute:{}, second:{}, offset:{}".format(
            year, month, day, hour, minute, second, offset
        ))
        
        if year == month == day == hour == minute == second == offset == 0: # timestamp null
            logging.warning("Zero timestamp")
        else:
            if year < 1980:
                year += 2000
                logging.debug("Pre-1980 year correction")
            if offset > 127:
                offset = - (offset & 127)
            self.timestamp = datetime(year, month, day, hour, minute, second)
            self.gmt_offset = offset / 4
        self.bytes = 7

def main():
    parser = argparse.ArgumentParser(
        description='Read data from Siemens SMI and SMO files.')
    parser.add_argument("-d", "--detailed",
        help="Show message with details. (alias for -mnt)",
        action="store_true")
    parser.add_argument("-m", "--message",
        help="Show message text.",
        action="store_true")
    parser.add_argument("-n", "--number",
        help="Show message sender/receiver number.",
        action="store_true")
    parser.add_argument("-t", "--time",
        help="Show message date and time.",
        action="store_true")
    parser.add_argument('-v', '--verbose',
        default=0,
        help="Increase verbosity.",
        action='count')
    parser.add_argument("file",
        help="File to read (*.smi and *.smo are supported)")
    args = parser.parse_args()

    log = logging.getLogger()
    log.setLevel([
        logging.ERROR,
        logging.WARNING,
        logging.INFO,
        logging.DEBUG,
        ][min(args.verbose, 3)])

    smi_file = SmiFile(open(args.file,mode='rb'))

    if args.time or args.detailed:
        if hasattr(smi_file.segments[0], 'timestamp'):
            timestamp = smi_file.segments[0].timestamp
            print("{date} (GMT{offset:+g})".format(
                date = timestamp.timestamp.isoformat(sep=' '),
                offset = timestamp.gmt_offset,
                ))
        else:
            print("??????")
    if args.number or args.detailed:
        address = smi_file.segments[0].address
        print("{prefix}{address}".format(
            prefix = getattr(address, 'prefix', "??? "),
            address = getattr(address, 'address', "?????????"),
            ))
    if args.message or args.detailed:
        for segment in smi_file.segments:
            print(segment.text)

if __name__ == "__main__":
    main()
