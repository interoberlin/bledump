#!/usr/bin/python
#
# Bluetooth Low Energy packet sniffing script
#
# Reads incoming packets on a serial port
# from a nRF51822-based USB dongle and
# outputs them in PCAP-format to a FIFO,
# which in turn is read by Wireshark.
#
# Authors:
#    Matthijs Kooijman <matthijs@stdin.nl>
#    Matthias Bock <mail@matthiasbock.net>
#
# License: GNU GPLv3
#

import os
import sys
import time
import errno
import serial
import struct
import select
import binascii
import datetime
import argparse

class Formatter:
    def __init__(self, out):
        self.out = out

    def fileno(self):
        return self.out.fileno()

    def close(self):
        self.out.close()

class PcapFormatter(Formatter):
    def write_header(self):
        self.out.write(struct.pack("=IHHiIII",
            0xa1b2c3d4,   # magic number
            2,            # major version number
            4,            # minor version number
            0,            # GMT to local correction
            0,            # accuracy of timestamps
            65535,        # max length of captured packets, in octets
            195,          # data link type (DLT) - IEEE 802.15.4
        ))
        self.out.flush()

    def write_packet(self, data):
        now = datetime.datetime.now()
        timestamp = int(time.mktime(now.timetuple()))
        self.out.write(struct.pack("=IIII",
            timestamp,        # timestamp seconds
            now.microsecond,  # timestamp microseconds
            len(data),        # number of octets of packet saved in file
            len(data),        # actual length of packet
        ))
        self.out.write(data)
        self.out.flush()

class HumanFormatter(Formatter):
    def write_header(self):
        pass

    def write_packet(self, data):
        self.out.write(binascii.hexlify(data).decode())
        self.out.write("\n")
        self.out.flush()

def open_fifo(options, name):
    try:
        os.mkfifo(name);
    except FileExistsError:
        pass
    except:
        raise

    if not options.quiet:
        print("Waiting for fifo to be openend...")
    # This blocks until the other side of the fifo is opened
    return open(name, 'wb')

def setup_output(options):
    if options.fifo:
        return PcapFormatter(open_fifo(options, options.fifo))
    elif options.write_file:
        return PcapFormatter(open(options.write_file, 'wb'))
    else:
        return HumanFormatter(sys.stdout)

def main():
    parser = argparse.ArgumentParser(description='Convert 802.15.4 packets read from a serial port into pcap format')
    parser.add_argument('port',
                        help='The serial port to read from')
    parser.add_argument('-b', '--baudrate', default=115200, type=int,
                        help='The baudrate to use for the serial port (defaults to %(default)s)')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='Do not output any informational messages')
    parser.add_argument('-d', '--send-init-delay', type=int, default=2,
                        help='Wait for this many seconds between opening the serial port and sending the init string (defaults to %(default)s)')
    parser.add_argument('-s', '--send-init', type=bytes, default=b'module.enable("sniffer"); sniffer.start(1);\r\n',
                        help='Send the given string over serial to enable capture mode (defaults to %(default)s)')
    parser.add_argument('-r', '--read-init', type=bytes,
                        help='Wait until the given string is read from serial before starting capture (defaults to %(default)s)')
    output = parser.add_mutually_exclusive_group()
    output.add_argument('-F', '--fifo',
                        help='Write output to a fifo instead of stdout. The fifo is created if needed and capturing does not start until the other side of the fifo is opened.')
    output.add_argument('-w', '--write-file',
                        help='Write output to a file instead of stdout')

    options = parser.parse_args();

    try:
        # If the fifo got closed, just start over again
        while True:
            do_sniff_once(options)
    except KeyboardInterrupt:
        pass

def do_sniff_once(options):
    # This might block until the other side of the fifo is opened
    out = setup_output(options)
    out.write_header()

    ser = serial.Serial(options.port, options.baudrate)
    print("Opened {} at {}".format(options.port, options.baudrate))

    if options.send_init_delay:
        if not options.quiet:
            print("Waiting for {} second{}".format(options.send_init_delay, 's' if options.send_init_delay != 1 else ''))
        time.sleep(options.send_init_delay)

    if (options.send_init):
        if not options.quiet:
            print("Sending: {}".format(options.send_init))
        ser.write(options.send_init)

    if (options.read_init):
        if not options.quiet:
            print("Waiting to read: {}".format(options.read_init))
        read = ser.read(len(options.read_init))
        while True:
            if read == options.read_init:
                break
            read = read[1:] + ser.read()

    if not options.quiet:
        print("Waiting for packets...")

    count = 0
    poll = select.poll()
    # Wait to read data from serial, or until the fifo is closed
    poll.register(ser, select.POLLIN)
    poll.register(out, select.POLLERR)

    while True:
        # Wait for something to do
        events = poll.poll()

        fds = [fd for (fd, evt) in events]
        if out.fileno() in fds:
            # Error on output, e.g. fifo closed on the other end
            break
        elif ser.fileno() in fds:
            # read from serial port until newline character is received
            data = ser.read()[0]
            c = " "
            while c != "\n":
                c = ser.read()[0]
                if c != "\r" and ord(c) >= 20 and ord(c) < 126:
                    # Only append human readable characters to capture.
                    # Other chars are transmission errors.
                    data += c
            
            # a packet line is a hex dump split with vertical lines
            if (data.find("|") == -1):
                print("Received something, but wasn't a packet.")
            else:
                # one more packet received
                print("Packet received:")
                count += 1

                # re-assemble hexdump of original on-air packet                
                parts = data.split("|")
                if len(parts) > 5:
                    del parts[5] # "OK"
                if len(parts) > 2:
                    del parts[2] # "MISS"
                whole = "".join(parts).replace("  "," ")
                print(whole)

                # write packet to FIFO                
#                data = hexdump2binary(whole)
#                try:
#                    # write packet to FIFO
#                    out.write_packet(data)
#                except OSError as e:
#                    # SIGPIPE indicates the fifo was closed
#                    if e.errno == errno.SIGPIPE:
#                        print("FIFO was closed.")
#                        break
                
    ser.close()
    out.close()

    if not options.quiet:
        print("Captured {} packet{}".format(count, 's' if count != 1 else ''))

if __name__ == '__main__':
    main()
