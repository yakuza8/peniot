from __future__ import absolute_import
from __future__ import print_function
from six.moves import input

from protocols.BLE.Adafruit_BLESniffer.SnifferAPI import CaptureFiles, Sniffer
from protocols.BLE.Adafruit_BLESniffer.SnifferAPI.Devices import Device

__author__ = "ktown"
__copyright__ = "Copyright Adafruit Industries 2014 (adafruit.com)"
__license__ = "MIT"
__version__ = "0.1.0"

import os
import sys
import time
import argparse



mySniffer = None
"""@type: SnifferAPI.Sniffer.Sniffer"""


def setup(serport, delay=6):
    """
    Tries to connect to and initialize the sniffer using the specific serial port
    @param serport: The name of the serial port to connect to ("COM14", "/dev/tty.usbmodem1412311", etc.)
    @type serport: str
    @param delay: Time to wait for the UART connection to be established (in seconds)
    @param delay: int
    """
    global mySniffer

    # Initialize the device on the specified serial port
    print("Connecting to sniffer on " + serport)
    mySniffer = Sniffer.Sniffer(serport)
    # Start the sniffer
    mySniffer.start()
    # Wait a bit for the connection to initialise
    time.sleep(delay)


def scanForDevices(scantime=5):
    """
    @param scantime: The time (in seconds) to scan for BLE devices in range
    @type scantime: float
    @return: A DeviceList of any devices found during the scanning process
    @rtype: DeviceList
    """
    if args.verbose:
        print("Starting BLE device scan ({0} seconds)".format(str(scantime)))

    mySniffer.scan()
    time.sleep(scantime)
    devs = mySniffer.getDevices()
    return devs


def selectDevice(devlist):
    """
    Attempts to select a specific Device from the supplied DeviceList
    @param devlist: The full DeviceList that will be used to select a target Device from
    @type devlist: DeviceList
    @return: A Device object if a selection was made, otherwise None
    @rtype: Device
    """
    count = 0

    if len(devlist):
        print("Found {0} BLE devices:\n".format(str(len(devlist))))
        # Display a list of devices, sorting them by index number
        for d in devlist.asList():
            """@type : Device"""
            count += 1
            print("  [{0}] {1} ({2}:{3}:{4}:{5}:{6}:{7}, RSSI = {8})".format(count, d.name,
                                                                             "%02X" % d.address[0],
                                                                             "%02X" % d.address[1],
                                                                             "%02X" % d.address[2],
                                                                             "%02X" % d.address[3],
                                                                             "%02X" % d.address[4],
                                                                             "%02X" % d.address[5],
                                                                             d.RSSI))
        try:
            i = int(input("\nSelect a device to sniff, or '0' to scan again\n> "))
        except KeyboardInterrupt:
            raise KeyboardInterrupt
            return None
        except:
            return None

        # Select a device or scan again, depending on the input
        if (i > 0) and (i <= count):
            # Select the indicated device
            return devlist.find(i - 1)
        else:
            # This will start a new scan
            return None


def dumpPackets():
    """Dumps incoming packets to the display"""
    # Get (pop) unprocessed BLE packets.
    packets = mySniffer.getPackets()
    # Display the packets on the screen in verbose mode
    if args.verbose:
        for packet in packets:
            if packet.blePacket is not None:
                # Display the raw BLE packet payload
                # Note: 'BlePacket' is nested inside the higher level 'Packet' wrapper class
                print(packet.blePacket.payload)
            else:
                print(packet)
    else:
        print('.' * len(packets))


if __name__ == '__main__':
    """Main program execution point"""

    # Instantiate the command line argument parser
    argparser = argparse.ArgumentParser(
        description="Interacts with the Bluefruit LE Friend Sniffer firmware")

    # Add the individual arguments
    # Mandatory arguments:
    argparser.add_argument("serialport",
                           help="serial port location ('COM14', '/dev/tty.usbserial-DN009WNO', etc.)")

    # Optional arguments:
    argparser.add_argument("-l", "--logfile",
                           dest="logfile",
                           default=CaptureFiles.captureFilePath,
                           help="log packets to file, default: " + CaptureFiles.captureFilePath)

    argparser.add_argument("-t", "--target",
                           dest="target",
                           help="target device address")

    argparser.add_argument("-r", "--random_txaddr",
                           dest="txaddr",
                           action="store_true",
                           default=False,
                           help="Target device is using random address")

    argparser.add_argument("-v", "--verbose",
                           dest="verbose",
                           action="store_true",
                           default=False,
                           help="verbose mode (all serial traffic is displayed)")

    # Parser the arguments passed in from the command-line
    args = argparser.parse_args()

    # Display the libpcap logfile location
    print("Capturing data to " + args.logfile)
    CaptureFiles.captureFilePath = args.logfile

    # Try to open the serial port
    try:
        setup(args.serialport)
    except OSError:
        # pySerial returns an OSError if an invalid port is supplied
        print("Unable to open serial port '" + args.serialport + "'")
        sys.exit(-1)
    except KeyboardInterrupt:
        sys.exit(-1)

    # Optionally display some information about the sniffer
    if args.verbose:
        print("Sniffer Firmware Version: " + str(mySniffer.swversion))

    # Scan for devices in range until the user makes a selection
    try:
        d = None
        """@type: Device"""
        if args.target:
            print("specified target device", args.target)
            _mac = [int(x, 16) for x in args.target.split(':')]
            if len(_mac) != 6:
                raise ValueError("Invalid device address")
            # -72 seems reasonable for a target device right next to the sniffer
            d = Device(_mac, name="NoDeviceName", RSSI=-72, txAdd=args.txaddr)

        # loop will be skipped if a target device is specified on commandline
        while d is None:
            print("Scanning for BLE devices (5s) ...")
            devlist = scanForDevices()
            if len(devlist):
                # Select a device
                d = selectDevice(devlist)

        # Start sniffing the selected device
        print("Attempting to follow device {0}:{1}:{2}:{3}:{4}:{5}".format("%02X" % d.address[0],
                                                                           "%02X" % d.address[1],
                                                                           "%02X" % d.address[2],
                                                                           "%02X" % d.address[3],
                                                                           "%02X" % d.address[4],
                                                                           "%02X" % d.address[5]))
        # Make sure we actually followed the selected device (i.e. it's still available, etc.)
        if d is not None:
            mySniffer.follow(d)
        else:
            print("ERROR: Could not find the selected device")

        # Dump packets
        while True:
            dumpPackets()
            time.sleep(1)

        # Close gracefully
        mySniffer.doExit()
        sys.exit()

    except (KeyboardInterrupt, ValueError, IndexError) as e:
        # Close gracefully on CTRL+C
        if 'KeyboardInterrupt' not in str(type(e)):
            print("Caught exception:", e)
        mySniffer.doExit()
        sys.exit(-1)
