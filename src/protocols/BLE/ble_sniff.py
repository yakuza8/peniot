import os
import sys
import time

from Utils import CommonUtil
from protocols.BLE.Adafruit_BLESniffer import sniffer
from protocols.BLE.Adafruit_BLESniffer.SnifferAPI import CaptureFiles


class BLESniffer:
    stopped_flag = False
    serial_port = None

    def __init__(self, serial_portt):

        self.stopped_flag = False
        # store the captured packets
        PATH_TO_FILE = BLESniffer.create_file_name()

        # Instantiate the command line argument parser
        sniffer.argparser = sniffer.argparse.ArgumentParser(
            description="Interacts with the Bluefruit LE Friend Sniffer firmware")

        # Parser the arguments passed in from the command-line
        sniffer.args = sniffer.argparser.parse_args()
        sniffer.args.verbose = False

        print("Capturing data to " + PATH_TO_FILE)
        CaptureFiles.captureFilePath = PATH_TO_FILE

        self.serial_port = serial_portt

    def run(self):
        # Try to open the serial port
        try:
            sniffer.setup(self.serial_port)
        except OSError:
            # pySerial returns an OSError if an invalid port is supplied
            print("Unable to open serial port '" + self.serial_port + "'")
            sys.exit(-1)
        except KeyboardInterrupt:
            sys.exit(-1)

        # Scan for devices in range until the user makes a selection
        try:
            d = None

            # loop will be skipped if a target device is specified on commandline
            while d is None:
                if self.stopped_flag is True:
                    break

                print("Scanning for BLE devices (5s) ...")
                devlist = sniffer.scanForDevices()
                if len(devlist):
                    # Select a device
                    d = sniffer.selectDevice(devlist)
                    print d

            if self.stopped_flag is True:
                d = None
            else:
                # Start sniffing the selected device
                print("Attempting to follow device {0}:{1}:{2}:{3}:{4}:{5}".format("%02X" % d.address[0],
                                                                                   "%02X" % d.address[1],
                                                                                   "%02X" % d.address[2],
                                                                                   "%02X" % d.address[3],
                                                                                   "%02X" % d.address[4],
                                                                                   "%02X" % d.address[5]))
            # Make sure we actually followed the selected device (i.e. it's still available, etc.)
            if d is not None:
                sniffer.mySniffer.follow(d)
            else:
                if self.stopped_flag is False:
                    print("ERROR: Could not find the selected device")

            # Dump packets
            while (self.stopped_flag is False) and (d is not None):  # Dogukan
                sniffer.dumpPackets()
                time.sleep(1)

            # Close gracefully
            sniffer.mySniffer.doExit()
            sys.exit()

        except (KeyboardInterrupt, ValueError, IndexError) as e:
            # Close gracefully on CTRL+C
            if 'KeyboardInterrupt' not in str(type(e)):
                print("Caught exception:", e)
            sniffer.mySniffer.doExit()
            sys.exit(-1)

    def stop_attack(self):
        self.stopped_flag = True
        print("BLE sniffing attack has been terminated")
        time.sleep(2)  # Sleep two seconds so the user can see the message

    @staticmethod
    def create_file_name():
        # store the captured packets
        return os.path.dirname(os.path.abspath(
            __file__)) + "/../../captured_packets/BLE_" + CommonUtil.get_current_datetime_for_filename_format() + ".pcap"
