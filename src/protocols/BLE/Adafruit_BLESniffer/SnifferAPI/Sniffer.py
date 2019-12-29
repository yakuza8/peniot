from __future__ import absolute_import
import sys
import os
import threading
import logging
from . import SnifferCollector
from . import Logger, Version


def initLog():
    Logger.initLogger()

    logging.info("--------------------------------------------------------")
    logging.info("Software version: " + Version.getReadableVersionString(Version.getRevision()))


initLog()


class Sniffer(threading.Thread, SnifferCollector.SnifferCollector):

    # Sniffer constructor. portnum argument is optional. If not provided,
    # the software will try to locate the firwmare automatically (may take time).
    # NOTE: portnum is 0-indexed, while Windows names are 1-indexed
    def __init__(self, portnum=None):
        threading.Thread.__init__(self)
        SnifferCollector.SnifferCollector.__init__(self, portnum)
        self.daemon = True

        self.subscribe("COMPORT_FOUND", self.comPortFound)

    # API STARTS HERE

    # Get [number] number of packets since last fetch (-1 means all)
    # Note that the packet buffer is limited to about 80000 packets.
    # Returns: A list of Packet objects
    def getPackets(self, number=-1):
        return self._getPackets(number)

    # Get a list of devices which are advertising in range of the Sniffer.
    # Returns: A DeviceList object.
    def getDevices(self):
        return self._devices

    # Signal the Sniffer firmware to sniff a specific device.
    # "device" argument is of type Device
    # if "followOnlyAdvertisements" is True the sniffer will not follow the device into a connection.  # noqa: E501
    # Returns nothing
    def follow(self, device=None, followOnlyAdvertisements=False):
        self._startFollowing(device, followOnlyAdvertisements)

    # Signal the Sniffer to scan for advertising devices by sending the REQ_SCAN_CONT UART packet.
    # This will cause it to stop sniffing any device it is sniffing at the moment.
    # Returns nothing.
    def scan(self):
        self._startScanning()

    # Send a temporary key to the sniffer to use when decrypting encrypted communication.
    # Returns nothing.
    def sendTK(self, TK):
        self._packetReader.sendTK(TK)

    # Set the preset COM port number. Only use this during startup. Set to None to search all ports.
    # Returns nothing.
    def setPortnum(self, portnum):
        self._portnum = portnum
        self._packetReader.portnum = portnum

    # Set the order in which the sniffer cycles through adv channels when following a device.
    # hopSequence must be a list of length 1, 2, or 3, and each item must be either 37, 38, or 39.
    # The same channel cannot occur more than once in the list.
    # Returns nothing.
    def setAdvHopSequence(self, hopSequence):
        self._packetReader.sendHopSequence(hopSequence)

    # Gracefully shut down the sniffer threads and connections.
    # Returns nothing.
    def doExit(self):
        return self._doExit()

    # NOTE: Methods with decorator @property can be used as (read-only) properties
    # Example: mMissedPackets = sniffer.missedPackets

    # The number of missed packets over the UART, as determined by the packet counter in the header.
    @property
    def missedPackets(self):
        return self._missedPackets

    # The number of packets which were sniffed in the last BLE connection.
    # From CONNECT_REQ until link loss/termination.
    @property
    def packetsInLastConnection(self):
        return self._packetsInLastConnection

    # The packet counter value of the last received connect request.
    @property
    def connectEventPacketCounterValue(self):
        return self._connectEventPacketCounterValue

    # A Packet object containing the last received connect request.
    @property
    def currentConnectRequest(self):
        return self._currentConnectRequest

    # A boolean indicating whether the sniffed device is in a connection.
    @property
    def inConnection(self):
        return self._inConnection

    # The internal state of the sniffer.
    # States are defined in SnifferCollector module. Valid values are 0-2.
    @property
    def state(self):
        return self._state

    # The COM port of the sniffer hardware. During initialization, this value is a preset.
    @property
    def portnum(self):
        return self._portnum

    # The version number of the API software.
    @property
    def swversion(self):
        return self._swversion

    # The version number of the sniffer firmware.
    @property
    def fwversion(self):
        return self._fwversion

    # API ENDS HERE

    # Private method
    def run(self):
        try:
            self._setup()
            self.runSniffer()
        except (KeyboardInterrupt) as e:
            unused_exc_type, unused_exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            lineno = exc_tb.tb_lineno
            logging.info("exiting ("+str(type(e))+" in "+fname+" at "+str(lineno)+"): "+str(e))
            self.goodExit = False
        except Exception as e:
            logging.exception("CRASH")
            self.goodExit = False
        else:
            self.goodExit = True

    # Private method
    def comPortFound(self, notification):
        # logging.info("Com port found")
        self._portnum = notification.msg["comPort"]
        self._boardId = self._makeBoardId()
        # self._packetReader.comport = self.portnum

    # Private method
    def runSniffer(self):
        if not self._exit:
            self._continuouslyPipe()
        else:
            self.goodExit = False

    # Private method
    def sendTestPacketToSniffer(self, payload):
        self._sendTestPacket(payload)

    # Private method
    def getTestPacketFromSniffer(self):
        return self._getTestPacket()
