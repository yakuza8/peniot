from __future__ import absolute_import
from . import Packet, Exceptions, CaptureFiles, Devices, Notifications, Version
import threading
import logging
import copy
from serial import SerialException
from six.moves import range


REQ_FOLLOW = 0x00
EVENT_FOLLOW = 0x01
EVENT_DEVICE = 0x02
REQ_SINGLE_PACKET = 0x03
RESP_SINGLE_PACKET = 0x04
EVENT_CONNECT = 0x05
EVENT_PACKET = 0x06
REQ_SCAN_CONT = 0x07
RESP_SCAN_CONT = 0x08
EVENT_DISCONNECT = 0x09
EVENT_ERROR = 0x0A
EVENT_EMPTY_DATA_PACKET = 0x0B
SET_TEMPORARY_KEY = 0x0C
PING_REQ = 0x0D
PING_RESP = 0x0E
TEST_COMMAND_ID = 0x0F
UART_TEST_START = 0x11
UART_DUMMY_PACKET = 0x12
SWITCH_BAUD_RATE_REQ = 0x13
SWITCH_BAUD_RATE_RESP = 0x14
GO_IDLE = 0xFE

STATE_INITIALIZING = 0
STATE_SCANNING = 1
STATE_FOLLOWING = 2

ADV_ACCESS_ADDRESS = [0xD6, 0xBE, 0x89, 0x8E]


class SnifferCollector(Notifications.Notifier):
    def __init__(self, portnum=None, *args, **kwargs):
        Notifications.Notifier.__init__(self, *args, **kwargs)
        self._portnum = portnum
        self._swversion = Version.getRevision()
        self._fwversion = 0
        self._setState(STATE_INITIALIZING)
        self._captureHandler = CaptureFiles.CaptureFileHandler()
        self._exit = False
        self._connectionAccessAddress = None
        self._packetListLock = threading.RLock()
        with self._packetListLock:
            self._packets = []

        self._packetReader = Packet.PacketReader(
            self._portnum,  callbacks=[("*", self.passOnNotification)])
        self._devices = Devices.DeviceList(
            callbacks=[("*", self.passOnNotification)])

        self._missedPackets = 0
        self._packetsInLastConnection = None
        self._connectEventPacketCounterValue = None
        self._inConnection = False
        self._currentConnectRequest = None

        self._nProcessedPackets = 0

        self._switchingBaudRate = False

        self._attemptedBaudRates = []

        self._boardId = self._makeBoardId()

    def __del__(self):
        self._doExit()

    def _setup(self):
        self._packetReader.setup()
        if self._exit:
            return

        if self._packetReader.fwversion < self.swversion:
            self.notify("OLD_FW_VERSION", {
                        "version": self._packetReader.fwversion})

        self._fwversion = self._packetReader.fwversion

        self._startScanning()

        self._setState(STATE_SCANNING)

    def _makeBoardId(self):
        try:
            boardId = int(self._packetReader.uart.ser.name.split("COM")[1])
            logging.info("board ID: %d" % boardId)
        except (IndexError, AttributeError):
            import random
            random.seed()
            boardId = random.randint(0, 255)
            logging.info("board ID (random): %d" % boardId)

        return boardId

    @property
    def state(self):
        return self._state

    def _setState(self, newState):
        self._state = newState
        self.notify("STATE_CHANGE", newState)

    def _switchBaudRate(self, newBaudRate):
        if newBaudRate in self._packetReader.uart.ser.BAUDRATES:
            self._packetReader.sendSwitchBaudRate(newBaudRate)
            self._switchingBaudRate = True
            self._proposedBaudRate = newBaudRate
            self._attemptedBaudRates.append(newBaudRate)

    def _processBLEPacket(self, packet):
        packet.boardId = self._boardId
        self._appendPacket(packet)

        self.notify("NEW_BLE_PACKET", {"packet": packet})
        self._captureHandler.writePacket(packet)

        self._nProcessedPackets += 1
        if packet.OK:
            try:
                if packet.blePacket.accessAddress == ADV_ACCESS_ADDRESS:

                    if self.state == STATE_FOLLOWING and packet.blePacket.advType == 5:
                        self._connectionAccessAddress = packet.blePacket.accessAddress

                    if self.state == STATE_SCANNING:
                        if (packet.blePacket.advType == 0
                            or packet.blePacket.advType == 1
                            or packet.blePacket.advType == 2
                            or packet.blePacket.advType == 4
                            or packet.blePacket.advType == 6
                            ) and (packet.blePacket.advAddress is not None
                                   ) and (packet.crcOK and not packet.direction):

                            newDevice = Devices.Device(
                                address=packet.blePacket.advAddress, name=packet.blePacket.name,
                                RSSI=packet.RSSI, txAdd=packet.txAdd)
                            self._devices.appendOrUpdate(newDevice)

            except Exception as e:
                logging.exception("packet processing error")
                self.notify("PACKET_PROCESSING_ERROR", {"errorString": str(e)})

    def _continuouslyPipe(self):

        while not self._exit:
            try:
                packet = self._packetReader.getPacket(timeout=2)
                if not packet.valid:
                    raise Exceptions.InvalidPacketException("")
            except Exceptions.SnifferTimeout as e:
                logging.info(str(e))
                packet = None
            except (SerialException, ValueError):
                logging.exception("UART read error")
                logging.error("Lost contact with sniffer hardware.")
                self._doExit()
            except Exceptions.InvalidPacketException:
                # logging.error("Continuously pipe: Invalid packet, skipping.")
                pass
            else:
                if packet.id == EVENT_PACKET:
                    self._processBLEPacket(packet)
                elif packet.id == EVENT_FOLLOW:
                    # This packet has no value for the user.
                    pass

                elif packet.id == EVENT_CONNECT:
                    self._connectEventPacketCounterValue = packet.packetCounter
                    self._inConnection = True
                    # copy it because packets are eventually deleted
                    self._currentConnectRequest = copy.copy(self._findPacketByPacketCounter(
                        self._connectEventPacketCounterValue-1))
                elif packet.id == EVENT_DISCONNECT:
                    if self._inConnection:
                        self._packetsInLastConnection = packet.packetCounter - \
                            self._connectEventPacketCounterValue
                        self._inConnection = False
                elif packet.id == SWITCH_BAUD_RATE_RESP and self._switchingBaudRate:
                    self._switchingBaudRate = False
                    if (packet.baudRate == self._proposedBaudRate):
                        self._packetReader.switchBaudRate(
                            self._proposedBaudRate)
                    else:
                        self._switchBaudRate(packet.baudRate)

    def _findPacketByPacketCounter(self, packetCounterValue):
        with self._packetListLock:
            for i in range(-1, -1-len(self._packets), -1):
                # iterate backwards through packets
                if self._packets[i].packetCounter == packetCounterValue:
                    return self._packets[i]
        return None

    def _startScanning(self):
        logging.info("starting scan")

        if self.state == STATE_FOLLOWING:
            logging.info("Stopped sniffing device")

        self._devices.clear()
        self._setState(STATE_SCANNING)
        self._packetReader.sendScan()
        self._packetReader.sendTK([0])

    def _doExit(self):
        self._exit = True
        self.notify("APP_EXIT")
        self._packetReader.doExit()

    def _startFollowing(self, device, followOnlyAdvertisements=False):

        self._devices.setFollowed(device)
        logging.info("Sniffing device " +
                     str(self._devices.index(device)) + ' - "'+device.name+'"')
        self._packetReader.sendFollow(
            device.address, device.txAdd, followOnlyAdvertisements)
        self._setState(STATE_FOLLOWING)

    def _appendPacket(self, packet):
        with self._packetListLock:
            if len(self._packets) > 100000:
                self._packets = self._packets[20000:]
            self._packets.append(packet)

    def _getPackets(self, number=-1):
        with self._packetListLock:
            returnList = self._packets[0:number]
            self._packets = self._packets[number:]
        return returnList

    def _sendTestPacket(self, payload):
        self._packetReader.sendTestPacket(payload)

    def _getTestPacket(self):
        return self._packetReader.getPacket()
