from __future__ import absolute_import
from . import UART, Exceptions, Notifications
import time
import logging
import os
import sys
import serial
from six.moves import range

SLIP_START = 0xAB
SLIP_END = 0xBC
SLIP_ESC = 0xCD
SLIP_ESC_START = SLIP_START+1
SLIP_ESC_END = SLIP_END+1
SLIP_ESC_ESC = SLIP_ESC+1

REQ_FOLLOW = 0x00
RESP_FOLLOW = 0x01
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
TEST_RESULT_ID = 0x10
UART_TEST_START = 0x11
UART_DUMMY_PACKET = 0x12
SWITCH_BAUD_RATE_REQ = 0x13
SWITCH_BAUD_RATE_RESP = 0x14
UART_OUT_START = 0x15
UART_OUT_STOP = 0x16
SET_ADV_CHANNEL_HOP_SEQ = 0x17
GO_IDLE = 0xFE

ADV_ACCESS_ADDRESS = [0xD6, 0xBE, 0x89, 0x8E]

SYNCWORD_POS = 0
HEADER_LEN_POS = 0
PAYLOAD_LEN_POS = HEADER_LEN_POS+1
PROTOVER_POS = PAYLOAD_LEN_POS+1
PACKETCOUNTER_POS = PROTOVER_POS+1
ID_POS = PACKETCOUNTER_POS+2

BLE_HEADER_LEN_POS = ID_POS+1
FLAGS_POS = BLE_HEADER_LEN_POS+1
CHANNEL_POS = FLAGS_POS+1
RSSI_POS = CHANNEL_POS+1
EVENTCOUNTER_POS = RSSI_POS+1
TIMESTAMP_POS = EVENTCOUNTER_POS+2
BLEPACKET_POS = TIMESTAMP_POS+4
TXADD_POS = BLEPACKET_POS + 4
TXADD_MSK = 0x40
PAYLOAD_POS = BLE_HEADER_LEN_POS

HEADER_LENGTH = 6
BLE_HEADER_LENGTH = 10
PROTOVER = 1

ADV_TYPE_ADV_IND = 0x0
ADV_TYPE_ADV_DIRECT_IND = 0x1
ADV_TYPE_ADV_NONCONN_IND = 0x2
ADV_TYPE_ADV_DISCOVER_IND = 0x6
ADV_TYPE_SCAN_REQ = 0x3
ADV_TYPE_SCAN_RSP = 0x4
ADV_TYPE_CONNECT_REQ = 0x5

VALID_ADV_CHANS = [37, 38, 39]


class PacketReader(Notifications.Notifier):
    def __init__(self, portnum=None, callbacks=[]):
        Notifications.Notifier.__init__(self, callbacks)
        self.portnum = portnum
        self.exit = False
        try:
            self.uart = UART.Uart(portnum)
        except serial.SerialException as e:
            logging.exception("Error opening UART.")
            self.uart = UART.Uart()
        self.packetCounter = 0
        self.lastReceivedPacketCounter = 0
        self.lastReceivedPacket = None

        # self.states = {}

    def setup(self):
        self.findSerialPort()
        self.uart.ser.port = self.portnum
        self.uart.ser.open

    def doExit(self):
        self.exit = True
        if self.uart.ser is not None:
            self.uart.ser.close()

    # This function takes a byte list, encode it in SLIP protocol and return the encoded byte list
    def encodeToSLIP(self, byteList):
        tempSLIPBuffer = []
        tempSLIPBuffer.append(SLIP_START)
        for i in byteList:
            if i == SLIP_START:
                tempSLIPBuffer.append(SLIP_ESC)
                tempSLIPBuffer.append(SLIP_ESC_START)
            elif i == SLIP_END:
                tempSLIPBuffer.append(SLIP_ESC)
                tempSLIPBuffer.append(SLIP_ESC_END)
            elif i == SLIP_ESC:
                tempSLIPBuffer.append(SLIP_ESC)
                tempSLIPBuffer.append(SLIP_ESC_ESC)
            else:
                tempSLIPBuffer.append(i)
        tempSLIPBuffer.append(SLIP_END)
        return tempSLIPBuffer

    # This function uses getSerialByte() function to get SLIP encoded bytes from the serial port
    # and return a decoded byte list
    # Based on https://github.com/mehdix/pyslip/
    def decodeFromSLIP(self, timeout=None):
        dataBuffer = []
        startOfPacket = False
        endOfPacket = False

        while not startOfPacket:
            startOfPacket = (self.getSerialByte(timeout) == SLIP_START)

        while not endOfPacket:
            serialByte = self.getSerialByte(timeout)
            if serialByte == SLIP_END:
                endOfPacket = True
            elif serialByte == SLIP_ESC:
                serialByte = self.getSerialByte()
                if serialByte == SLIP_ESC_START:
                    dataBuffer.append(SLIP_START)
                elif serialByte == SLIP_ESC_END:
                    dataBuffer.append(SLIP_END)
                elif serialByte == SLIP_ESC_ESC:
                    dataBuffer.append(SLIP_ESC)
                else:
                    raise Exceptions.UARTPacketError(
                        "Unexpected character after SLIP_ESC: %d." % serialByte)
            else:
                dataBuffer.append(serialByte)
        return dataBuffer

    # This function read byte chuncks from the serial port and return one byte at a time
    # Based on https://github.com/mehdix/pyslip/
    def getSerialByte(self, timeout=None):
        serialByte = self.uart.readByte(timeout)
        if len(serialByte) != 1:
            raise Exceptions.SnifferTimeout("Packet read timed out.")
        return ord(serialByte)

    def handlePacketHistory(self, packet):
        # Reads and validates packet counter
        if self.lastReceivedPacket and (
            packet.packetCounter != (self.lastReceivedPacket.packetCounter+1)) and (
                self.lastReceivedPacket.packetCounter != 0):
            logging.info("gap in packets, between {} and {}. packet before: {}, packet after: {}"
                         .format(
                             self.lastReceivedPacket.packetCounter,
                             str(packet.packetCounter),
                             str(self.lastReceivedPacket.packetList),
                             str(packet.packetList)
                         ))
        self.lastReceivedPacket = packet

    def getPacket(self, timeout=None):
        packetList = []
        try:
            packetList = self.decodeFromSLIP(timeout)
        except Exceptions.UARTPacketError:
            logging.exception("")
            return None
        else:
            packet = Packet(packetList)
            if packet.valid:
                self.handlePacketHistory(packet)
            return packet

    def useByteQueue(self, useByteQueue=True):
        self.uart.useByteQueue = useByteQueue

    def getByteQueue(self):
        return self.uart.byteQueue

    def sendPacket(self, id, payload, timeout=None):
        packetList = [HEADER_LENGTH] + [len(payload)] + [PROTOVER] + \
            toLittleEndian(self.packetCounter, 2) + [id] + payload
        pkt = self.encodeToSLIP(packetList)
        self.packetCounter += 1
        self.uart.writeList(pkt, timeout)

    def sendScan(self, timeout=None):
        self.sendPacket(REQ_SCAN_CONT, [], timeout)

    def sendFollow(self, addr, txAdd=1, followOnlyAdvertisements=False, timeout=None):
        # TxAdd is a single byte (0 or 1) so we just append it to the address.
        # addr.append(txAdd)
        self.sendPacket(REQ_FOLLOW, addr+[followOnlyAdvertisements], timeout)

    def sendPingReq(self, timeout=1):
        self.sendPacket(PING_REQ, [], timeout)

    def sendTK(self, TK, timeout=None):
        if (len(TK) < 16):
            TK = [0] * (16-len(TK)) + TK
        else:
            TK = TK[:16]
        self.sendPacket(SET_TEMPORARY_KEY, TK, timeout)

        logging.info("Sent key value to sniffer: "+str(TK))
        self.notify("TK_SENT", {"TK": TK})
        return TK

    def sendSwitchBaudRate(self, newBaudRate, timeout=None):
        self.sendPacket(SWITCH_BAUD_RATE_REQ, toLittleEndian(newBaudRate, 4), timeout)

    def switchBaudRate(self, newBaudRate):
        self.uart.switchBaudRate(newBaudRate)

    def sendHopSequence(self, hopSequence):
        for chan in hopSequence:
            if chan not in VALID_ADV_CHANS:
                raise Exceptions.InvalidAdvChannel("%s is not an adv channel" % str(chan))
        payload = [len(hopSequence)] + hopSequence + [37]*(3-len(hopSequence))
        self.sendPacket(SET_ADV_CHANNEL_HOP_SEQ, payload)
        self.notify("NEW_ADV_HOP_SEQ", {"hopSequence": hopSequence})

    def sendGoIdle(self, timeout=None):
        self.sendPacket(GO_IDLE, [], timeout)

    def findSerialPort(self):
        foundPort = False
        iPort = 0  # To avoid COM1 (iPort=0).
        nTicks = 0

        trials = 10
        # comports = self.findSeggerComPorts().keys()

        if self.portnum is not None:
            self.notify("INFO_PRESET")
        else:
            self.notify("INFO_NO_PRESET")

        readTimeout = 1
        iPort = self.portnum if self.portnum is not None else 1
        while not foundPort and not self.exit:

            try:
                self.uart.ser.port = iPort
                try:
                    self.uart.ser.open()
                except:
                    pass
                self.sendPingReq()
                startTime = time.time()
                continueLoop = True
                packetCounter = 0
                while continueLoop and (time.time() < (startTime+1)):
                    packet = self.getPacket(timeout=readTimeout)

                    if packet is None:
                        continueLoop = False
                        raise Exception("None packet")
                    elif packet.id == 0x0E:
                        continueLoop = False
                        fwversion = packet.version
                        self.portnum = self.uart.ser.portstr
                        self.notify("COMPORT_FOUND", {"comPort": self.portnum})
                        self.fwversion = fwversion
                        return
                    else:
                        packetCounter += 1

                if continueLoop:
                    raise Exception("No packet with correct id. Received " +
                                    str(packetCounter)+" packets.")

            except Exception as e:
                if "The system cannot find the file specified." not in str(e):
                    # logging.exception("Error on COM"+str(iPort+1)+": "+str(e))
                    logging.info("Error on port " + str(iPort) + ". file: " +
                                 os.path.basename(sys.exc_info()[2].tb_frame.f_code.co_filename) +
                                 ", line " + str(sys.exc_info()[2].tb_lineno) + ": "+str(e))
                    # logging.exception("error")
                    trials = trials + 1
                    if (trials>9):
                        self.doExit()   #Try to open the port for some time, if can't just exit
                try:
                    if self.uart.ser is not None:
                        self.uart.ser.close()
                except:  # noqa: E722
                    logging.exception("could not close UART")

            if self.portnum is None:
                if type(iPort) != int:
                    iPort = 0
                iPort += 1
                iPort = (iPort % 256)

            if self.portnum is not None or (iPort % 64) == 0:
                nTicks += 1
                self.notify("DEVICE_DISCOVERY_TICK", {"tickNumber": nTicks})
                if readTimeout < 3:
                    readTimeout += 0.1

            # logging.info("iPort: " +str(iPort))
            # logging.info("self.portnum: " +str(self.portnum))

            if self.portnum is not None:
                time.sleep(0.7)
            else:
                time.sleep(0.01)
        return (None, None)


class Packet:

    def __init__(self, packetList):
        try:
            if packetList == []:
                raise Exceptions.InvalidPacketException(
                    "packet list not valid: %s" % str(packetList))
            self.packetList = packetList
            self.readStaticHeader(packetList)
            self.readDynamicHeader(packetList)
            self.readPayload(packetList)

        except Exceptions.InvalidPacketException as e:
            logging.error("Invalid packet: %s" % str(e))
            self.OK = False
            self.valid = False
        except:  # noqa: E722
            logging.exception("packet creation error")
            logging.info("packetList: " + str(packetList))
            self.OK = False
            self.valid = False

    def __repr__(self):
        return "UART packet, type: "+str(self.id)+", PC: "+str(self.packetCounter)

    def readStaticHeader(self, packetList):
        self.headerLength = packetList[HEADER_LEN_POS]
        self.payloadLength = packetList[PAYLOAD_LEN_POS]
        self.protover = packetList[PROTOVER_POS]

    def readDynamicHeader(self, packetList):
        self.header = packetList[0:self.headerLength]
        if self.headerLength == HEADER_LENGTH:
            self.packetCounter = parseLittleEndian(
                packetList[PACKETCOUNTER_POS:PACKETCOUNTER_POS+2])
            self.id = packetList[ID_POS]
        else:
            logging.info("incorrect header length: %d" % self.headerLength)

    def readPayload(self, packetList):
        self.blePacket = None
        self.OK = False

        if not self.validatePacketList(packetList):
            raise Exceptions.InvalidPacketException("packet list not valid: %s" % str(packetList))
        else:
            self.valid = True

        self.payload = packetList[PAYLOAD_POS:PAYLOAD_POS+self.payloadLength]

        if self.id == EVENT_PACKET:
            try:
                self.bleHeaderLength = packetList[BLE_HEADER_LEN_POS]
                if self.bleHeaderLength == BLE_HEADER_LENGTH:
                    self.flags = packetList[FLAGS_POS]
                    self.readFlags()
                    self.channel = packetList[CHANNEL_POS]
                    self.rawRSSI = packetList[RSSI_POS]
                    self.RSSI = -self.rawRSSI
                    self.txAdd = packetList[TXADD_POS] & TXADD_MSK
                    self.eventCounter = parseLittleEndian(
                        packetList[EVENTCOUNTER_POS:EVENTCOUNTER_POS+2])
                    self.timestamp = parseLittleEndian(packetList[TIMESTAMP_POS:TIMESTAMP_POS+2])
                    # self.payload = packetList[13:(4+self.length)]
                    # The hardware adds a padding byte which isn't sent on air.
                    # The following removes it.
                    self.packetList.pop(BLEPACKET_POS+6)
                    self.payloadLength -= 1
                    if packetList[PAYLOAD_LEN_POS] > 0:
                        packetList[PAYLOAD_LEN_POS] -= 1

                if self.OK:
                    try:
                        self.blePacket = BlePacket(packetList[BLEPACKET_POS:])
                    except:  # noqa: E722
                        logging.exception("blePacket error")
            except:  # noqa: E722
                # malformed packet
                logging.exception("packet error")
                self.OK = False
        elif self.id == PING_RESP:
            self.version = parseLittleEndian(self.packetList[PAYLOAD_POS:PAYLOAD_POS+2])
        elif self.id == SWITCH_BAUD_RATE_RESP or self.id == SWITCH_BAUD_RATE_REQ:
            self.baud_rate = parseLittleEndian(packetList[PAYLOAD_POS:PAYLOAD_POS+4])
        elif self.id == TEST_RESULT_ID:
            self.testId = packetList[PAYLOAD_POS]
            self.testLength = packetList[PAYLOAD_POS+1]
            self.testPayload = packetList[PAYLOAD_POS+2:]

    def readFlags(self):
        self.crcOK = not not (self.flags & 1)
        self.direction = not not (self.flags & 2)
        self.encrypted = not not (self.flags & 4)
        self.micOK = not not (self.flags & 8)
        self.OK = self.crcOK and (self.micOK or not self.encrypted)

    def getList(self):
        return self.packetList

    def validatePacketList(self, packetList):
        try:
            if (packetList[PAYLOAD_LEN_POS] + packetList[HEADER_LEN_POS]) == len(packetList):
                return True
            else:
                return False
        except:  # noqa: E722
            logging.exception("Invalid packet: %s" % str(packetList))
            return False


class BlePacket():
    def __init__(self, packetList):
        self.extractAccessAddress(packetList)
        if self.accessAddress == ADV_ACCESS_ADDRESS:
            self.extractAdvType(packetList)
            self.extractAdvAddress(packetList)
            self.extractName(packetList)
        self.extractLength(packetList)
        self.payload = packetList[6:]

    def __repr__(self):
        return "BLE packet, AAddr: "+str(self.accessAddress)

    def extractAccessAddress(self, packetList):
        self.accessAddress = packetList[0:4]

    def extractAdvType(self, packetList):
        self.advType = (packetList[4] & 15)

    def extractAdvAddress(self, packetList):
        addr = None
        if (self.advType == 0 or self.advType == 1 or self.advType == 2 or self.advType == 4
           or self.advType == 6):
            addrType = not not packetList[4] & 64
            addr = packetList[6:12]
            addr.reverse()
            addr += [addrType]
        elif (self.advType == 3 or self.advType == 5):
            addrType = not not packetList[4] & 64
            addr = packetList[12:18]
            addr.reverse()
            addr += [addrType]

        self.advAddress = addr

    def extractName(self, packetList):
        name = ""
        if (self.advType == 0 or self.advType == 2 or self.advType == 6):
            i = 12
            while i < len(packetList):
                length = packetList[i]
                if (i+length+1) > len(packetList) or length == 0:
                    break
                type = packetList[i+1]
                if type == 8 or type == 9:
                    nameList = packetList[i+2:i+length+1]
                    name = ""
                    for j in nameList:
                        name += chr(j)
                i += (length+1)
            name = '"'+name+'"'
        elif (self.advType == 1):
            name = "[ADV_DIRECT_IND]"

        self.name = name  # .decode(encoding="UTF-8")

    def extractLength(self, packetList):
        length = packetList[5]
        self.length = length


def parseLittleEndian(list):
    total = 0
    for i in range(len(list)):
        total += (list[i] << (8*i))
    return total


def toLittleEndian(value, size):
    list = [0]*size
    for i in range(size):
        list[i] = (value >> (i*8)) % 256
    return list
