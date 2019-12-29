from __future__ import absolute_import
import logging
import serial
import collections
import serial.tools.list_ports as list_ports
from . import Exceptions


class Uart:
    def __init__(self, portnum=None, useByteQueue=False):
        self.ser = None
        try:
            self.ser = serial.Serial(
                port=portnum,
                baudrate=460800,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=None,  # seconds
                writeTimeout=None,
                rtscts=True
            )

        except Exception as e:
            if self.ser:
                self.ser.close()
            raise

        self.useByteQueue = useByteQueue
        self.byteQueue = collections.deque()

        # if self.ser.name != None:
        # print "UART %s on port %s" % ("open" if self.ser else "closed", self.ser.name)

    def __del__(self):
        if self.ser:
            logging.info("closing UART")
            self.ser.close()

    def switchBaudRate(self, newBaudRate):
        self.ser.baudrate = newBaudRate

    def read(self, length, timeout=None):
        if timeout != self.ser.timeout:
            try:
                self.ser.timeout = timeout
            except ValueError as e:
                logging.error("Error setting UART read timeout. Continuing.")

        value = self.ser.read(length)
        if len(value) != length:
            raise Exceptions.SnifferTimeout(
                "UART read timeout (" + str(self.ser.timeout) + " seconds).")

        if self.useByteQueue:
            self.byteQueue.extend(value)
        return value

    def readByte(self, timeout=None):
        readString = ""

        readString = self.read(1, timeout)

        return readString

    def readList(self, size, timeout=None):
        return self.read(size, timeout)

    def writeList(self, array, timeout=None):
        nBytes = 0
        if timeout != self.ser.writeTimeout:
            try:
                self.ser.writeTimeout = timeout
            except ValueError as e:
                logging.error("Error setting UART write timeout. Continuing.")
        try:
            nBytes = self.ser.write(array)
        except:  # noqa: E722
            self.ser.close()
            raise

        return nBytes


def list_serial_ports():
    # Scan for available ports.
    return list_ports.comports()
