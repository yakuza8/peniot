from __future__ import absolute_import
from __future__ import print_function
import time
import os
import logging
import traceback
import threading
import logging.handlers as logHandlers
from six.moves import range

#################################################################
# This file contains the logger. To log a line, simply write     #
# 'logging.[level]("whatever you want to log")'                    #
# [level] is one of {info, debug, warning, error, critical,        #
#     exception}                                                    #
# See python logging documentation                                #
# As long as Logger.initLogger has been called beforehand, this    #
# will result in the line being appended to the log file        #
#################################################################

try:
    logFilePath = os.path.join(
        os.getenv('appdata'), 'Nordic Semiconductor', 'Sniffer', 'logs')
except AttributeError:
    logFilePath = "logs"

logFileName = os.path.join(logFilePath, 'log.txt')

logHandler = None
logFlusher = None

myMaxBytes = 1000000

# Ensure that the directory we are writing the log file to exists.
# Create our logfile, and write the timestamp in the first line.


def initLogger():
    try:
        # First, make sure that the directory exists
        if not os.path.isdir(logFilePath):
            os.makedirs(logFilePath)

        # If the file does not exist, create it, and save the timestamp
        if not os.path.isfile(logFileName):
            with open(logFileName, "wb") as f:
                f.write('{0}{1}'.format(time.time(), os.linesep).encode())

        global logHandler
        global logFlusher

        logHandler = MyRotatingFileHandler(
            logFileName, mode='a', maxBytes=myMaxBytes, backupCount=3)
        logFormatter = logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s', datefmt='%d-%b-%Y %H:%M:%S (%z)')
        logHandler.setFormatter(logFormatter)
        logger = logging.getLogger()
        logger.addHandler(logHandler)
        logger.setLevel(logging.INFO)

        logFlusher = LogFlusher(logHandler)
    except:  # noqa: 722
        print("LOGGING FAILED")
        print(traceback.format_exc())
        raise


def shutdownLogger():
    logging.shutdown()

# Clear the log (typically after it has been sent on email)


def clearLog():
    try:
        logHandler.doRollover()
    except:  # noqa: 722
        print("LOGGING FAILED")
        raise


# Returns the timestamp residing on the first line of the logfile.
# Used for checking the time of creation
def getTimestamp():
    try:
        with open(logFileName, "r") as f:
            f.seek(0)
            return f.readline()
    except:  # noqa: 722
        print("LOGGING FAILED")


def addTimestamp():
    try:
        with open(logFileName, "a") as f:
            f.write(str(time.time()) + os.linesep)
    except:  # noqa: 722
        print("LOGGING FAILED")
# Returns the entire content of the logfile. Used when sending emails


def readAll():
    try:
        text = ""
        with open(logFileName, "r") as f:
            text = f.read()
        return text
    except:  # noqa: 722
        print("LOGGING FAILED")


class MyRotatingFileHandler(logHandlers.RotatingFileHandler):
    def doRollover(self):
        try:
            logHandlers.RotatingFileHandler.doRollover(self)
            addTimestamp()
            self.maxBytes = myMaxBytes
        except:  # noqa: 722
            # There have been permissions issues with the log files.
            self.maxBytes += int(myMaxBytes/2)
            # logging.exception("log rollover error")


class LogFlusher(threading.Thread):
    def __init__(self, logHandler):
        threading.Thread.__init__(self)

        self.daemon = True
        self.handler = logHandler
        self.exit = False

        self.start()

    def run(self):
        while not self.exit:
            time.sleep(10)
            self.doFlush()

    def doFlush(self):
        self.handler.flush()
        os.fsync(self.handler.stream.fileno())

    def stop(self):
        self.exit = True


if __name__ == '__main__':
    initLogger()
    for i in range(50):
        logging.info("test log no. "+str(i))
        print("test log no. ", i)
