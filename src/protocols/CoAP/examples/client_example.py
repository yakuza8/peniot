from coapthon.client.helperclient import HelperClient

import argparse
import logging
import signal
import sys
import time

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 5683
DEFAULT_PATH = "peniot"

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s:%(levelname)s:%(name)s : %(message)s")
logger = logging.getLogger("CoAP Client")

global_client = None

"""
    CoAP Basic Client
"""


def signal_handler(sig, frame):
    global global_client
    logger.info("Connection will be closed")
    if global_client is not None:
        global_client.stop()
    sys.exit(0)


def client_procedure(host, port, path):
    """
    Client procedure for CoAP
    :param host: Host address to connect
    :param port: Port number of server
    :param path: Path as endpoint to request resources
    :return: None
    """
    # Signal handler to exit from function
    signal.signal(signal.SIGINT, signal_handler)

    # Make global client available to exit properly
    global global_client
    client = HelperClient(server=(host, port))
    global_client = client

    # Start client loop for requests
    while True:
        response = client.get(path)
        logger.info("Received message = {0}".format(str(response.line_print)))
        time.sleep(2)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-H", "--host", help="Host string of server", default=DEFAULT_HOST)
    parser.add_argument("-P", "--port", help="Port number of server", default=DEFAULT_PORT, type=int)
    parser.add_argument("-e", "--endpoint", help="Path of resources", default=DEFAULT_PATH)
    args = parser.parse_args()

    client_procedure(args.host, args.port, args.endpoint)
