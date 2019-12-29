from coapthon.server.coap import CoAP
from resource_example import BasicResource

import argparse
# import logging

DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 5683
DEFAULT_PATH = "peniot"

# Since it has logger itself
# logging.basicConfig(level=logging.DEBUG, format="%(asctime)s:%(levelname)s:%(name)s : %(message)s")
# logger = logging.getLogger("CoAP Server")

"""
    CoAP Basic Server
"""


class CoAPServer(CoAP):
    def __init__(self, host, port, path):
        CoAP.__init__(self, (host, port))
        self.add_resource(path + '/', BasicResource())


def server_procedure(host, port, path):
    """
    Server procedure for CoAP
    :param host: Host address to connect
    :param port: Port number of server
    :param path: Path as endpoint to request resources
    :return: None
    """
    server = CoAPServer(host, port, path)
    try:
        server.listen(10)
    except KeyboardInterrupt:
        print "Server Shutdown"
        server.close()
        print "Exiting..."


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-H", "--host", help="Host string of server", default=DEFAULT_HOST)
    parser.add_argument("-P", "--port", help="Port number of server", default=DEFAULT_PORT, type=int)
    parser.add_argument("-e", "--endpoint", help="Path of resources", default=DEFAULT_PATH)
    args = parser.parse_args()

    server_procedure(args.host, args.port, args.endpoint)
