"""
    This package contains the following functionalities:

    1) Example usage of CoAP.
    2) Attacks that is done on CoAP
    3) CoAP Scanner
    4) Old Attack Scripts for CoAP
    5) CoAP Protocol

    Moreover, we have a class which inherits from Protocol class.
"""


from coapthon.client.helperclient import HelperClient

import enum
import logging

FORMAT = "%(asctime)s:%(levelname)s:%(name)s:%(message)s"
logging.basicConfig(level=logging.DEBUG, format=FORMAT)
logger = logging.getLogger("CoAP Init")


class CoAPMethods(enum.Enum):
    EMPTY = 0
    GET = 1
    POST = 2
    PUT = 3
    DELETE = 4


def does_method_have_payload(method):
    """
    :type method: CoAPMethods
    :param method: Method which is tested to have paylaod
    :return: Whether method has payload or not
    """
    return method in [CoAPMethods.POST, CoAPMethods.PUT]


def make_request(client, _path, _method_type, _payload=None):
    """
    :param _path: Path to be fuzzed
    :param _method_type: Which CoAP method will be used while fuzzing
    :param _payload: Payload to be fuzzed
    :type client: HelperClient
    :return response: Response of request if proper request is done, otherwise None
    """
    try:
        response = None
        if _method_type == CoAPMethods.GET:
            response = client.get(_path)
        elif _method_type == CoAPMethods.POST:
            response = client.post(_path, _payload)
        elif _method_type == CoAPMethods.PUT:
            response = client.put(_path, _payload)
        elif _method_type == CoAPMethods.DELETE:
            response = client.delete(_path)
        return response
    except UnicodeEncodeError:
        logger.error("Unicode encoding error is occurred!")


def get_coap_methods_by_name(method_string):
    uppered_method_name = method_string.upper()
    if uppered_method_name == "EMPTY":
        return CoAPMethods.EMPTY
    elif uppered_method_name == "GET":
        return CoAPMethods.GET
    elif uppered_method_name == "POST":
        return CoAPMethods.POST
    elif uppered_method_name == "PUT":
        return CoAPMethods.PUT
    elif uppered_method_name == "DELETE":
        return CoAPMethods.DELETE
    else:
        logger.error("Unknown CoAP Method Type!")
        return CoAPMethods.POST


def get_coap_methods_as_string(method):
    if method == CoAPMethods.EMPTY:
        return "EMPTY"
    elif method == CoAPMethods.GET:
        return "GET"
    elif method == CoAPMethods.POST:
        return "POST"
    elif method == CoAPMethods.PUT:
        return "PUT"
    elif method == CoAPMethods.DELETE:
        return "DELETE"
    else:
        logger.error("Unknown CoAP Method Type!")
        return "None"
