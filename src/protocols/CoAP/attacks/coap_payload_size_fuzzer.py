import logging
import multiprocessing
import random
import signal
import time
import unittest

from coapthon.client.helperclient import HelperClient

from Entity.attack import Attack
from Entity.input_format import InputFormat
from protocols import CoAP as PeniotCoAP


class CoAPPayloadSizeFuzzerAttack(Attack):
    """
    CoAP Protocol - Payload Size Fuzzer Attack module
    It is created to test any CoAP device as black box test with malformed or semi-malformed inputs
    """
    client = None

    # Input Fields
    host = None
    port = None
    path = None
    method = None
    method_string = PeniotCoAP.get_coap_methods_as_string(PeniotCoAP.CoAPMethods.POST)
    fuzzing_turn = 10

    # Miscellaneous Members
    logger = None
    max_payload_length = 2 ** 16 - 1
    sent_message_count = 0  # Transmitted fuzzing packets
    stopped_flag = False

    def __init__(self):
        default_parameters = ["", "", "", "", 10, self.max_payload_length]
        inputs = [
            InputFormat("Host Name", "host", "", str, mandatory=True),
            InputFormat("Port Number", "port", "", int, mandatory=True),
            InputFormat("Endpoint", "path", "", str, mandatory=True),
            InputFormat("Method", "method_string", self.method_string, str, mandatory=True),
            InputFormat("Fuzzing Round Count", "fuzzing_turn", self.fuzzing_turn, int),
            InputFormat("Maximum Payload Size", "max_payload_length", self.max_payload_length, int, mandatory=True)
        ]

        Attack.__init__(self, "CoAP Payload Size Fuzzer Attack", inputs, default_parameters,
                        "    CoAP Payload size fuzzer attack description")

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
            self.client = None
        time.sleep(2)  # Sleep two seconds so the user can see the message

    def pre_attack_init(self):
        try:
            assert PeniotCoAP.does_method_have_payload(self.method) and self.fuzzing_turn >= 2
        except AssertionError as e:
            raise
        self.client = HelperClient(server=(self.host, self.port))
        self.method = PeniotCoAP.get_coap_methods_by_name(self.method_string)

    def run(self):
        Attack.run(self)
        self.pre_attack_init()

        # Fill the size list as randomly generated
        size_list = [0, self.max_payload_length]
        size_list.extend([random.randint(0, self.max_payload_length) for _ in range(self.fuzzing_turn - 2)])

        fuzzing = 0
        self.logger.info("Size payload fuzzing is started. Please consider it may take some time.")
        for payload_size in size_list:

            if self.stopped_flag is True:  # Attack is terminated
                break

            # Create payload and send it
            random_strings = "".join([chr(_) for _ in range(65, 91)]) + "".join([chr(_) for _ in range(97, 123)])
            random_character = random.choice(random_strings)
            sized_payload = random_character * payload_size
            PeniotCoAP.make_request(self.client, self.path, self.method, sized_payload)

            # Informative procedures
            self.logger.info("Turn {0} is completed".format(fuzzing + 1))
            self.sent_message_count += 1
            fuzzing += 1
            time.sleep(1)

        if self.stopped_flag is False:
            self.logger.info("Payload size attack is finished.")
        else:
            self.logger.info("Payload size attack has been terminated.")

        if self.client is not None:
            self.client.stop()
            self.client = None


class TestCoAPPayloadSizeAttack(unittest.TestCase):
    def setUp(self):
        self.coap_payload_size_fuzzer = CoAPPayloadSizeFuzzerAttack()

    def tearDown(self):
        pass

    def test_name(self):
        self.assertEqual("CoAP Payload Size Fuzzer Attack", self.coap_payload_size_fuzzer.get_attack_name())

    def test_inputs(self):
        inputs = self.coap_payload_size_fuzzer.get_inputs()
        self.assertIsNotNone(inputs)
        self.assertGreater(len(inputs), 0, "Non inserted inputs")
        self.assertEquals(len(inputs), 6)

    def test_non_initialized_inputs(self):
        inputs = self.coap_payload_size_fuzzer.get_inputs()
        for _input in inputs:
            value = getattr(self.coap_payload_size_fuzzer, _input.get_name())
            self.assertTrue(value is None or type(value) == _input.get_type())

    def test_after_getting_inputs(self):
        example_inputs = ["a.b.c.d", 8888, "peniot-coap-test", "PuT", 13, 6583]
        for index, _input in enumerate(example_inputs):
            self.coap_payload_size_fuzzer.inputs[index].set_value(_input)

        # Previously it should not be set
        self.assertIsNone(self.coap_payload_size_fuzzer.client)

        super(CoAPPayloadSizeFuzzerAttack, self.coap_payload_size_fuzzer).run()

        inputs = self.coap_payload_size_fuzzer.get_inputs()
        for index, _input in enumerate(inputs):
            value = getattr(self.coap_payload_size_fuzzer, _input.get_name())
            self.assertEqual(example_inputs[index], value)

    def test_invalid_method(self):
        example_inputs = ["127.0.0.1", 8888, "peniot-coap-test", "geT", 13, 6583]
        for index, _input in enumerate(example_inputs):
            self.coap_payload_size_fuzzer.inputs[index].set_value(_input)

        super(CoAPPayloadSizeFuzzerAttack, self.coap_payload_size_fuzzer).run()
        try:
            self.coap_payload_size_fuzzer.pre_attack_init()
        except AssertionError as e:
            self.assertTrue(True)

    def test_invalid_fuzzing_turn(self):
        example_inputs = ["127.0.0.1", 8888, "peniot-coap-test", "puT", 1, 6583]
        for index, _input in enumerate(example_inputs):
            self.coap_payload_size_fuzzer.inputs[index].set_value(_input)

        super(CoAPPayloadSizeFuzzerAttack, self.coap_payload_size_fuzzer).run()
        try:
            self.coap_payload_size_fuzzer.pre_attack_init()
        except AssertionError as e:
            self.assertTrue(True)

    def test_payload_size_fuzzing_attack(self):
        def run_attack():
            example_inputs = ["127.0.0.1", 5683, "peniot", "pOsT", 3, 6583]
            for index, _input in enumerate(example_inputs):
                self.coap_payload_size_fuzzer.inputs[index].set_value(_input)

            try:
                self.coap_payload_size_fuzzer.run()
            except Exception as e:
                self.assertTrue(False)

        print "* If server is not initialized this test will not execute properly."
        p = multiprocessing.Process(target=run_attack, name="DoS Attack")
        p.start()
        time.sleep(5)
        if p.is_alive():
            p.terminate()
            p.join()


if __name__ == '__main__':
    unittest.main()
