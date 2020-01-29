import logging
import multiprocessing
import random
import signal
import time
import unittest

from coapthon.client.helperclient import HelperClient

from Entity.attack import Attack
from Entity.input_format import InputFormat
from Utils.FuzzerUtil import radamsa_util as rdm
from protocols import CoAP as PeniotCoAP


class CoAPRandomPayloadFuzzingAttack(Attack):
    """
    CoAP Protocol - Random Payload Fuzzing Attack module
    It is created to test any CoAP device as black box test with malformed or semi-malformed inputs
    """
    client = None

    # Input Fields
    host = None
    port = None
    path = None
    payload = None
    method = None
    method_string = PeniotCoAP.get_coap_methods_as_string(PeniotCoAP.CoAPMethods.POST)
    fuzzing_turn = 10
    fuzzing_count = 10

    # Miscellaneous Members
    logger = None
    max_length_of_random_payload = 100
    sent_message_count = 0  # Transmitted fuzzing packets
    stopped_flag = False

    def __init__(self):
        default_parameters = ["", "", "", "", "", 2, 10, 100]
        inputs = [
            InputFormat("Host Name", "host", "", str, mandatory=True),
            InputFormat("Port Number", "port", "", int, mandatory=True),
            InputFormat("Endpoint", "path", "", str, mandatory=True),
            InputFormat("Seed Payload", "payload", "", str, mandatory=True),
            InputFormat("Method", "method_string", self.method_string, str, mandatory=True),
            InputFormat("Fuzzing Round Count", "fuzzing_turn", self.fuzzing_turn, int),
            InputFormat("Number of fuzzer messages", "fuzzing_count", self.fuzzing_count, int),
            InputFormat("Payload length", "max_length_of_random_payload", self.max_length_of_random_payload, int, mandatory=True)
        ]

        Attack.__init__(self, "CoAP Random Payload Fuzzing Attack", inputs, default_parameters,
                        "    It creates a random payload and sends \n"
                        "    this payload to the client.")

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
        self.client = HelperClient(server=(self.host, self.port))
        self.method = PeniotCoAP.get_coap_methods_by_name(self.method_string)
        try:
            assert PeniotCoAP.does_method_have_payload(self.method) and self.fuzzing_turn >= 2
        except AssertionError as e:
            raise

    def run(self):
        Attack.run(self)
        self.pre_attack_init()

        self.logger.info("Random payload fuzzing is started.")

        if self.payload is None:
            length = random.randint(1, self.max_length_of_random_payload)
            self.payload = "".join([chr(random.randint(1, 127)) for _ in range(length)])

        for fuzzing in range(self.fuzzing_turn):
            if self.stopped_flag is True:
                break
            while self.stopped_flag is False:
                try:
                    returned_strings = rdm.get_ascii_decodable_radamsa_malformed_input(self.payload, self.fuzzing_count)
                    if type(returned_strings) == list:
                        fuzzer_messages = [string.decode("utf-8") for string in returned_strings]
                    else:
                        fuzzer_messages = returned_strings.decode("utf-8")
                    break
                except UnicodeDecodeError:
                    continue
            # Check whether result is list or not
            if type(fuzzer_messages) == list:
                for message in fuzzer_messages:
                    PeniotCoAP.make_request(self.client, self.path, self.method, message)
                    # Increment sent message count
                    self.sent_message_count += 1
            else:
                PeniotCoAP.make_request(self.client, self.path, self.method, fuzzer_messages)
                # Increment sent message count
                self.sent_message_count += 1
            time.sleep(1)
            self.logger.info("Turn {0} is completed".format(fuzzing + 1))

        if self.stopped_flag is False:
            self.logger.info("Random payload fuzzing is finished.")
        else:
            self.logger.info("Random payload fuzzing has been terminated.")

        if self.client is not None:
            self.client.stop()
            self.client = None


class TestCoAPRandomPayloadAttack(unittest.TestCase):
    def setUp(self):
        self.coap_random_payload_fuzzer = CoAPRandomPayloadFuzzingAttack()

    def tearDown(self):
        pass

    def test_name(self):
        self.assertEqual("CoAP Random Payload Fuzzing Attack", self.coap_random_payload_fuzzer.get_attack_name())

    def test_inputs(self):
        inputs = self.coap_random_payload_fuzzer.get_inputs()
        self.assertIsNotNone(inputs)
        self.assertGreater(len(inputs), 0, "Non inserted inputs")
        self.assertEquals(len(inputs), 8)

    def test_non_initialized_inputs(self):
        inputs = self.coap_random_payload_fuzzer.get_inputs()
        for _input in inputs:
            value = getattr(self.coap_random_payload_fuzzer, _input.get_name())
            self.assertTrue(value is None or type(value) == _input.get_type())

    def test_after_getting_inputs(self):
        example_inputs = ["a.b.c.d", 8888, "peniot-coap-test", "Heyyo", "PuT", 13, 12, 11]
        for index, _input in enumerate(example_inputs):
            self.coap_random_payload_fuzzer.inputs[index].set_value(_input)

        # Previously it should not be set
        self.assertIsNone(self.coap_random_payload_fuzzer.client)

        super(CoAPRandomPayloadFuzzingAttack, self.coap_random_payload_fuzzer).run()

        inputs = self.coap_random_payload_fuzzer.get_inputs()
        for index, _input in enumerate(inputs):
            value = getattr(self.coap_random_payload_fuzzer, _input.get_name())
            self.assertEqual(example_inputs[index], value)

    def test_invalid_method(self):
        example_inputs = ["127.0.0.1", 8888, "peniot-coap-test", "Ghetto", "geT", 13, 12, 11]
        for index, _input in enumerate(example_inputs):
            self.coap_random_payload_fuzzer.inputs[index].set_value(_input)

        super(CoAPRandomPayloadFuzzingAttack, self.coap_random_payload_fuzzer).run()
        try:
            self.coap_random_payload_fuzzer.pre_attack_init()
        except AssertionError as e:
            self.assertTrue(True)

    def test_invalid_fuzzing_turn(self):
        example_inputs = ["127.0.0.1", 8888, "peniot-coap-test", "Keyyo", "puT", 1, 12, 11]
        for index, _input in enumerate(example_inputs):
            self.coap_random_payload_fuzzer.inputs[index].set_value(_input)

        super(CoAPRandomPayloadFuzzingAttack, self.coap_random_payload_fuzzer).run()
        try:
            self.coap_random_payload_fuzzer.pre_attack_init()
        except AssertionError as e:
            self.assertTrue(True)

    def test_random_payload_fuzzing_attack(self):
        def run_attack():
            example_inputs = ["127.0.0.1", 5683, "peniot", None, "pOsT", 3, 5, 12]
            for index, _input in enumerate(example_inputs):
                self.coap_random_payload_fuzzer.inputs[index].set_value(_input)

            try:
                self.coap_random_payload_fuzzer.run()
            except Exception as e:
                self.assertTrue(False)

        print "* If server is not initialized this test will not execute properly."
        p = multiprocessing.Process(target=run_attack, name=self.coap_random_payload_fuzzer.get_attack_name())
        p.start()
        time.sleep(15)
        if p.is_alive():
            p.terminate()
            p.join()


if __name__ == '__main__':
    unittest.main()
