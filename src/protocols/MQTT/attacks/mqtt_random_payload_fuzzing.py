import multiprocessing
import unittest

import paho.mqtt.client as paho

import logging
import random
import signal
import time

from Entity.attack import Attack
from Entity.input_format import InputFormat
from Utils.FuzzerUtil import radamsa_util as rdm
from Utils.RandomUtil import random_generated_names


class MQTTRandomPayloadFuzzingAttack(Attack):
    """
    MQTT Protocol - Random Payload Fuzzing Attack module
    It is created to test any MQTT device as black box test with malformed or semi-malformed inputs
    """
    client = None

    # Input Fields
    address = None
    topic = None
    turn = 10
    count = 1
    payload = None

    # Misc Members
    logger = None
    max_length_of_random_payload = 100
    sent_message_count = 0
    stopped_flag = False

    def __init__(self):
        default_parameters = ["127.0.0.1", "#", 10, 10, ""]
        inputs = [
            InputFormat("Broker Address", "address", "", str, mandatory=True),
            InputFormat("Topic", "topic", "", str, mandatory=True),
            InputFormat("Fuzzing Turn", "turn", self.turn, int),
            InputFormat("Fuzzing Message Count in each Turn", "count", self.count, int),
            InputFormat("Payload", "payload", "", str, mandatory=True)
        ]

        Attack.__init__(self, "MQTT Random Payload Fuzzing Attack", inputs, default_parameters,
                        "    It creates a random payload and sends \n"
                        "    this payload to the client.")

        logging.basicConfig(level=logging.DEBUG, format="%(asctime)s:%(levelname)s:%(name)s:%(message)s")

        # Signal handler to exit from function
        signal.signal(signal.SIGINT, self.signal_handler)

    def signal_handler(self, sig, frame):
        self.stop_attack()

    def stop_attack(self):
        self.logger.info("Transmitted fuzzing packet count: {0}, exitting...".format(self.sent_message_count))
        self.stopped_flag = True
        if self.client is not None:
            self.client.disconnect()  # Close the connection before exitting
        time.sleep(2)  # Sleep two seconds so the user can see the message
        # sys.exit(0)

    def pre_attack_init(self):
        self.client = paho.Client(random_generated_names.get_random_client_name())
        try:
            self.client.connect(self.address)
        except Exception as e:
            self.logger.error("Failed to connect to broker")

    def run(self):
        Attack.run(self)
        self.pre_attack_init()

        self.client.loop_start()
        self.logger.info("Random payload fuzzing is started.")

        if self.payload is None:
            length = random.randint(1, self.max_length_of_random_payload)
            self.payload = "".join([chr(random.randint(1, 127)) for _ in range(length)])

        for fuzzing in range(self.turn):

            if self.stopped_flag is True:
                break

            while True:
                try:
                    returned_strings = rdm.get_ascii_decodable_radamsa_malformed_input(self.payload, self.count)
                    if type(returned_strings) == list:
                        fuzzer_messages = [string.decode("utf-8") for string in returned_strings]
                    else:
                        fuzzer_messages = returned_strings.decode("utf-8")
                    break
                except UnicodeDecodeError:
                    self.logger.debug("Error occurred while decoding payload in random payload fuzzing.")
                    continue
            # Check whether result is list or not
            if type(fuzzer_messages) == list:
                for message in fuzzer_messages:
                    self.client.publish(self.topic, message)
                    # Increment sent message count
                    self.sent_message_count += 1
            else:
                self.client.publish(self.topic, fuzzer_messages)
                # Increment sent message count
                self.sent_message_count += 1
            time.sleep(1)
            self.logger.info("Turn {0} is completed with message content = {1}".format(fuzzing + 1, fuzzer_messages))

        self.client.loop_stop()
        self.logger.info("Random payload fuzzing is finished.")


class TestMQTTRandomPayloadAttack(unittest.TestCase):
    def setUp(self):
        self.mqtt_random_payload_fuzzer = MQTTRandomPayloadFuzzingAttack()

    def tearDown(self):
        pass

    def test_name(self):
        self.assertEqual("MQTT Random Payload Fuzzing Attack", self.mqtt_random_payload_fuzzer.get_attack_name())

    def test_inputs(self):
        inputs = self.mqtt_random_payload_fuzzer.get_inputs()
        self.assertIsNotNone(inputs)
        self.assertGreater(len(inputs), 0, "Non inserted inputs")
        self.assertEquals(len(inputs), 5)

    def test_non_initialized_inputs(self):
        inputs = self.mqtt_random_payload_fuzzer.get_inputs()
        for _input in inputs:
            value = getattr(self.mqtt_random_payload_fuzzer, _input.get_name())
            self.assertTrue(value is None or type(value) == _input.get_type())

    def test_after_getting_inputs(self):
        example_inputs = ["a.b.c.d", "pen-topic", 12, 2, "pen-payload"]
        for index, _input in enumerate(example_inputs):
            self.mqtt_random_payload_fuzzer.inputs[index].set_value(_input)

        # Previously it should not be set
        self.assertIsNone(self.mqtt_random_payload_fuzzer.client)

        super(MQTTRandomPayloadFuzzingAttack, self.mqtt_random_payload_fuzzer).run()

        inputs = self.mqtt_random_payload_fuzzer.get_inputs()
        for index, _input in enumerate(inputs):
            value = getattr(self.mqtt_random_payload_fuzzer, _input.get_name())
            self.assertEqual(example_inputs[index], value)

    def test_invalid_fuzzing_turn(self):
        example_inputs = ["127.0.0.1", "peniot-topic", 1]
        for index, _input in enumerate(example_inputs):
            self.mqtt_random_payload_fuzzer.inputs[index].set_value(_input)

        super(MQTTRandomPayloadFuzzingAttack, self.mqtt_random_payload_fuzzer).run()
        try:
            self.mqtt_random_payload_fuzzer.pre_attack_init()
        except AssertionError as e:
            self.assertTrue(True)

    def test_random_payload_fuzzing_attack(self):
        def run_attack():
            example_inputs = ["127.0.0.1", "peniot/test", 3, 1, "peniot-bbdep"]
            for index, _input in enumerate(example_inputs):
                self.mqtt_random_payload_fuzzer.inputs[index].set_value(_input)

            try:
                self.mqtt_random_payload_fuzzer.run()
            except Exception as e:
                self.assertTrue(False)

        print "* If server is not initialized this test will not execute properly."
        p = multiprocessing.Process(target=run_attack, name="Random Payload Fuzzing Attack")
        p.start()
        time.sleep(5)
        if p.is_alive():
            p.terminate()
            p.join()


if __name__ == '__main__':
    unittest.main()
