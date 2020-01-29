import logging
import multiprocessing
import signal
import time
import unittest

import paho.mqtt.client as paho

from Entity.attack import Attack
from Entity.input_format import InputFormat
from Utils.RandomUtil import random_generated_names


class MQTTTopicNameFuzzingAttack(Attack):
    """
    MQTT Protocol - Topic Name Fuzzer Attack module
    It is created to test any MQTT device as black box test with malformed or semi-malformed inputs
    """
    client = None

    # Input Fields
    address = None
    client2_name = None

    # Misc Members
    logger = None

    def __init__(self):
        default_parameters = ["127.0.0.1", ""]
        inputs = [
            InputFormat("Broker Address", "address", "", str, mandatory=True),
            InputFormat("Client Name", "client2_name", "", str, mandatory=True)
        ]

        Attack.__init__(self, "MQTT Topic Name Fuzzing Attack", inputs, default_parameters,
                        "    MQTT Topic Name Fuzzing Attack description")

        logging.basicConfig(level=logging.DEBUG, format="%(asctime)s:%(levelname)s:%(name)s:%(message)s")

        # Signal handler to exit from function
        signal.signal(signal.SIGINT, self.signal_handler)

    def signal_handler(self, sig, frame):
        self.stop_attack()

    def stop_attack(self):
        self.logger.info("MQTT topic name fuzzing is interrupted, exitting...")
        if self.client is not None:
            self.client.disconnect()  # Close the connection before exitting
        time.sleep(2)  # Sleep two seconds so the user can see the message
        # sys.exit(0)

    def pre_attack_init(self):
        self.client = paho.Client(random_generated_names.get_random_client_name())
        try:
            self.client.connect(self.address)
        except Exception as e:  # We may fail to connect the broker if the adress is invalid so except it
            self.logger.error("Failed to connect to broker")

    def run(self):
        Attack.run(self)
        self.pre_attack_init()

        self.client.publish(self.client2_name + "/status", "topic_name_fuzzing_type_1")
        print "Please check if the attacked client continues working"

        er = self.client.subscribe("$SYS/#", 1)

        if er[0] == 0:
            self.logger.info("Successfully subscribed to all system topics. ALERT!")
            self.client.unsubscribe("$SYS/#")
        else:
            self.logger.info("Failed to subscribe to all system topics. Very good!")

        # Trying to publish to a system topic, change the number of clients connected
        self.logger.info(
            "Please check from the broker monitor if 999 is published to $SYS/broker/clients/connected, it will be published in a seconds!")
        time.sleep(2)
        self.client.publish("$SYS/broker/clients/connected", 999)
        self.logger.info("Please check from the broker monitor if 999 is published to $SYS/broker/clients/connected.")


class TestMQTTTopicNameFuzzingAttack(unittest.TestCase):
    def setUp(self):
        self.mqtt_topic_name_fuzzer = MQTTTopicNameFuzzingAttack()

    def tearDown(self):
        pass

    def test_name(self):
        self.assertEqual("MQTT Topic Name Fuzzing Attack", self.mqtt_topic_name_fuzzer.get_attack_name())

    def test_inputs(self):
        inputs = self.mqtt_topic_name_fuzzer.get_inputs()
        self.assertIsNotNone(inputs)
        self.assertGreater(len(inputs), 0, "Non inserted inputs")
        self.assertEquals(len(inputs), 2)

    def test_non_initialized_inputs(self):
        inputs = self.mqtt_topic_name_fuzzer.get_inputs()
        for _input in inputs:
            value = getattr(self.mqtt_topic_name_fuzzer, _input.get_name())
            self.assertTrue(value is None or type(value) == _input.get_type())

    def test_after_getting_inputs(self):
        example_inputs = ["a.b.c.d", "peniot-test-cli"]
        for index, _input in enumerate(example_inputs):
            self.mqtt_topic_name_fuzzer.inputs[index].set_value(_input)

        # Previously it should not be set
        self.assertIsNone(self.mqtt_topic_name_fuzzer.client)

        super(MQTTTopicNameFuzzingAttack, self.mqtt_topic_name_fuzzer).run()

        inputs = self.mqtt_topic_name_fuzzer.get_inputs()
        for index, _input in enumerate(inputs):
            value = getattr(self.mqtt_topic_name_fuzzer, _input.get_name())
            self.assertEqual(example_inputs[index], value)

    def test_payload_size_fuzzing_attack(self):
        def run_attack():
            example_inputs = ["127.0.0.1", "peniot-cli"]
            for index, _input in enumerate(example_inputs):
                self.mqtt_topic_name_fuzzer.inputs[index].set_value(_input)

            try:
                self.mqtt_topic_name_fuzzer.run()
            except Exception as e:
                self.assertTrue(False)

        print "* If server is not initialized this test will not execute properly."
        p = multiprocessing.Process(target=run_attack, name="Topic Name Fuzzing Attack")
        p.start()
        time.sleep(5)
        if p.is_alive():
            p.terminate()
            p.join()


if __name__ == '__main__':
    unittest.main()
