from Entity.attack import Attack
from Entity.input_format import InputFormat
from Utils import CommonUtil
from Utils.SnifferUtil import generic_sniffer

import logging
import signal
import sys
import time
import unittest

from protocols.CoAP.coap_scanner import CoAPScanner

"""
    CoAP Protocol - Sniff Attack module
    It is created to scan/sniff the devices for their information
"""


class CoAPSniffAttack(Attack):
    # Input Fields
    timeout = generic_sniffer.DEFAULT_SNIFF_TIMEOUT
    interface = generic_sniffer.DEFAULT_INTERFACE
    save_output = generic_sniffer.DEFAULT_SAVE

    # Miscellaneous Members
    logger = None

    def __init__(self):
        default_parameters = [10.0, generic_sniffer.DEFAULT_INTERFACE, generic_sniffer.DEFAULT_SAVE]
        inputs = [
            InputFormat("Timeout", "timeout", self.timeout, float),
            InputFormat("Interface", "interface", str(self.interface), str, mandatory=True),
            InputFormat("Save Captured Packets", "save_output", str(self.save_output), bool)
        ]

        Attack.__init__(self, "CoAP Sniff Attack", inputs, default_parameters,
                        "    It listens to the network traffic and\n"
                        "    captures CoAP packets.")

        logging.basicConfig(level=logging.DEBUG, format="%(asctime)s:%(levelname)s:%(name)s:%(message)s")

        # Signal handler to exit from function
        signal.signal(signal.SIGINT, self.signal_handler)

    def signal_handler(self, sig, frame):
        self.stop_attack()

    def stop_attack(self):
        self.logger.info("Exitting...")
        time.sleep(2)  # Sleep two seconds so the user can see the message

    def run(self):
        super(CoAPSniffAttack, self).run()
        packets = CoAPScanner().scan(self.timeout, self.interface,
                                     output_pcap_filename="CoAP_" + CommonUtil.get_current_datetime_for_filename_format() if self.save_output else None)

        for packet in packets:
            self.logger.info(packet)

        return packets


class TestCoAPSniffAttack(unittest.TestCase):
    def setUp(self):
        self.coap_sniff_attack = CoAPSniffAttack()

    def tearDown(self):
        pass

    def testName(self):
        self.assertEqual("CoAP Sniff Attack", self.coap_sniff_attack.get_attack_name())

    def testNonInitializedInputs(self):
        inputs = self.coap_sniff_attack.get_inputs()
        for _input in inputs:
            value = getattr(self.coap_sniff_attack, _input.get_name())
            self.assertTrue(value is None or type(value) == _input.get_type())

    def testAfterGettingInputs(self):
        example_inputs = [13.2, "test-interface", False]
        for index, _input in enumerate(example_inputs):
            self.coap_sniff_attack.inputs[index].set_value(_input)

        super(CoAPSniffAttack, self.coap_sniff_attack).run()

        inputs = self.coap_sniff_attack.get_inputs()
        for index, _input in enumerate(inputs):
            value = getattr(self.coap_sniff_attack, _input.get_name())
            self.assertEqual(example_inputs[index], value)

    def testSniffAttack(self):
        example_inputs = [10.0]
        for index, _input in enumerate(example_inputs):
            self.coap_sniff_attack.inputs[index].set_value(_input)

        packets = self.coap_sniff_attack.run()
        self.assertIsNotNone(packets)
        self.assertTrue(type(packets) == list)
        self.assertGreaterEqual(len(packets), 0)


if __name__ == '__main__':
    unittest.main()
