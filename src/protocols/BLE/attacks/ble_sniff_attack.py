import logging

from Entity.attack import Attack
from Entity.input_format import InputFormat
from protocols.BLE.ble_sniff import BLESniffer


class BLESniffAttack(Attack):
    """
    BLE Protocol - BLE Sniff Attack Module
    """
    # Input Fields
    port = "/dev/ttyUSB0"
    bleSni = None

    def __init__(self):
        default_parameters = ["/dev/ttyUSB0"]
        inputs = [
            InputFormat("Port", "port", self.port, str, mandatory=True),
        ]

        Attack.__init__(self, "BLE Sniffing", inputs, default_parameters, "BLE Sniff Definition")

        logging.basicConfig(level=logging.DEBUG, format="%(asctime)s:%(levelname)s:%(name)s:%(message)s")

    def run(self):
        self.bleSni = BLESniffer(
            self.port)  # if we initialize this in init, it gives an error when we want to go back after an attack
        super(BLESniffAttack, self).run()
        self.bleSni.run()

    def signal_handler(self, sig, frame):
        self.stop_attack()

    def stop_attack(self):
        self.bleSni.stop_attack()
