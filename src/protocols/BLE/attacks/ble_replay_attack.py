import logging

from Entity.attack import Attack
from Entity.input_format import InputFormat
from protocols.BLE.ble_replay_attack import BLEReplayAttackHelper


class BLEReplayAttack(Attack):
    """
    BLE Protocol - BLE Replay Attack Module
    """
    # Input Fields
    file_path = None

    def __init__(self):
        default_parameters = [""]
        inputs = [
            InputFormat("File Path", "file_path", "", str, mandatory=True, from_captured_packets=True),
        ]

        Attack.__init__(self, "BLE Replay Attack", inputs, default_parameters, "BLE Replay Attack Definition")

        logging.basicConfig(level=logging.DEBUG, format="%(asctime)s:%(levelname)s:%(name)s:%(message)s")

    def run(self):
        super(BLEReplayAttack, self).run()
        BLEReplayAttackHelper(self.file_path)

    def stop_attack(self):
        pass  # Since this attack is so short there is no need to a stop routine.
