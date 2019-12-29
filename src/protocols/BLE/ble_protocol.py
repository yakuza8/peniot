from Entity.protocol import Protocol


class BLE(Protocol):

    def __init__(self):
        ble_definition = ""
        attack_suites = []
        Protocol.__init__(self, "BLE", attack_suites, ble_definition)
