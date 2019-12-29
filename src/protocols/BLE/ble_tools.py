from bluepy import btle

"""
    This class enables us to scan for BLE devices. 
"""


class BLEScanner:
    """
    Scan for BLE devices and returns these devices as ScanEntry

    :param interface the Bluetooth interface
    :param timeout how long scan operation takes (in seconds)
    :return A list of ScanEntry objects
    """
    @staticmethod
    def scan(interface, timeout):
        scanner = btle.Scanner(interface)
        entries = scanner.scan(timeout)
        return entries



"""
    This class is used to create a connection with the device
    Then, we can access its services or characteristics using the class methods
"""


class BLEPeripheral:
    """
    Using the given parameters, create a connection with the device
    :param address MAC address of the device
    :param address_type fixed (btle.ADDR_TYPE_PUBLIC) or random (btle.ADDR_TYPE_RANDOM) address types
    :param the Bluetooth interface on which the connection is set
    """
    def __init__(self, address, address_type, interface):
        self.device = btle.Peripheral(address, address_type, interface)

    def getServices(self):
        """
        This method gets the services (a list of btle.Service) which are provided by BLE device
        """
        return self.device.getServices()

    def getCharacteristics(self):
        """
        This method gets the characteristics (a list of btle.Characteristics) which are provided bu BLE device
        """
        return self.device.getCharacteristics()

    def getAddress(self):
        """
        Methods to get properties of the device
        """
        return self.device.addr

    def getAddressType(self):
        return self.device.addrType

    def getInterface(self):
        return self.device.iface