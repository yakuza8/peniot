import pexpect


class BLEDevice:
    """
    Represents a BLE device.
    It uses `gatttool` to connect a BLE device.
    """

    def __init__(self, address):
        self.device = None
        self.address = address
        # connect to the device specified with the given address
        self.connect()

    def connect(self):
        """
        Connects to the BLE device
        """
        print "Connecting..."
        # Run gatttool interactively.
        self.device = pexpect.spawn("gatttool -b " + self.address + " -I")
        self.device.expect('\[LE\]>', timeout=10)
        self.device.sendline('connect')
        self.device.expect('Connection successful.*\[LE\]>', timeout=10)
        print "Successfully connected!"

    """
        Updates the value of the handle
    """

    def writecmd(self, handle, value):
        cmd = "char-write-cmd " + handle + " " + value
        self.device.sendline(cmd)
        print "Wrote " + value + " to handle: " + handle
