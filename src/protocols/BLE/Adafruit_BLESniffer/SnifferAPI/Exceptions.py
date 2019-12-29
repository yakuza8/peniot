class SnifferTimeout(Exception):
    pass


class UARTPacketError(Exception):
    pass


class InvalidPacketException(Exception):
    pass

# Internal Use


class SnifferWatchDogTimeout(SnifferTimeout):
    pass

# Internal Use


class ExitCodeException(Exception):
    pass
