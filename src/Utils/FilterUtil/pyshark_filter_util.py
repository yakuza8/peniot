import logging

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s:%(levelname)s:%(name)s : %(message)s")
logger = logging.getLogger("Util - PyShark Filter")


class PySharkFilter:
    """
    Container class for internally represented pyshark filter
    where filter has layer_name, field_nane and value to be checked while filter
    """
    def __init__(self, layer_name, field_name, value):
        self.layer_name = layer_name
        self.field_name = field_name
        self.value = value

    def set_layer_name(self, layer_name):
        self.layer_name = layer_name
        return self

    def get_layer_name(self):
        return self.layer_name

    def set_field_name(self, field_name):
        self.field_name = field_name
        return self

    def get_field_name(self):
        return self.field_name

    def set_value(self, value):
        self.value = value
        return self

    def get_value(self):
        return self.value

    def apply_filter_to_packet(self, packet):
        """
        Apply filter to packet, if exists check value equality otherwise return False
        :param packet: Packet to be filtered
        :return: Whether packet is the same value with filter value
        """
        try:
            return packet[self.layer_name].get_field_value(self.field_name).main_field.raw_value == unicode(self.value)
        except KeyError:
            logger.error("Given layer name or field name is not defined in packet!")
            return False

