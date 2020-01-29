from Utils.SnifferUtil import generic_sniffer as generic_sniffer

# Capturing via TShark
amqp_layer_filter = "amqp"


class AMQPScanner:
    """
    This class is used to scan for a AMQP device.
    It captures packets from the network and try to find AMQP devices.
    """

    def __init__(self):
        pass

    @staticmethod
    def scan(timeout=generic_sniffer.DEFAULT_SNIFF_TIMEOUT, interface=generic_sniffer.DEFAULT_INTERFACE,
             use_json_and_include_raw=False, output_pcap_filename=None):
        sniffer = generic_sniffer.GenericSniffer(timeout=timeout, interface=interface,
                                                 use_json=use_json_and_include_raw,
                                                 include_raw=use_json_and_include_raw,
                                                 output_pcap_filename=output_pcap_filename,
                                                 display_filter=amqp_layer_filter)
        sniffer.start_live_capture()
        return sniffer.get_captured_packets()


if __name__ == '__main__':
    packets = AMQPScanner().scan()
    for packet in packets:
        print packet
