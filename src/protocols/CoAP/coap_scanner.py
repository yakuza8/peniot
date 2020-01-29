from Utils.SnifferUtil import generic_sniffer as generic_sniffer

import socket

# Capturing via TShark
coap_layer_filter = 'coap'


class CoAPScanner:
    """
    This class is used to scan for a CoAP device.
    It captures packets from the network and try to find CoAP devices.
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
                                                 display_filter=coap_layer_filter)
        sniffer.start_live_capture()
        return sniffer.get_captured_packets()

    @staticmethod
    def get_raw_udp_payload_as_bytes(packet):
        return (packet.coap_raw.value[0]).decode("hex")

    @staticmethod
    def get_raw_frame_as_bytes(packet):
        return (packet.frame_raw.value[0]).decode("hex")


if __name__ == '__main__':
    raw = False
    packets = CoAPScanner().scan()
    """
    for i in packets:
        # Send messages to server as replayed
        if raw:
            if "<DATA Layer>" not in str(i.layers):
                udp_payload = CoAPScanner.get_raw_udp_payload_as_bytes(i)
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(udp_payload, ("127.0.0.1", 5683))
        else:
            print i
    """
