import logging
import os

import pyshark
from Utils.FilterUtil import pyshark_filter_util as pyshark_filter_util

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s:%(levelname)s:%(name)s : %(message)s")
logger = logging.getLogger("Generic Sniffer")

DEFAULT_INTERFACE = "any"
DEFAULT_SNIFF_TIMEOUT = 15.
DEFAULT_SAVE = False
DEFAULT_SAVE_DIR = os.path.dirname(os.path.abspath(__file__)) + "/../../captured_packets/"


def filter_packets_by_filter_list(packets, filter_list):
    """
    :param packets: Packet list
    :param filter_list: Filters with respect to packet field
    :type filter_list: list of pyshark_filter_util.PySharkFilter
    :return: Filtered packets as list
    """

    filtered_packets = [packet for packet in packets
                        if all(single_filter.apply_filter_to_packet(packet) for single_filter in filter_list)]
    return filtered_packets


class GenericSniffer:
    """
    Generic sniffer template class
    The class can listen specific interface by tshark over pyshark
    and filter wanted packets by looking at display filter parameter
    with the given timeout amount
    """

    def __init__(self, timeout=DEFAULT_SNIFF_TIMEOUT, interface=DEFAULT_INTERFACE, use_json=False, include_raw=False,
                 output_pcap_filename=None, output_dir=DEFAULT_SAVE_DIR, display_filter=None):
        self.captured_packets = None

        self.timeout = timeout
        self.interface = interface
        self.use_json = use_json
        self.include_raw = include_raw
        # Default value is None and it is important to have it None since it will not produce file in this case
        if output_pcap_filename is None:
            self.output_pcap_filename = None
        else:
            self.output_pcap_filename = "{0}{1}{2}".format(output_dir, output_pcap_filename,
                                                           ("" if output_pcap_filename.endswith(".pcap") else ".pcap"))

        self.display_filter = display_filter

    def start_live_capture(self):
        """
        Start capture procedure of packets over listener
        :return: None since captured packets are saved internally
        """
        capture = pyshark.LiveCapture(interface=self.interface, use_json=self.use_json, include_raw=self.include_raw,
                                      output_file=self.output_pcap_filename, display_filter=self.display_filter)
        capture.sniff(timeout=self.timeout)
        self.captured_packets = capture._packets
        logger.info("{0} packets are captured.".format(len(self.captured_packets)))
        capture.close()

    def get_captured_packets(self):
        """
        :return: Captured packets as list
        """
        return self.captured_packets

    def filter_packets_by_protocol(self, protocol=None):
        """
        Filtering operation of packets via protocol name
        :param protocol: Protocol name which will be used for filtering packets by looking their layers
        :return: Filtered packet list
        """
        if protocol is None:
            return self.captured_packets
        else:
            return filter(lambda packet: protocol in str(packet.layers), self.captured_packets)


if __name__ == '__main__':
    sniffer = GenericSniffer()
    sniffer.start_live_capture()
