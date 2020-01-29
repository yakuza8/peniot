from Utils.SnifferUtil import generic_sniffer as generic_sniffer

from scapy.all import *

# Since MQTT runs on TCP/IP, we filter captured packets using TCP protocol
mqtt_filter = "tcp"
# 1883 and 8883 ports are reserved for MQTT protocol
mqtt_port = 1883
mqtt_port_ssl = 8883

# Capturing via TShark
mqtt_layer_filter = "mqtt"


class MQTTScanner:
    """
    This class is used to scan for a MQTT device.
    It captures packets from the network and try to find MQTT devices.
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
                                                 display_filter=mqtt_layer_filter)
        sniffer.start_live_capture()
        return sniffer.get_captured_packets()

    @staticmethod
    def get_raw_tcp_payload_as_bytes(packet):
        return (packet.mqtt_raw.value[0]).decode("hex")

    @staticmethod
    def get_raw_frame_as_bytes(packet):
        return (packet.frame_raw.value[0]).decode("hex")

    '''
    @staticmethod
    def scan(count, interface, timeout, mac_address=None, src_dst=None):
        """
        Scans the network to find MQTT devices and returns the packets
        if mac_address and src_dst parameters are provided,then we will search for a specific device
        :param count: the total number of packets to be captured
        :param interface: the interface to be scanned
        :param timeout: the time out value to give finish scanning (in sec)
        :param mac_address: MAC address of the device
        :param src_dst: if src_dst is 0, then we will check packets' source field, if it is 1,then we will check
                        packets' destination field
        :return: packets found
        """
        packets = []
        if src_dst is not None and mac_address is not None:
            mac_address = mac_address.lower()  # it should contain lower case chars
            if src_dst == 0:  # check source field
                packets = sniff(count=count, iface=interface, timeout=timeout, filter=mqtt_filter,
                                lfilter=lambda d: d.src == mac_address)
            elif src_dst == 1:  # check destination field
                packets = sniff(count=count, iface=interface, timeout=timeout, filter=mqtt_filter,
                                lfilter=lambda d: d.dst == mac_address)
        else:
            packets = sniff(count=count, iface=interface, timeout=timeout, filter=mqtt_filter)
        packets_found = []  # the packets we found
        for i in range(0, len(packets)):
            if packets[i]['TCP'].sport == mqtt_port or packets[i]['TCP'].dport == mqtt_port_ssl:
                packets_found.append(packets[i])
        return packets_found

    @staticmethod
    def scan_file(count, interface, file_name, mac_address=None, src_dst=None):
        """
        Scans the given packet file to find MQTT devices and returns the packets
        if mac_address and src_dst parameters are provided,then we will search for a specific device
        :param count: the total number of packets to be captured
        :param interface: the interface to be scanned
        :param file_name: the name of file to be checked to find a MQTT device
        :param mac_address: MAC address of the device
        :param src_dst: if src_dst is 0, then we will check packets' source field, if it is 1,then we will check
                        packets' destination field
        :return: packets found
        """
        packets = []
        if src_dst is not None and mac_address is not None:
            mac_address = mac_address.lower()  # it should contain lower case chars
            if src_dst == 0:  # check source field
                packets = sniff(count=count, iface=interface, offline=file_name, filter=mqtt_filter,
                                lfilter=lambda d: d.src == mac_address)
            elif src_dst == 1:  # check destination field
                packets = sniff(count=count, iface=interface, offline=file_name, filter=mqtt_filter,
                                lfilter=lambda d: d.dst == mac_address)
        else:
            packets = sniff(count=count, iface=interface, offline=file_name, filter=mqtt_filter)
        packets_found = []  # the packets we found
        for i in range(0, len(packets)):
            if MQTTScanner.check_port(packets[i]['TCP']):
                packets_found.append(packets[i])
        return packets_found

    @staticmethod
    def check_port(packet_param):
        """
        Checks whether the packet has a MQTT port as source or destination port number.
        :param packet_param: the packet to be checked
        :return:
        """
        if packet_param.sport == mqtt_port_ssl or packet_param.sport == mqtt_port or \
        packet_param.dport == mqtt_port or packet_param.dport == mqtt_port_ssl:
            return True
        return False
    '''


if __name__ == '__main__':
    packets = MQTTScanner().scan()
