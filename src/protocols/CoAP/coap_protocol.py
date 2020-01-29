from Entity.protocol import Protocol

import unittest


class CoAP(Protocol):

    def __init__(self):
        co_ap_definition = "CoAP (Constrained Application Protocol) is designed as a lightweight machine-to-machine " \
                          "(M2M) protocol that can run on smart devices where memory and computing resources are " \
                          "scarce.\n\n" \
                          "The protocol is especially targeted for constrained hardware such as 8-bits microcontrollers " \
                          ",low power sensors and similar devices that can not run on HTTP or TLS. CoAP is a " \
                          "simplification of the HTTP protocol running on UDP, that helps save bandwidth. But just " \
                          "like any other UDP-based protocol, CoAP is inherently susceptible to IP address " \
                          "spoofing and packet amplification, the two major factors that enable the amplification of " \
                          " a DDoS attack.\n\nLike HTTP, CoAP is based on the wildly successful REST model: Servers " \
                          "make resources available under a URL, and clients access these resources using methods " \
                          "such as GET, PUT, POST, and DELETE.\n\nCoAP can carry different types of payloads, and " \
                          "can identify which payload type is being used. CoAP integrates with XML, JSON, CBOR, or " \
                          "any data format of your choice.\n\nCoAP is designed to use minimal resources, both on " \
                          "the device and on the network. Instead of a complex transport stack, it gets by with UDP " \
                          "on IP. A 4-byte fixed header and a compact encoding of options enables small messages that" \
                          "cause no or little fragmentation on the link layer. Many servers can operate in a " \
                          "completely stateless fashion."

        attack_suites = []
        Protocol.__init__(self, "CoAP", attack_suites, co_ap_definition)


class TestCoAPProtocol(unittest.TestCase):
    def setUp(self):
        self.coap = CoAP()

    def tearDown(self):
        pass

    def test_name(self):
        self.assertEqual("CoAP", self.coap.get_protocol_name())

    def test_attacks(self):
        attack_suites = self.coap.get_attack_suites()
        self.assertIsNotNone(attack_suites)
        self.assertEquals(len(attack_suites), 0)


if __name__ == '__main__':
    unittest.main()
