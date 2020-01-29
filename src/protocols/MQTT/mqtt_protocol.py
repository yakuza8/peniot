from Entity.protocol import Protocol

import unittest


class MQTT(Protocol):

    def __init__(self):
        mqtt_definition = "MQTT is an application layer internet of things (IoT) protocol. " \
                          "It is mainly a messaging protocol. At the center of MQTT, there exists a central broker " \
                          "that acts as a server.Each client connected to that broker can open a topic " \
                          "and publish messsages to that topic.Then any client connected to a broker can subscribe to the " \
                          "topics stored on that broker.More than one client can subscribe to a single topic.\n\n" \
                          "Clients communicate via publishing and subscring to topics that they are interested. Main duties of " \
                          "the broker are storing topics, storing the messages published on these topics and then sending the " \
                          "published messages to the clients subscribed to that particular topic. More explicitly, when a " \
                          "message is published by a client to a topic, first the broker stores that message in the memory space " \
                          "that it had allocated for that topic. Then the broker sends that message to every single client that " \
                          "had subscribed to that topic. Existence of a working broker is essential, without a central broker " \
                          "clients cannot communicate among themselves.\n\n" \
                          "Aforementioned structure of the MQTT makes the broker main target of cyber attacks. Therefore, it " \
                          "is very important that security configurations of the MQTT broker are set correctly. However, " \
                          "this does not mean client security is not important. Clients should be configured in a way that " \
                          "they can handle unexpected inputs without facing a failure. From our MQTT attacks menu, you can choose " \
                          "from a list of attacks to test your devices. You can get more information about each attack from " \
                          "the attacks page."
        attack_suites = []
        Protocol.__init__(self, "MQTT", attack_suites, mqtt_definition)


class TestMQTTProtocol(unittest.TestCase):
    def setUp(self):
        self.mqtt = MQTT()

    def tearDown(self):
        pass

    def test_name(self):
        self.assertEqual("MQTT", self.mqtt.get_protocol_name())

    def test_attacks(self):
        attack_suites = self.mqtt.get_attack_suites()
        self.assertIsNotNone(attack_suites)
        self.assertEquals(len(attack_suites), 0)


if __name__ == '__main__':
    unittest.main()
