import unittest

from Entity.protocol import Protocol


class AMQP(Protocol):

    def __init__(self):
        amqp_definition = "AMQP stands for Advanced Message Queuing Protocol and it is an open standard application layer protocol.\n\n" \
                          "There are a couple of key parts in AMQP:\n" \
                          "* Broker (Server): An application - implementing the AMQP model - that accepts connections from clients\n" \
                          " for message routing, queuing etc.\n" \
                          "* Message: Content of data transferred / routed including information such as payload and message attributes.\n" \
                          "* Consumer: An application which receives message(s) - put by a producer - from queues.\n" \
                          "* Producer: An application which puts messages to a queue."
        attack_suites = []
        Protocol.__init__(self, "AMQP", attack_suites, amqp_definition)


class TestAMQPProtocol(unittest.TestCase):
    def setUp(self):
        self.amqp = AMQP()

    def tearDown(self):
        pass

    def test_name(self):
        self.assertEqual("AMQP", self.amqp.get_protocol_name())

    def test_attacks(self):
        attack_suites = self.amqp.get_attack_suites()
        self.assertIsNotNone(attack_suites)
        self.assertEquals(len(attack_suites), 0)


if __name__ == '__main__':
    unittest.main()
