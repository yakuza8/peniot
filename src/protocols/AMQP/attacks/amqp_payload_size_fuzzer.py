import logging
import multiprocessing
import random
import signal
import time
import unittest

import pika

from Entity.attack import Attack
from Entity.input_format import InputFormat


class AMQPPayloadSizeFuzzerAttack(Attack):
    """
    AMQP Protocol - Payload Size Fuzzer Attack module
    It is created to test any AMQP device as black box test with malformed or semi-malformed inputs
    """
    # Input Fields
    host = "localhost"
    queue = "peniot-queue"
    exchange = "peniot-exchange"
    routing_key = "peniot-routing-key"
    payload = None
    exchange_type = "direct"
    turn = 10

    # Misc Members
    connection = None
    channel = None
    logger = None
    sent_message_count = 0
    max_payload_length = 2 ** 32
    stopped_flag = False

    def __init__(self):
        default_parameters = ["", "", "", "", "", "", 10]
        inputs = [
            InputFormat("Host Name", "host", "localhost", str, mandatory=True),
            InputFormat("Queue Name", "queue", "peniot-queue", str, mandatory=True),
            InputFormat("Exchange Name", "exchange", "peniot-exchange", str, mandatory=True),
            InputFormat("Routing Key", "routing_key", "peniot-routing-key", str, mandatory=True),
            InputFormat("Payload", "payload", "", str, mandatory=True),
            InputFormat("Exchange Type", "exchange_type", "direct", str, mandatory=True),
            InputFormat("Fuzzing Turn", "turn", 10, int)
        ]
        Attack.__init__(self, "AMQP Payload Size Fuzzer Attack", inputs, default_parameters,
                        "    AMQP Payload size fuzzer attack description")

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
        try:
            assert self.turn >= 2
        except AssertionError as e:
            raise
        # Get connection and channel
        self.connection = pika.BlockingConnection(pika.ConnectionParameters(host=self.host))
        self.channel = self.connection.channel()

        # Create exchange
        self.channel.exchange_declare(exchange=self.exchange, exchange_type=self.exchange_type)

        # Define queue to store
        self.channel.queue_declare(queue=self.queue)

    def run(self):
        Attack.run(self)
        self.pre_attack_init()

        assert self.turn >= 2
        # Fill the size list as randomly generated
        size_list = [0, self.max_payload_length]
        size_list.extend([random.randint(0, self.max_payload_length) for _ in range(self.turn - 2)])

        fuzzing = 0
        self.logger.info("Size payload fuzzing is started. Please consider it may take some time.")
        for payload_size in size_list:

            if self.stopped_flag is True:
                break
            # Create payload and send it
            random_strings = "".join([chr(_) for _ in range(65, 91)]) + "".join([chr(_) for _ in range(97, 123)])
            random_character = random.choice(random_strings)
            sized_payload = random_character * payload_size
            self.channel.basic_publish(exchange=self.exchange, routing_key=self.routing_key, body=sized_payload)

            # Informative procedures
            self.logger.info("Turn {0} is completed".format(fuzzing + 1))
            self.sent_message_count += 1
            fuzzing += 1
            time.sleep(1)

        if self.stopped_flag is False:
            self.logger.info("Payload size attack is finished.")


class TestCoAPPayloadSizeAttack(unittest.TestCase):
    def setUp(self):
        self.amqp_payload_size_fuzzer = AMQPPayloadSizeFuzzerAttack()

    def tearDown(self):
        pass

    def test_name(self):
        self.assertEqual("AMQP Payload Size Fuzzer Attack", self.amqp_payload_size_fuzzer.get_attack_name())

    def test_inputs(self):
        inputs = self.amqp_payload_size_fuzzer.get_inputs()
        self.assertIsNotNone(inputs)
        self.assertGreater(len(inputs), 0, "Non inserted inputs")
        self.assertEquals(len(inputs), 7)

    def test_non_initialized_inputs(self):
        inputs = self.amqp_payload_size_fuzzer.get_inputs()
        for _input in inputs:
            value = getattr(self.amqp_payload_size_fuzzer, _input.get_name())
            self.assertTrue(value is None or type(value) == _input.get_type())

    def test_after_getting_inputs(self):
        example_inputs = ["localhost", "peniot-queue", "peniot-exchange", "peniot-routing-key", "peniot-body", "direct",
                          5]
        for index, _input in enumerate(example_inputs):
            self.amqp_payload_size_fuzzer.inputs[index].set_value(_input)

        # Previously it should not be set
        self.assertIsNone(self.amqp_payload_size_fuzzer.connection)

        super(AMQPPayloadSizeFuzzerAttack, self.amqp_payload_size_fuzzer).run()

        inputs = self.amqp_payload_size_fuzzer.get_inputs()
        for index, _input in enumerate(inputs):
            value = getattr(self.amqp_payload_size_fuzzer, _input.get_name())
            self.assertEqual(example_inputs[index], value)

    def test_invalid_fuzzing_turn(self):
        example_inputs = ["localhost", "peniot-queue", "peniot-exchange", "peniot-routing-key", "peniot-body", "direct",
                          1]
        for index, _input in enumerate(example_inputs):
            self.amqp_payload_size_fuzzer.inputs[index].set_value(_input)

        super(AMQPPayloadSizeFuzzerAttack, self.amqp_payload_size_fuzzer).run()
        try:
            self.amqp_payload_size_fuzzer.pre_attack_init()
        except AssertionError as e:
            self.assertTrue(True)

    def test_payload_size_fuzzing_attack(self):
        def run_attack():
            example_inputs = ["localhost", "peniot-queue", "peniot-exchange", "peniot-routing-key", "peniot-body",
                              "direct", 3]
            for index, _input in enumerate(example_inputs):
                self.amqp_payload_size_fuzzer.inputs[index].set_value(_input)

            try:
                self.amqp_payload_size_fuzzer.run()
            except Exception as e:
                self.assertTrue(False)

        print "* If server is not initialized this test will not execute properly."
        p = multiprocessing.Process(target=run_attack, name="DoS Attack")
        p.start()
        time.sleep(5)
        if p.is_alive():
            p.terminate()
            p.join()


if __name__ == '__main__':
    unittest.main()
