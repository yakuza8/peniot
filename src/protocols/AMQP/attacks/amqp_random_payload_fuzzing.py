import logging
import multiprocessing
import random
import signal
import time
import unittest

import pika

from Entity.attack import Attack
from Entity.input_format import InputFormat
from Utils.FuzzerUtil import radamsa_util as rdm


class AMQPRandomPayloadFuzzingAttack(Attack):
    """
    AMQP Protocol - Random Payload Fuzzing Attack module
    """
    # Input Fields
    host = "localhost"
    queue = "peniot-queue"
    exchange = "peniot-exchange"
    routing_key = "peniot-routing-key"
    payload = None
    exchange_type = "direct"
    turn = 10
    count = 1

    # Misc Members
    connection = None
    channel = None
    logger = None
    sent_message_count = 0
    max_length_of_random_payload = 100
    stopped_flag = False

    def __init__(self):
        default_parameters = ["", "", "", "", "", "", 10, 1]
        inputs = [
            InputFormat("Host Name", "host", "localhost", str, mandatory=True),
            InputFormat("Queue Name", "queue", "peniot-queue", str, mandatory=True),
            InputFormat("Exchange Name", "exchange", "peniot-exchange", str, mandatory=True),
            InputFormat("Routing Key", "routing_key", "peniot-routing-key", str, mandatory=True),
            InputFormat("Payload", "payload", "", str),
            InputFormat("Exchange Type", "exchange_type", "direct", str, mandatory=True),
            InputFormat("Fuzzing Turn", "turn", 10, int),
            InputFormat("Fuzzing Count", "count", 1, int)
        ]

        Attack.__init__(self, "AMQP Random Payload Fuzzing Attack", inputs, default_parameters,
                        "    It creates a random payload and sends \n"
                        "    this payload to the client.")

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
        Attack.run(self)
        self.pre_attack_init()

        payload = self.payload
        if payload is None:
            # Create seed with randomly
            length = random.randint(1, self.max_length_of_random_payload)
            payload = "".join([chr(random.randint(1, 127)) for _ in range(length)])

        self.logger.info("Random payload fuzzing is started.")
        for fuzzing in range(self.turn):

            if self.stopped_flag is True:
                break
            while True:
                try:
                    returned_strings = rdm.get_ascii_decodable_radamsa_malformed_input(payload, self.count)
                    if type(returned_strings) == list:
                        fuzzer_messages = [string.decode("utf-8") for string in returned_strings]
                    else:
                        fuzzer_messages = returned_strings.decode("utf-8")
                    break
                except UnicodeDecodeError:
                    continue
            # Check whether result is list or not
            if type(fuzzer_messages) == list:
                for message in fuzzer_messages:
                    self.channel.basic_publish(exchange=self.exchange, routing_key=self.routing_key, body=message)
                    # Increment sent message count
                    self.sent_message_count += 1
            else:
                self.channel.basic_publish(exchange=self.exchange, routing_key=self.routing_key, body=fuzzer_messages)
                # Increment sent message count
                self.sent_message_count += 1
            time.sleep(1)
            self.logger.info("Turn {0} is completed".format(fuzzing + 1))

        if self.stopped_flag is False:
            self.logger.info("Random payload fuzzing is finished.")

        if self.connection is not None:
            self.connection.close()


class TestAMQPRandomPayloadAttack(unittest.TestCase):
    def setUp(self):
        self.amqp_random_payload_fuzzer = AMQPRandomPayloadFuzzingAttack()

    def tearDown(self):
        pass

    def test_name(self):
        self.assertEqual("AMQP Random Payload Fuzzing Attack", self.amqp_random_payload_fuzzer.get_attack_name())

    def test_inputs(self):
        inputs = self.amqp_random_payload_fuzzer.get_inputs()
        self.assertIsNotNone(inputs)
        self.assertGreater(len(inputs), 0, "Non inserted inputs")
        self.assertEquals(len(inputs), 8)

    def test_non_initialized_inputs(self):
        inputs = self.amqp_random_payload_fuzzer.get_inputs()
        for _input in inputs:
            value = getattr(self.amqp_random_payload_fuzzer, _input.get_name())
            self.assertTrue(value is None or type(value) == _input.get_type())

    def test_after_getting_inputs(self):
        example_inputs = ["localhost", "peniot-queue", "peniot-exchange", "peniot-routing-key", "peniot-body", "direct",
                          13, 12]
        for index, _input in enumerate(example_inputs):
            self.amqp_random_payload_fuzzer.inputs[index].set_value(_input)

        # Previously it should not be set
        self.assertIsNone(self.amqp_random_payload_fuzzer.connection)

        super(AMQPRandomPayloadFuzzingAttack, self.amqp_random_payload_fuzzer).run()

        inputs = self.amqp_random_payload_fuzzer.get_inputs()
        for index, _input in enumerate(inputs):
            value = getattr(self.amqp_random_payload_fuzzer, _input.get_name())
            self.assertEqual(example_inputs[index], value)

    def test_invalid_fuzzing_turn(self):
        example_inputs = ["localhost", "peniot-queue", "peniot-exchange", "peniot-routing-key", "peniot-body", "direct",
                          1, 11]
        for index, _input in enumerate(example_inputs):
            self.amqp_random_payload_fuzzer.inputs[index].set_value(_input)

        super(AMQPRandomPayloadFuzzingAttack, self.amqp_random_payload_fuzzer).run()
        try:
            self.amqp_random_payload_fuzzer.pre_attack_init()
        except AssertionError as e:
            self.assertTrue(True)

    def test_random_payload_fuzzing_attack(self):
        def run_attack():
            example_inputs = ["localhost", "peniot-queue", "peniot-exchange", "peniot-routing-key", "peniot-body",
                              "direct", 5, 1]
            for index, _input in enumerate(example_inputs):
                self.amqp_random_payload_fuzzer.inputs[index].set_value(_input)

            try:
                self.amqp_random_payload_fuzzer.run()
            except Exception as e:
                self.assertTrue(False)

        print "* If server is not initialized this test will not execute properly."
        p = multiprocessing.Process(target=run_attack, name=self.amqp_random_payload_fuzzer.get_attack_name())
        p.start()
        time.sleep(15)
        if p.is_alive():
            p.terminate()
            p.join()


if __name__ == '__main__':
    unittest.main()
