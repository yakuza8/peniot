import multiprocessing
import unittest

import paho.mqtt.client as paho

import logging
import random
import signal
import struct
import time

from Entity.attack import Attack
from Entity.input_format import InputFormat
from Utils.RandomUtil import random_generated_names


class MQTTGenerationBasedFuzzingAttack(Attack):
    """
    MQTT Protocol - Payload Size Fuzzer Attack module
    It is created to test any MQTT device as black box test with malformed or semi-malformed inputs
    """
    client = None

    # Input Fields
    address = None

    # Misc Members
    sent_message_count = 0  # Transmitted fuzzing packets
    logger = None
    stopped_flag = False

    subscribe = paho.SUBSCRIBE
    unsubscribe = paho.UNSUBSCRIBE

    def __init__(self):
        default_parameters = ["127.0.0.1"]
        inputs = [
            InputFormat("Broker Address", "address", "", str, mandatory=True)
        ]

        Attack.__init__(self, "MQTT Generation Based Fuzzing Attack", inputs, default_parameters,
                        "   Inject the packets which are created from the scratch\n"
                        "   and changed by come of their bits to corrupt the content")

        logging.basicConfig(level=logging.DEBUG, format="%(asctime)s:%(levelname)s:%(name)s:%(message)s")

        # Signal handler to exit from function
        signal.signal(signal.SIGINT, self.signal_handler)

    def signal_handler(self, sig, frame):
        self.stop_attack()

    def stop_attack(self):
        self.logger.info("Transmitted fuzzing packet count: {0}, exitting...".format(self.sent_message_count))
        self.stopped_flag = True
        if (self.client is not None):
            self.client.disconnect()  # Close the connection before exitting
        time.sleep(2)  # Sleep two seconds so the user can see the message
        # sys.exit(0)

    def pre_attack_init(self):
        self.client = paho.Client(random_generated_names.get_random_client_name())
        try:
            self.client.connect(self.address)
        except Exception as e:
            self.logger.error("Failed to connect to broker")

    def send_subscribe_or_unsubscribe(self, fuzz_client, message_type, topics, dup=False, optional_remaining_length=2,
                                      command_dup_shift_times=3, command_base_xor_part=0x2):
        """
        Generic subscribe and unsubscribe packet injection functionality
        :param fuzz_client: Client ot be fuzzed
        :param message_type: Currently either SUBSCRIBE or UNSUBSCRIBE
        :param topics: Topics in form [("my/topic", 0), ("another/topic", 2)] for SUBSCRIBE
                                   or ["my/topic",another/topic"] for UNSUBSCRIBE
        :param dup: Duplicate flag, I set it FALSE, but you can test with TRUE
        :param optional_remaining_length: To exploit message content, normally MQTT header length
                                          for SUBSCRIBE and UNSUBSCRIBE is 2 bytes
        :param command_dup_shift_times: Aligning command in header, change this to create malformed messages
        :param command_base_xor_part: Normally, we need to perform XOR with 0x2 to command part of MQTT Control Packet
                                      field of the header
        :type fuzz_client: mqtt.Client
        :return: Tuple of queued message and local mid
        """
        remaining_length = optional_remaining_length
        for t in topics:
            remaining_length += optional_remaining_length + len(t)

        command = message_type | (dup << command_dup_shift_times) | command_base_xor_part
        packet = bytearray()
        packet.append(command)
        fuzz_client._pack_remaining_length(packet, remaining_length)
        local_mid = fuzz_client._mid_generate()
        packet.extend(struct.pack("!H", local_mid))
        if message_type == self.subscribe:
            for t, q in topics:
                fuzz_client._pack_str16(packet, t)
                packet.append(q)
        elif message_type == self.unsubscribe:
            for t in topics:
                fuzz_client._pack_str16(packet, t)
        else:
            self.logger.info("Unknown message type in Generation Based Fuzzing")

        return (fuzz_client._packet_queue(command, packet, local_mid, 1), local_mid)

    def random_topic_generator(self, message_type, possible_characters, possible_qos_values, length=10):
        try:
            assert length > 2
            where_to_put_slash = random.randint(1, length - 1)
            topic = "{0}/{1}".format(
                "".join([random.choice(possible_characters) for _ in range(1, where_to_put_slash)]),
                "".join([random.choice(possible_characters) for _ in range(where_to_put_slash, length)]))
            if message_type == self.subscribe:
                return topic, random.choice(possible_qos_values)
            elif message_type == self.unsubscribe:
                return topic
            else:
                self.logger.info("Unknown message type in Generation Based Fuzzing")
        except AssertionError:
            self.logger.error("Length must be greater than 2")
            return "random/topic"

    def run(self):
        Attack.run(self)
        self.pre_attack_init()

        subscribe = paho.SUBSCRIBE
        unsubscribe = paho.UNSUBSCRIBE

        # Quality of service creator
        random_qosses = [0, 1, 2]

        # Currently include "A...Za...z"
        random_strings = "".join([chr(_) for _ in range(65, 91)]) + "".join([chr(_) for _ in range(97, 123)])

        '''
            (fuzz_client, message_type, topics, dup=False, optional_remaining_length=2,
            command_dup_shift_times=3, command_base_xor_part=0x2):
        '''
        test_cases = [
            dict(message_type=subscribe, topics=[self.random_topic_generator(subscribe, random_strings, random_qosses)]
                 , dup=False, optional_remaining_length=2, command_dup_shift_times=3, command_base_xor_part=0x2),
            dict(message_type=subscribe, topics=[self.random_topic_generator(subscribe, random_strings, random_qosses),
                                                 self.random_topic_generator(subscribe, random_strings, random_qosses)]
                 , dup=False, optional_remaining_length=3, command_dup_shift_times=3, command_base_xor_part=0x2),
            dict(message_type=subscribe, topics=[self.random_topic_generator(subscribe, random_strings, random_qosses)]
                 , dup=False, optional_remaining_length=2, command_dup_shift_times=5, command_base_xor_part=0x2),
            dict(message_type=subscribe, topics=[self.random_topic_generator(subscribe, random_strings, random_qosses)]
                 , dup=False, optional_remaining_length=2, command_dup_shift_times=3, command_base_xor_part=0x5),
            dict(message_type=unsubscribe,
                 topics=[self.random_topic_generator(unsubscribe, random_strings, random_qosses)]
                 , dup=False, optional_remaining_length=2, command_dup_shift_times=3, command_base_xor_part=0x2),
            dict(message_type=unsubscribe,
                 topics=[self.random_topic_generator(unsubscribe, random_strings, random_qosses),
                         self.random_topic_generator(unsubscribe, random_strings, random_qosses)]
                 , dup=False, optional_remaining_length=3, command_dup_shift_times=3, command_base_xor_part=0x2),
            dict(message_type=unsubscribe,
                 topics=[self.random_topic_generator(unsubscribe, random_strings, random_qosses)]
                 , dup=False, optional_remaining_length=2, command_dup_shift_times=5, command_base_xor_part=0x2),
            dict(message_type=unsubscribe,
                 topics=[self.random_topic_generator(unsubscribe, random_strings, random_qosses)]
                 , dup=False, optional_remaining_length=2, command_dup_shift_times=3, command_base_xor_part=0x5)
        ]

        for test_case in test_cases:

            if self.stopped_flag is True:
                break

            self.send_subscribe_or_unsubscribe(
                self.client, test_case["message_type"], test_case["topics"],
                test_case["dup"], test_case["optional_remaining_length"],
                test_case["command_dup_shift_times"], test_case["command_base_xor_part"]
            )
            # Increment sent message count
            self.sent_message_count += 1

            self.logger.info("Test case {0} has been run in generation based fuzzing".format(str(test_case)))
            time.sleep(1)


class TestMQTTGenerationBasedFuzzingAttack(unittest.TestCase):
    def setUp(self):
        self.mqtt_generation_based_fuzzer = MQTTGenerationBasedFuzzingAttack()

    def tearDown(self):
        pass

    def test_name(self):
        self.assertEqual("MQTT Generation Based Fuzzing Attack", self.mqtt_generation_based_fuzzer.get_attack_name())

    def test_inputs(self):
        inputs = self.mqtt_generation_based_fuzzer.get_inputs()
        self.assertIsNotNone(inputs)
        self.assertGreater(len(inputs), 0, "Non inserted inputs")
        self.assertEquals(len(inputs), 1)

    def test_non_initialized_inputs(self):
        inputs = self.mqtt_generation_based_fuzzer.get_inputs()
        for _input in inputs:
            value = getattr(self.mqtt_generation_based_fuzzer, _input.get_name())
            self.assertTrue(value is None or type(value) == _input.get_type())

    def test_after_getting_inputs(self):
        example_inputs = ["a.b.c.d"]
        for index, _input in enumerate(example_inputs):
            self.mqtt_generation_based_fuzzer.inputs[index].set_value(_input)

        # Previously it should not be set
        self.assertIsNone(self.mqtt_generation_based_fuzzer.client)

        super(MQTTGenerationBasedFuzzingAttack, self.mqtt_generation_based_fuzzer).run()

        inputs = self.mqtt_generation_based_fuzzer.get_inputs()
        for index, _input in enumerate(inputs):
            value = getattr(self.mqtt_generation_based_fuzzer, _input.get_name())
            self.assertEqual(example_inputs[index], value)

    def testGenerationBasedFuzzingAttack(self):
        def run_attack():
            example_inputs = ["127.0.0.1"]
            for index, _input in enumerate(example_inputs):
                self.mqtt_generation_based_fuzzer.inputs[index].set_value(_input)

            try:
                self.mqtt_generation_based_fuzzer.run()
            except Exception as e:
                self.assertTrue(False)

        print "* If server is not initialized this test will not execute properly."
        p = multiprocessing.Process(target=run_attack, name="Generation Based Fuzzing Attack")
        p.start()
        time.sleep(10)
        if p.is_alive():
            p.terminate()
            p.join()


if __name__ == '__main__':
    unittest.main()
