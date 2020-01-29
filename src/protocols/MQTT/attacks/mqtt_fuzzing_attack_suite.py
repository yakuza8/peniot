from mqtt_generation_based_fuzzing import *
from mqtt_payload_size_fuzzer import *
from mqtt_random_payload_fuzzing import *
from mqtt_topic_name_fuzzing import MQTTTopicNameFuzzingAttack
from Entity.attack_suite import AttackSuite


class MQTTFuzzingAttackSuite(AttackSuite):

    def __init__(self):
        attacks = [MQTTTopicNameFuzzingAttack(), MQTTGenerationBasedFuzzingAttack(), MQTTPayloadSizeFuzzerAttack(), MQTTRandomPayloadFuzzingAttack()]
        AttackSuite.__init__(self, "MQTT Fuzzing Attack Suite", attacks)


class TestMQTTFuzzingAttackSuite(unittest.TestCase):
    def setUp(self):
        self.mqtt_fuzzing_attack_suite = MQTTFuzzingAttackSuite()

    def tearDown(self):
        pass

    def test_name(self):
        self.assertEqual("MQTT Fuzzing Attack Suite", self.mqtt_fuzzing_attack_suite.get_attack_suite_name())

    def test_attack_list(self):
        attacks = self.mqtt_fuzzing_attack_suite.get_attacks()
        self.assertIsNotNone(attacks)
        self.assertGreater(len(attacks), 0, "Non inserted attacks")
        self.assertEquals(len(attacks), 4)

    def test_attacks(self):
        attacks = self.mqtt_fuzzing_attack_suite.get_attacks()
        for attack in attacks:
            p = multiprocessing.Process(target=attack.run, name=attack.get_attack_name())
            p.start()
            time.sleep(5)
            if p.is_alive():
                p.terminate()
                p.join()


if __name__ == '__main__':
    unittest.main()
