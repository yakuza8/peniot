from Entity.attack_suite import AttackSuite
from coap_payload_size_fuzzer import *
from coap_random_payload_fuzzing import *

import multiprocessing
import unittest


class CoAPFuzzingAttackSuite(AttackSuite):

    def __init__(self):
        attacks = [CoAPRandomPayloadFuzzingAttack(), CoAPPayloadSizeFuzzerAttack()]
        AttackSuite.__init__(self, "CoAP Fuzzing Attack Suite", attacks)


class TestCoAPFuzzingAttackSuite(unittest.TestCase):
    def setUp(self):
        self.coap_fuzzing_attack_suite = CoAPFuzzingAttackSuite()

    def tearDown(self):
        pass

    def test_name(self):
        self.assertEqual("CoAP Fuzzing Attack Suite", self.coap_fuzzing_attack_suite.get_attack_suite_name())

    def test_attack_list(self):
        attacks = self.coap_fuzzing_attack_suite.get_attacks()
        self.assertIsNotNone(attacks)
        self.assertGreater(len(attacks), 0, "Non inserted attacks")
        self.assertEquals(len(attacks), 2)

    def test_attacks(self):
        attacks = self.coap_fuzzing_attack_suite.get_attacks()
        for attack in attacks:
            p = multiprocessing.Process(target=attack.run, name=attack.get_attack_name())
            p.start()
            time.sleep(5)
            if p.is_alive():
                p.terminate()
                p.join()


if __name__ == '__main__':
    unittest.main()
