import multiprocessing
import unittest

from Entity.attack_suite import AttackSuite
from amqp_payload_size_fuzzer import *
from amqp_random_payload_fuzzing import *


class AMQPFuzzingAttackSuite(AttackSuite):

    def __init__(self):
        attacks = [AMQPRandomPayloadFuzzingAttack(), AMQPPayloadSizeFuzzerAttack()]
        AttackSuite.__init__(self, "AMQP Fuzzing Attack Suite", attacks)


class TestAMQPFuzzingAttackSuite(unittest.TestCase):
    def setUp(self):
        self.amqp_fuzzing_attack_suite = AMQPFuzzingAttackSuite()

    def tearDown(self):
        pass

    def testName(self):
        self.assertEqual("AMQP Fuzzing Attack Suite", self.amqp_fuzzing_attack_suite.get_attack_suite_name())

    def testAttackList(self):
        attacks = self.amqp_fuzzing_attack_suite.get_attacks()
        self.assertIsNotNone(attacks)
        self.assertGreater(len(attacks), 0, "Non inserted attacks")
        self.assertEquals(len(attacks), 2)

    def testAttacks(self):
        attacks = self.amqp_fuzzing_attack_suite.get_attacks()
        for attack in attacks:
            p = multiprocessing.Process(target=attack.run, name=attack.get_attack_name())
            p.start()
            time.sleep(5)
            if p.is_alive():
                p.terminate()
                p.join()


if __name__ == '__main__':
    unittest.main()
