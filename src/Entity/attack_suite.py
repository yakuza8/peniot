class AttackSuite(object):

    name = None
    attacks = []

    def __init__(self, name, attacks):
        self.name = name
        self.attacks = attacks

    def get_attack_suite_name(self):
        return self.name

    def set_attack_suite_name(self, name):
        self.name = name
        return self

    def get_attacks(self):
        return self.attacks

    def set_attacks(self, attacks):
        self.attacks = attacks
        return self

    def insert_attack(self, attack):
        if self.attacks is not None:
            self.attacks.append(attack)

    def run(self):
        for attack in self.attacks:
            attack.run()
