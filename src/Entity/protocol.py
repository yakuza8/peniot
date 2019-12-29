class Protocol(object):

    name = None
    attack_suites = []

    def __init__(self, name, attack_suites, definition):
        self.name = name
        self.attack_suites = attack_suites
        self.definition = definition

    def get_protocol_name(self):
        return self.name

    def set_protocol_name(self, name):
        self.name = name
        return self

    def get_attack_suites(self):
        return self.attack_suites

    def set_attack_suites(self, attack_suites):
        self.attack_suites = attack_suites
        return self

    def get_definition(self):
        return self.definition

    def set_definition(self, new_def):
        self.definition = new_def
        return self

    def insert_attack_suite(self, attack_suite):
        if self.attack_suites is not None:
            self.attack_suites.append(attack_suite)
