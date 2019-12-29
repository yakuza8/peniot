class InputFormat(object):

    def __init__(self, label_name, name, value, _type, default_value=None, mandatory=False, secret=False,
                 from_captured_packets=False):
        self.label_name = label_name
        self.name = name
        self.value = value
        self.type = _type
        self.mandatory = mandatory
        self.default_value = default_value
        self.secret = secret
        self.from_captured_packets = from_captured_packets

    def get_label_name(self):
        return self.label_name

    def set_label_name(self, label_name):
        self.label_name = label_name
        return self

    def get_name(self):
        return self.name

    def set_name(self, name):
        self.name = name
        return self

    def get_value(self):
        return self.value

    def set_value(self, value):
        self.value = value
        return self

    def get_type(self):
        return self.type

    def set_type(self, _type):
        self.type = _type
        return self

    def set_mandatory(self, mandadory):
        self.mandatory = mandadory
        return self

    def is_mandatory(self):
        return self.mandatory

    def set_default_value(self, default_value):
        self.default_value = default_value
        return self

    def get_default_value(self):
        return self.default_value

    def is_secret(self):
        return self.secret

    def set_secret(self, secret):
        self.secret = secret
        return self

    def is_from_captured_packets(self):
        return self.from_captured_packets

    def set_from_captured_packets(self, from_captured_packets):
        self.from_captured_packets = from_captured_packets
        return self
