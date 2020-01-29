import logging

from GUI import hard_coded_texts as hct


class Attack(object):
    name = None
    inputs = []
    default_parameters = []

    def __init__(self, name, inputs, default_parameters, definition, logger=None):
        self.name = name
        self.inputs = inputs
        self.default_parameters = default_parameters
        self.definition = definition
        if logger is None:
            self.logger = logging.getLogger(hct.get_logger_name())
        else:
            self.logger = logging.getLogger("Default logger")

        # Load default parameters into input format values
        self.load_default_parameters()

    def get_attack_name(self):
        return self.name

    def set_attack_name(self, name):
        self.name = name
        return self

    def get_inputs(self):
        return self.inputs

    def set_inputs(self, inputs):
        self.inputs = inputs
        return self

    def insert_input(self, _input):
        if self.inputs is not None:
            self.inputs.append(_input)

    def get_default_parameters(self):
        return self.default_parameters

    def set_default_parameters(self, default_parameters):
        self.default_parameters = default_parameters
        return self

    def insert_default_parameters(self, _default_parameter):
        if self.default_parameters is not None:
            self.default_parameters.append(_default_parameter)

    def get_definition(self):
        return self.definition

    def set_definition(self, definition):
        self.definition = definition

    def set_input_value(self, input_name):
        for _input in self.inputs:
            if _input.get_name() == input_name:
                setattr(self, _input.get_name(), _input.get_value())

    def run(self):
        # Set all the input values of the class, then show begins
        for _input in self.inputs:
            setattr(self, _input.get_name(), _input.get_value())
        # Will be filled by inherited class

    def stop_attack(self):
        pass  # Will be filled by attacks

    def load_default_parameters(self):
        for _input_index, _input in enumerate(self.inputs):
            _input.set_value(self.default_parameters[_input_index])
