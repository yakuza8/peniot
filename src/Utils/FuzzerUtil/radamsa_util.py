import logging
import subprocess

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s:%(levelname)s:%(name)s:%(message)s")
logger = logging.getLogger("Util - Radamsa")

ASCII_DECODE_LIMIT = 128


def radamsa_malformed_input_generator(input_string, output_count=1):
    """
    Return test case output from given input string
    :param output_count: Number of returned output strings
    :param input_string: Any type of variable can be input
    :return: Radamsa generated output string for fuzzing
    """
    # Create subprocess for both echo and radamsa
    echo_process = subprocess.Popen(["echo", input_string], stdout=subprocess.PIPE)
    radamsa_process = subprocess.Popen(["radamsa", "-n", str(output_count)],
                                       stdin=echo_process.stdout, stdout=subprocess.PIPE)
    echo_process.stdout.close()
    # Get values
    output_string, error_message = radamsa_process.communicate()

    if error_message is None:
        if output_count > 1:
            # If it are more than one, then split it
            return output_string.split("\n")
        else:
            return output_string
    else:
        logger.debug(error_message)


def get_ascii_decodable_radamsa_malformed_input(input_string, output_count=1):
    def delete_non_ascii_characters(_string):
        return "".join([_ for _ in _string if ord(_) < ASCII_DECODE_LIMIT])

    returned_strings = radamsa_malformed_input_generator(input_string, output_count)
    _type = type(returned_strings)
    if _type == list:
        return [delete_non_ascii_characters(_returned_string) for _returned_string in returned_strings]
    elif _type == str:
        return delete_non_ascii_characters(returned_strings)
    else:
        logger.error("Non-matched type for output value")
