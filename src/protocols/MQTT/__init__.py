"""
    This package includes the following functionalities

    1) Attacks to perform on MQTT protocol
    2) MQTT subscriber and publisher for testing Mosquitto servers
    3) ...

    Moreover, we have a class which inherits from Protocol class.
"""

import random
import string
import time

# TODO replace usages of this function with RandomUtil functions
def get_random_mqtt_client_name():
    return 'peniot-cli-' + ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(16)) + '-' + str(int(time.time()))