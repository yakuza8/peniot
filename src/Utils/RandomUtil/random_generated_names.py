import random
import string
import time


def get_random_client_name():
    return 'peniot-cli-' + ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits)
                                   for _ in range(16)) + '-' + str(int(time.time()))


def get_random_file_name():
    return 'peniot_file_' + ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits)
                                    for _ in range(16)) + '-' + str(int(time.time()))
