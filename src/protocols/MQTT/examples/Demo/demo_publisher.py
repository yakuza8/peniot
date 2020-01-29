import paho.mqtt.client as paho

import argparse
import logging
import signal
import sys
import time

from Utils.RandomUtil.random_generated_names import get_random_client_name

DEFAULT_BROKER_HOST = "localhost"
DEFAULT_TOPIC_NAME = "peniot/demo"
DEFAULT_CLIENT_NAME = get_random_client_name()

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s:%(levelname)s:%(name)s : %(message)s")
logger = logging.getLogger("MQTT Demo Publisher Example")

global_publisher = None


def signal_handler(sig, frame):
    global global_publisher
    logger.info("Connection will be closed")
    if global_publisher is not None:
        global_publisher.loop_stop()
        global_publisher.disconnect()
    sys.exit(0)


def publish_procedure(publisher_client, broker_host_name=DEFAULT_BROKER_HOST, topic=DEFAULT_TOPIC_NAME):
    """
    Publisher execution context
    :param publisher_client: Publisher object
    :param broker_host_name: Host name to connect
    :param topic: Topic to be published
    :type publisher_client: paho.Client
    :return: Nothing
    """
    # Signal handler to exit from function
    signal.signal(signal.SIGINT, signal_handler)

    global global_publisher
    publisher_client.connect(broker_host_name)
    global_publisher = publisher_client

    # Start loop that always checks receive and send buffer with threads and tries to catch new messages
    publisher_client.loop_start()
    data_gen = data_generator()
    while True:
        publish_content = next(data_gen)
        publisher_client.publish(topic, publish_content)
        time.sleep(2)
        logger.info("Message {0} is published".format(publish_content))


def data_generator():
    import datetime
    import random

    today = datetime.datetime.now()
    while True:
        yield "{0},{1}".format(today.date(), round(random.uniform(-20, 40), 2))
        today = today + datetime.timedelta(days=1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-b", "--broker", help="Broker host name or IP address", default=DEFAULT_BROKER_HOST)
    parser.add_argument("-t", "--topic", help="Topic name to subscribe", default=DEFAULT_TOPIC_NAME)
    parser.add_argument("-c", "--cli", help="Client name for subscription", default=DEFAULT_CLIENT_NAME)
    args = parser.parse_args()

    # Create publisher
    publisher = paho.Client(args.cli)
    logger.info("Publisher is created")

    # Assign necessary callbacks
    logger.info("Callbacks are assigned")

    publish_procedure(publisher, args.broker, args.topic)

