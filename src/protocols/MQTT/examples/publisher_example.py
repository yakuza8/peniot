import paho.mqtt.client as paho

import argparse
import logging
import signal
import sys
import time

DEFAULT_BROKER_HOST = "localhost"
DEFAULT_TOPIC_NAME = "peniot/test"
DEFAULT_CLIENT_NAME = "peniot-publisher"

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s:%(levelname)s:%(name)s : %(message)s")
logger = logging.getLogger("MQTT Publisher Example")

global_publisher = None

"""
    MQTT Example Publisher
"""


def signal_handler(sig, frame):
    global global_publisher
    logger.info("Connection will be closed")
    if global_publisher is not None:
        global_publisher.loop_stop()
        global_publisher.disconnect()
    sys.exit(0)


def on_message(client, userdata, message):
    logger.info("Received message = {0}".format(str(message.payload.decode("utf-8"))))


def on_connect(client, userdata, flags, rc):
    logger.info("Connection is established")


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
    publish_content = 0
    while True:
        publisher_client.publish(topic, "Peniot test message: " + str(publish_content))
        time.sleep(2)
        publish_content += 1
        logger.info("Message {0} is published".format(publish_content))


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
    publisher.on_message = on_message
    logger.info("Callbacks are assigned")

    publish_procedure(publisher, args.broker, args.topic)

