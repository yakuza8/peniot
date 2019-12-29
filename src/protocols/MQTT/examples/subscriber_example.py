import paho.mqtt.client as paho

import argparse
import logging
import signal
import sys
import time

DEFAULT_BROKER_HOST = "localhost"
DEFAULT_TOPIC_NAME = "peniot/test"
DEFAULT_CLIENT_NAME = "peniot-subscriber"

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s:%(levelname)s:%(name)s : %(message)s")
logger = logging.getLogger("MQTT Subscriber Example")

global_subscriber = None

"""
    MQTT Example Subscriber
"""


def signal_handler(sig, frame):
    global global_subscriber
    logger.info("Connection will be closed")
    if global_subscriber is not None:
        global_subscriber.loop_stop()
        global_subscriber.disconnect()
    sys.exit(0)


def on_message(client, userdata, message):
    logger.info("Received message = {0}".format(str(message.payload.decode("utf-8"))))


def on_connect(client, userdata, flags, rc):
    logger.info("Connection is established")


def subscribe_procedure(subscriber_client, broker_host_name=DEFAULT_BROKER_HOST, topic=DEFAULT_TOPIC_NAME):
    """
    Subscriber execution context
    :param subscriber_client: Subscriber object
    :param broker_host_name: Host name to connect
    :param topic: Topic to be subscribe
    :type subscriber_client: paho.Client
    :return: Nothing
    """
    # Signal handler to exit from function
    signal.signal(signal.SIGINT, signal_handler)

    global global_subscriber
    subscriber_client.connect(broker_host_name)
    global_subscriber = subscriber_client

    # Start loop that always checks receive and send buffer with threads and tries to catch new messages
    subscriber_client.loop_start()

    while True:
        subscriber_client.subscribe(topic)
        time.sleep(2)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-b", "--broker", help="Broker host name or IP address", default=DEFAULT_BROKER_HOST)
    parser.add_argument("-t", "--topic", help="Topic name to subscribe", default=DEFAULT_TOPIC_NAME)
    parser.add_argument("-c", "--cli", help="Client name for subscription", default=DEFAULT_CLIENT_NAME)
    args = parser.parse_args()

    # Create subscriber
    subscriber = paho.Client(args.cli)
    
    logger.info("Subscriber is created")

    # Assign necessary callbacks
    subscriber.on_message = on_message
    logger.info("Callbacks are assigned")

    subscribe_procedure(subscriber, args.broker, args.topic)

