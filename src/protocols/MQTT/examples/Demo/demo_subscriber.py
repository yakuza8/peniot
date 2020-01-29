import paho.mqtt.client as paho

import argparse
import logging
import signal
import sys
import threading

from Utils.RandomUtil.random_generated_names import get_random_client_name

DEFAULT_BROKER_HOST = "localhost"
DEFAULT_TOPIC_NAME = "peniot/demo"
DEFAULT_CLIENT_NAME = get_random_client_name()

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s:%(levelname)s:%(name)s : %(message)s")
logger = logging.getLogger("MQTT Demo Subscriber Example")

global_subscriber = None


class DemoSubscriber(object):
    """
    Demo Subscriber that will have limited data storage and error prone code to simulate effects of attacks
    """
    def __init__(self):
        self.message_container = []
        self.start_processing_of_temperatures()

    def on_message(self, client, userdata, message):
        coming_message = str(message.payload.decode("utf-8"))
        logger.info("Received message = {0}".format(coming_message))
        if coming_message == "peniot-pay":
            return
        self.on_message_append(coming_message)

    def on_message_append(self, message):
        # Parse message
        parsed_entity = TemperatureData(message)
        if len(self.message_container) < 2**8:
            self.message_container.append(parsed_entity)
        else:
            logger.error("Message container is full!")
            # sys.exit(0)

    def start_processing_of_temperatures(self):
        if len(self.message_container) > 0:
            logger.info("Popped message = {0}".format(self.message_container.pop(0)))

        threading.Timer(2.0, self.start_processing_of_temperatures).start()


class TemperatureData(object):
    """
    Container class for temperature data that comes from publisher
    """
    def __init__(self, temperature_string):
        try:
            parsed = temperature_string.split(",")
            self.date, self.temperature = tuple(parsed)
        except Exception as e:
            logger.error("Impossible data to parse... I gave up, I need rest to recover...")
            # sys.exit(0)

    def get_date(self):
        return self.date

    def set_date(self, date):
        self.date = date

    def get_temperature(self):
        return self.temperature

    def set_temperature(self, temperature):
        self.temperature = temperature

    def __repr__(self):
        return "{0},{1}".format(self.date, self.temperature)


def signal_handler(sig, frame):
    global global_subscriber
    logger.info("Connection will be closed")
    if global_subscriber is not None:
        global_subscriber.loop_stop()
        global_subscriber.disconnect()
    sys.exit(0)


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
    subscriber_client.subscribe(topic)
    subscriber_client.loop_forever()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-b", "--broker", help="Broker host name or IP address", default=DEFAULT_BROKER_HOST)
    parser.add_argument("-t", "--topic", help="Topic name to subscribe", default=DEFAULT_TOPIC_NAME)
    parser.add_argument("-c", "--cli", help="Client name for subscription", default=DEFAULT_CLIENT_NAME)
    args = parser.parse_args()

    # Create subscriber
    subscriber = paho.Client(args.cli)
    logger.info("Subscriber is created")
    demo_subscriber = DemoSubscriber()

    # Assign necessary callbacks
    subscriber.on_message = demo_subscriber.on_message
    logger.info("Callbacks are assigned")

    subscribe_procedure(subscriber, args.broker, args.topic)

