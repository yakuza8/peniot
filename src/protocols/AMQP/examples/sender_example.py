import pika

import argparse
import logging
import signal
import sys
import time

DEFAULT_BROKER_HOST = "localhost"
DEFAULT_QUEUE_NAME = "peniot-queue"
DEFAULT_EXCHANGE = "peniot-exchange"
DEFAULT_ROUTING_KEY = "peniot-routing-key"
DEFAULT_BODY = "peniot-body"
DEFAULT_EXCHANGE_TYPE = "direct"

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s:%(levelname)s:%(name)s : %(message)s")
logger = logging.getLogger("AMQP Sender Example")

global_connection = None

"""
    AMQP Example Sender
"""


def signal_handler(sig, frame):
    global global_connection
    logger.info("Connection will be closed")
    if global_connection is not None:
        global_connection.close()
    sys.exit(0)


def send_procedure(channel_to_send, exchange=DEFAULT_EXCHANGE, routing_key=DEFAULT_ROUTING_KEY, body=DEFAULT_BODY):
    """
    Sending procedure for AMQP protocol
    :param channel_to_send: Channel means which is created given host name
    :param exchange: Name of exchange
    :param routing_key: Routing key which is similar to endpoint this context
    :param body: Body of messages
    :return: None
    """
    # Signal handler to exit from function
    signal.signal(signal.SIGINT, signal_handler)

    publish_content = 0
    while True:
        channel_to_send.basic_publish(exchange=exchange, routing_key=routing_key, body=body + " " + str(publish_content))
        time.sleep(2)
        publish_content += 1
        logger.info("Message {0} is published".format(publish_content))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-b", "--broker", help="Broker host name or IP address", default=DEFAULT_BROKER_HOST)
    parser.add_argument("-q", "--queue", help="Queue name to subscribe", default=DEFAULT_QUEUE_NAME)
    parser.add_argument("-e", "--exchange", help="Name of exchange", default=DEFAULT_EXCHANGE)
    parser.add_argument("-r", "--routing_key", help="Routing key (endpoint)", default=DEFAULT_ROUTING_KEY)
    parser.add_argument("-c", "--content", help="Content of message body", default=DEFAULT_BODY)
    parser.add_argument("-x", "--exchange_type", help="Type of exchange", default=DEFAULT_EXCHANGE_TYPE)
    args = parser.parse_args()

    # Get connection and channel
    connection = pika.BlockingConnection(pika.ConnectionParameters(host=args.broker))
    global_connection = connection
    channel = connection.channel()

    # Create exchange
    channel.exchange_declare(exchange=args.exchange, exchange_type=DEFAULT_EXCHANGE_TYPE)

    # Define queue to store
    channel.queue_declare(queue=args.queue)

    # Start sending procedure
    send_procedure(channel, args.exchange, args.routing_key, args.content)
