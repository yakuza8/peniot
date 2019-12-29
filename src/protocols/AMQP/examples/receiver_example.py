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

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s:%(levelname)s:%(name)s : %(message)s")
logger = logging.getLogger("AMQP Receiver Example")

global_connection = None

"""
    AMQP Example Receiver
"""


def signal_handler(sig, frame):
    global global_connection
    logger.info("Connection will be closed")
    if global_connection is not None:
        global_connection.close()
    sys.exit(0)


def callback(ch, method, properties, body):
    logger.info("Received %r" % body)


def receive_procedure(channel_to_receive, queue_name=DEFAULT_QUEUE_NAME):
    """
    Sending procedure for AMQP protocol
    :param channel_to_receive: Channel means which is created given host name
    :param queue_name: Queue from which consume message
    :return: None
    """
    # Signal handler to exit from function
    signal.signal(signal.SIGINT, signal_handler)

    # Start consuming
    channel_to_receive.basic_consume(callback, queue=queue_name, no_ack=True)
    channel_to_receive.start_consuming()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-b", "--broker", help="Broker host name or IP address", default=DEFAULT_BROKER_HOST)
    parser.add_argument("-q", "--queue", help="Queue name to subscribe", default=DEFAULT_QUEUE_NAME)
    parser.add_argument("-e", "--exchange", help="Name of exchange", default=DEFAULT_EXCHANGE)
    parser.add_argument("-r", "--routing_key", help="Routing key (endpoint)", default=DEFAULT_ROUTING_KEY)
    parser.add_argument("-c", "--content", help="Content of message body", default=DEFAULT_BODY)
    args = parser.parse_args()

    # Get connection and channel
    connection = pika.BlockingConnection(pika.ConnectionParameters(host=args.broker))
    global_connection = connection
    channel = connection.channel()

    channel.queue_bind(queue=args.queue, exchange=args.exchange, routing_key=args.routing_key)

    # Start sending procedure
    receive_procedure(channel, args.queue)
