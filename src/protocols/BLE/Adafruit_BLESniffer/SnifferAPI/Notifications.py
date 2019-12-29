from __future__ import absolute_import
import threading


class Notification():
    def __init__(self, key, msg=None):
        if type(key) is not str:
            raise TypeError("Invalid notification key: "+str(key))
        self.key = key
        self.msg = msg

    def __repr__(self):
        return "Notification (key: %s, msg: %s)" % (str(self.key), str(self.msg))


class Notifier():
    def __init__(self, callbacks=[]):
        self.callbacks = {}
        self.callbackLock = threading.RLock()
        # logging.info("callbacks: "+  str(callbacks))
        for callback in callbacks:
            self.subscribe(*callback)

        # logging.info(self.callbacks)

    def subscribe(self, key, callback):
        with self.callbackLock:
            if callback not in self.getCallbacks(key):
                self.getCallbacks(key).append(callback)

    def getCallbacks(self, key):
        with self.callbackLock:
            # logging.info(self.callbacks)
            if key not in self.callbacks:
                self.callbacks[key] = []
            return self.callbacks[key]

    def notify(self, key=None, msg=None, notification=None):
        # logging.info(self.callbacks)
        with self.callbackLock:
            if notification is None:
                notification = Notification(key, msg)

            for callback in self.getCallbacks(notification.key):
                callback(notification)

            for callback in self.getCallbacks("*"):
                callback(notification)

        # logging.info("sending notification: %s" % str(notification))

    def passOnNotification(self, notification):
        self.notify(notification=notification)
