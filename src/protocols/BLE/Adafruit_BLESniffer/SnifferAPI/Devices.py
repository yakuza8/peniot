from __future__ import absolute_import
from . import Notifications
import logging


class DeviceList(Notifications.Notifier):
    def __init__(self, *args, **kwargs):
        Notifications.Notifier.__init__(self, *args, **kwargs)
        logging.info("args: " + str(args))
        logging.info("kwargs: " + str(kwargs))
        self.devices = []

    def __len__(self):
        return len(self.devices)

    def __repr__(self):
        return "Sniffer Device List: "+str(self.asList())

    def clear(self):
        self.devices = []

    def appendOrUpdate(self, newDevice):
        existingDevice = self.find(newDevice)

        # logging.info("appendOrUpdate")

        # Add device to the list of devices being displayed, but only if CRC is OK
        if existingDevice is None:
            self.append(newDevice)
        else:
            updated = False
            if (newDevice.name != "") and (existingDevice.name == ""):
                existingDevice.name = newDevice.name
                updated = True

            if (newDevice.RSSI < (newDevice.RSSI - 5)) or (existingDevice.RSSI > (newDevice.RSSI+2)):  # noqa: E501
                existingDevice.RSSI = newDevice.RSSI
                updated = True

            if updated:
                self.notify("DEVICE_UPDATED", existingDevice)
                # self.updateDeviceDisplay()

    def append(self, device):
        self.devices.append(device)
        self.notify("DEVICE_ADDED", device)

    def find(self, id):
        # logging.info("find type: %s" % str(id.__class__.__name__))
        if type(id) == list:
            for dev in self.devices:
                if dev.address == id:
                    return dev
        elif type(id) == int:
            return self.devices[id]
        elif type(id) == str:
            for dev in self.devices:
                if dev.name in [id, '"'+id+'"']:
                    return dev
        elif id.__class__.__name__ == "Device":
            # logging.info("find Device")
            return self.find(id.address)
        return None

    def remove(self, id):
        if type(id) == list:  # address
            device = self.devices.pop(self.devices.index(self.find(id)))
        elif type(id) == int:
            device = self.devices.pop(id)
        elif type(id) == Device:
            device = self.devices.pop(self.devices.index(self.find(id.address)))
        self.notify("DEVICE_REMOVED", device)
        # self.updateDeviceDisplay()

    # def getSelected(self):
        # for dev in self.devices:
        # if dev.selected:
        # return dev
        # if len(self.devices) ==  1:
        # self.devices[0].selected = True
        # else:
        # return None

    def index(self, device):
        index = 0
        for dev in self.devices:
            if dev.address == device.address:
                return index
            index += 1
        return None

    # def setSelected(self, device):
        # if device in self.devices:
        # for dev in self.devices:
        # dev.selected = False
        # device.selected = True
        # self.notify("DEVICE_SELECTED", device)

    def setFollowed(self, device):
        if device in self.devices:
            for dev in self.devices:
                dev.followed = False
            device.followed = True
        self.notify("DEVICE_FOLLOWED", device)

    # def incrementSelected(self, step = 1):
        # if len(self.devices) > 0:
        # self.setSelected(self.find((self.index(self.getSelected())+step)%len(self.devices)))

    def asList(self):
        return self.devices[:]


class Device:
    def __init__(self, address, name, RSSI, txAdd=1):
        self.address = address
        self.txAdd = txAdd
        self.name = name
        self.RSSI = RSSI
        # self.selected = selected
        self.followed = False