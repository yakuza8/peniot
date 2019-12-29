from bluetooth.ble import BeaconService
import time
import argparse

# This one uses pybluez library!!!

DEFAULT_ADVERTISEMENT = "1234567890"

parser = argparse.ArgumentParser()
parser.add_argument("-a", "--advertisement", help="Advertisement input", default=DEFAULT_ADVERTISEMENT)
args = parser.parse_args()
# You can get an advertisement input from the user or have a default one

service = BeaconService()

while True:
	service.start_advertising(args.advertisement, 1, 1, 1, 200)
	time.sleep(5)
	# Service.stop_advertising()

# Here, we continiously advertise ourselves to hook a naive listener which does not have a white list.
# However, we will implement what will happen when we trick a naive scanner later
