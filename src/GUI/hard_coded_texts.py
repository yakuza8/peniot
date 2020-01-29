"""
       This file contains some methods which return hard-coded texts and constant texts
"""


# Window title, size and background color
project_title = "Peniot"
window_size = "800x650"
window_background_color = "white"
mandatory_fields_background_color = "red"

# Button labels
start_testing_label = "Start Testing"
extend_peniot_label = "Extend Peniot"
view_captured_packets = "View Captured Packets"
help_label = "Help"
back_to_menu_label = "Back to menu"
about_us_label = "About us"
footer_label = "2018-2019 CENG Term Project"
go_to_input_page = "Go to input page"
back_to_attack_selection_page = "Back to attacks selection"
back_to_attack_suite_page = "Back to the attack suite page"
back_to_attack_details = "Back to attacks details"
perform_attack = "Perform the attack"
load_default_parameters = "Load default parameters"
stop_attack_go_back = "Stop the attack and go back"
generate_report = "Generate report"

# Settings for logger
logging_format = "%(asctime)s:%(levelname)s:%(name)s:%(message)s"
logger_name = "Attack Reporting Page"

# Color for the console
console_background_color = "black"
console_foreground_color = "white"


def get_project_name():
    return "Peniot:Penetration testing tool for Internet of Things"


def get_about_us():
    return "The developers of PENIOT project are the following : \n" \
           "    Berat Cankar\n" \
           "    Bilgehan Bingol\n" \
           "    Dogukan Cavdaroglu\n" \
           "    Ebru Celebi\n" \
           "The supervisor of the project is :\n" \
           "    Asst. Prof. Dr. Pelin Angin "


def get_help():
    return "PENIOT enables users to test their IoT devices.For now,it supports the \n" \
           "following protocols:\n" \
           "    * MQTT\n" \
           "    * CoAP\n" \
           "    * BLE\n" \
           "    * AMQP\n" \
           "For each protocol, there is at least one attack.After selecting protocol\n" \
           "and attacks, you just need to provide some information about your\n" \
           "device or network.PENIOT will handle the rest while you are resting.\n" \
           "At the end, it will provide a report which states the results of the performed attack.\n"


def get_extension_help():
    return "Extension utility which enables you to export internal structure of entities\n" \
           "(Attack, AttackSuite and Protocol) or import your implemented entities into\n" \
           "Peniot so that you can simulate/execute your own implementations."


def get_logger_name():
    """
    Returns the logger name we will use for reporting the attack results
    """
    return logger_name
