"""
    Common Utilities
    It contains necessary functionalities used commonly in project.
"""

import datetime


def get_current_datetime_for_filename_format():
    return datetime.datetime.now().strftime("%Y-%m-%d_%H:%M:%S")


def get_current_datetime_for_report_format():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_boolean_value(bool_str):
    bool_str = str(bool_str)
    true_list = ["1", "true", "yes", "t", "y"]
    if bool_str.lower() in true_list:
        return True
    false_list = ["0", "false", "no", "f", "n"]
    if bool_str.lower() in false_list:
        return False
    raise TypeError("Invalid input for bool type!")

