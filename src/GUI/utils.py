# This file contains methods which are used in the GUI.
import importlib
import inspect
import os
import pkgutil
from GUI.hard_coded_texts import project_title, window_size, window_background_color
from Tkinter import *
import shutil

from Utils.ExtendUtil.import_util import ImportUtil

# list of default protocols
DEFAULT_PROTOCOLS = ["MQTT", "CoAP", "AMQP", "BLE"]

"""
    Check whether the given protocol is default or not
"""


def is_default_protocol(protocol_name):
    if DEFAULT_PROTOCOLS.__contains__(protocol_name):
        return True
    return False


"""
    Deletes the given protocol
"""


def delete_protocol(protocol_name):
    path_to_protocol = os.path.dirname(os.path.abspath(__file__)) + "/../protocols/" + protocol_name
    shutil.rmtree(path_to_protocol)
    return True


"""
    Deletes the given attack
"""


def delete_attack(attack_name):
    # get the protocol name
    protocol_name = attack_name[:attack_name.index(" ")]
    # get the attack real name
    # remove protocol name
    attack_name = attack_name[attack_name.index(" ") + 1:]
    # remove 'Attack' label at the end
    attack_name = attack_name[:attack_name.index(" ")]

    # delete the attack
    path_to_attack = os.path.dirname(
        os.path.abspath(__file__)) + "/../protocols/" + protocol_name + "/attacks/" + attack_name
    shutil.rmtree(path_to_attack)
    return True


"""
    A pop up message generator.
"""


def pop_up_window(root, protocol_name, definition, justify=LEFT):
    popup = Toplevel(root)
    # prevent pop-up from resizing
    popup.resizable(False, False)
    popup.wm_title(protocol_name)
    label = Label(popup, text=definition, anchor=W, font=("Arial", 10), justify=justify, wraplength=800)
    # A pop-up with protocol name on top and definition below
    label.pack(side="top", fill="both", pady=10)
    B1 = Button(popup, text="OK", command=popup.destroy)
    B1.pack(expand=True, fill=BOTH)
    # prohibits any other window to accept events
    popup.grab_set()
    # center the window
    center_widget(popup)
    popup.mainloop()


"""
    it simply searches for the subclasses of Protocol class and returns the all protocols
"""


def get_protocols():
    # available protocols
    protocols = []
    # base package to start searching for protocols
    packages = ["src.protocols"]
    # continue to search until no package is available
    while len(packages) > 0:
        # get the package
        package = packages.pop()
        # get the package module
        package_module = importlib.import_module(package)
        prefix = package_module.__name__ + "."
        for finder, name, ispkg in pkgutil.iter_modules(package_module.__path__, prefix):
            # if it is a package, add it to the package list
            if ispkg:
                packages.append(name)
            else:
                # for some modules, we may have errors, skip those errors for now
                try:
                    mod = importlib.import_module(name)
                except ImportError:
                    continue
                for tname, klass in inspect.getmembers(mod):
                    if inspect.isclass(klass):
                        # if the class inherits from Protocol class, simply add it to the protocol list
                        if "Protocol" in [c.__name__ for c in inspect.getmro(klass)[1:]]:
                            protocols.append({"package_name": package, "protocol": klass()})
    return protocols


"""
    it simply searches for the subclasses of Attack class in the given package and returns the attacks
"""


def get_attacks(package_name):
    # available attack names
    attack_names = []
    # available attack suites
    attack_suites = []
    # available attacks
    attacks = []
    # base package to start searching for protocols
    packages = [package_name + ".attacks"]
    # continue to search until no package is available
    while len(packages) > 0:
        # get the package
        package = packages.pop()
        package_module = importlib.import_module(package)
        prefix = package_module.__name__ + "."
        for finder, name, ispkg in pkgutil.iter_modules(package_module.__path__, prefix):
            # if it is a package, add it to the package list
            if ispkg:
                packages.append(name)
            else:
                try:
                    mod = importlib.import_module(name)
                except ImportError:
                    continue
                for tname, klass in inspect.getmembers(mod):
                    if inspect.isclass(klass):
                        # if the class inherits from Attack class, simply add it to the attack list
                        if "Attack" in [c.__name__ for c in inspect.getmro(klass)[1:]]:
                            attack = klass()
                            # check whether we have this attack in the list or not
                            if not attack_names.__contains__(attack.get_attack_name()):
                                attacks.append(attack)
                                attack_names.append(attack.get_attack_name())
                        # if the class inherits from AttackSuite class, simply add it to the Attack suite list
                        if "AttackSuite" in [c.__name__ for c in inspect.getmro(klass)[1:]]:
                            attack_suite = klass()
                            attack_suites.append(attack_suite)
    # remove attack names included in the attack suites
    for attack_suite in attack_suites:
        for attack in attack_suite.get_attacks():
            if attack_names.__contains__(attack.get_attack_name()):
                attack_names.remove(attack.get_attack_name())
    # final list of available attacks
    available_attacks = []
    # retrieve attack whose name is included in the attack name list
    for attack in attacks:
        for attack_name in attack_names:
            if attack.get_attack_name() == attack_name:
                available_attacks.append(attack)
                break
    # add attack suites to the available attacks
    for attack_suite in attack_suites:
        available_attacks.append(attack_suite)
    return available_attacks


"""
    Retrieves the files containing saved captured packets
"""


def get_captured_packet_files():
    # names of the files
    file_names = []
    # search files in the src.captured_packets package
    path_to_package = os.path.dirname(os.path.abspath(__file__))[:-4] + "/captured_packets"
    for root, dirs, files in os.walk(path_to_package):
        for filename in files:
            # only get .txt files
            if filename.endswith(".pcap") or filename.endswith(".txt"):
                file_names.append(filename)
    return file_names


"""
    This function is used to change the frame.
    Firstly, we have to delete the old frame. Then, we start to use new one.
"""


def change_frame(old_frame, new_frame):
    # destroy old frame
    old_frame.grid_forget()
    old_frame.destroy()
    # new frame
    new_frame.tkraise()


"""
    It creates the root window.
"""


def create_root():
    # create the root window
    root = Tk()
    # root window related settings
    root.title(project_title)
    root.geometry(window_size)
    root.configure(background=window_background_color)
    root.resizable(False, False)
    # center the window
    center_widget(root)

    startup_calls()
    root.protocol("WM_DELETE_WINDOW", lambda: shutdown_calls(root))

    return root


"""
    Used to center the given window on the screen
"""


def center_widget(window):
    # render the window to get correct width and height
    window.update()
    # make window invisible so that we will have a smooth transition from upper left side to center
    window.withdraw()
    # get window size settings
    width_of_window = window.winfo_width()
    height_of_window = window.winfo_height()
    # get screen size settings
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    # calculate the x and y coordinates
    x_coordinate = (screen_width / 2) - (width_of_window / 2)
    y_coordinate = (screen_height / 2) - (height_of_window / 2)
    # set the geometry
    window.geometry("%dx%d+%d+%d" % (width_of_window, height_of_window, x_coordinate, y_coordinate))
    # make the window visible
    window.deiconify()


def startup_calls():
    """
    Initialize program dependent modules to make program prepared for all operations
    """
    ImportUtil.startup()


def shutdown_calls(root):
    """
    Register method callback to call necessary ending operations
    """
    ImportUtil.shutdown()
    root.destroy()
