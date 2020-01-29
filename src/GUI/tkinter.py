import logging
import tkFileDialog
import ttk
from threading import Timer

from custom_widgets import *
from hard_coded_texts import *
from utils import *
from Entity.attack import Attack
from Entity.attack_suite import AttackSuite
from Utils import CommonUtil
from Utils.ExtendUtil.export_util import ExportUtil, ExportOptions
from Utils.ExtendUtil.import_util import ImportUtil, ImportOptions
from Utils.ReportUtil.report_generator import GenerateReport

root = None


class HomePage(Frame):
    """
    This is the first page which users see when they start the application.
    It simply contains a menu with the following options:
        - Start Testing
        - Help
        - About us
    """

    def __init__(self, parent_window):
        Frame.__init__(self, parent_window)
        # Configure the window
        self.configure(background=window_background_color)
        # Create the header
        Header(self).grid(row=0)
        # Start testing button
        CustomButton(self, start_testing_label, lambda: change_frame(self, ProtocolsPage(root)), 1)
        # Extension button
        CustomButton(self, extend_peniot_label, lambda: change_frame(self, ExtensionPage(root)), 2)
        # View captured packets button
        CustomButton(self, view_captured_packets, lambda: change_frame(self, ViewCapturedPackets(root)), 3)
        # Help button
        CustomButton(self, help_label, lambda: change_frame(self, Help(root)), 4)
        # About us button
        CustomButton(self, about_us_label, lambda: change_frame(self, AboutUs(root)), 5)
        # Footer
        footer = Label(self, text=footer_label, width=55, font=("Arial", 20), height=5)
        footer.grid(row=6)
        footer.configure(background=window_background_color)
        # Make it visible
        self.grid()


class AboutUs(Frame):
    """
    This page displays information about the developers of the project.
    """

    def __init__(self, parent_window):
        Frame.__init__(self, parent_window)
        # Configure the window
        self.configure(background=window_background_color)
        # Create the header
        Header(self).grid(row=0)
        # Information about us
        info_about_us = Label(self, text=get_about_us(), width=55, anchor=W, justify=LEFT, font=("Arial", 15),
                              height=10)
        info_about_us.grid(row=1)
        info_about_us.configure(background=window_background_color)
        # Back to menu button
        CustomButton(self, back_to_menu_label, lambda: change_frame(self, HomePage(root)), 2)
        # Make it visible
        self.grid()


class Help(Frame):
    """
    This page displays information about the tool.
    """

    def __init__(self, parent_window):
        Frame.__init__(self, parent_window)
        # Configure the window
        self.configure(background=window_background_color)
        # Create the header
        Header(self).grid(row=0)
        # Information about us
        info_about_us = Label(self, text=get_help(), width=70, anchor=W, justify=LEFT, font=("Arial", 15), height=10)
        info_about_us.grid(row=1)
        info_about_us.configure(background=window_background_color)
        # Back to menu button
        CustomButton(self, back_to_menu_label, lambda: change_frame(self, HomePage(root)), 2)
        # Make it visible
        self.grid()


class ViewCapturedPackets(Frame):
    """
    This page enables users to download captured packets.
    """
    CAPTURED_PACKET_PATH = os.path.dirname(os.path.abspath(__file__))[:-4] + "/captured_packets/"

    def __init__(self, parent_window):
        Frame.__init__(self, parent_window)
        # Generate content
        self.generate_content()
        # Make it visible
        self.grid()

    def generate_content(self):
        """
        This method is used to generate rows representing the files
        """
        # Destroy the existing widgets
        for widget in self.winfo_children():
            widget.destroy()
        # Configure the window
        self.configure(background=window_background_color)
        # Create the header
        Header(self).grid(row=0, columnspan=4)
        # Row index
        row_index = 1
        # Get the file names
        file_names = get_captured_packet_files()
        for file_name in file_names:
            # Remove .txt part
            file_name_without_extension = file_name[:-4]
            info = file_name_without_extension.split("_")
            # Protocol name
            protocol_name = Label(self, text=info[0])
            protocol_name.grid(row=row_index, column=0)
            protocol_name.configure(background=window_background_color)
            # Date
            date = Label(self, text=info[1] + " " + info[2])
            date.grid(row=row_index, column=1)
            date.configure(background=window_background_color)
            # Download button
            CustomButton(self, "Download", lambda file_name=file_name: self.download_file(file_name), row_index, None,
                         None, 2)
            # Delete button
            print file_name
            CustomButton(self, "Delete", lambda file_name=file_name: self.delete_captured_packets_file(file_name),
                         row_index, None,
                         None, 3)
            # Increment row index
            row_index = row_index + 1
        # Back to menu button
        CustomButton(self, back_to_menu_label, lambda: change_frame(self, HomePage(root)), row_index, 3)
        self.grid()

    def delete_captured_packets_file(self, file_name):
        """ 
        This method is used to delete a captured packets file
        """
        os.remove(self.CAPTURED_PACKET_PATH + file_name)
        # Generate content
        self.generate_content()

    def download_file(self, file_name):
        """
        This methods is used to export the selected packets file.
        """
        # Get the directory
        directory_name = tkFileDialog.askdirectory(initialdir=os.getcwd(), title="Select directory to download packets")

        try:
            # Read the file
            packets_file = os.open(os.path.dirname(os.path.abspath(__file__))[:-4] + "/captured_packets/" + file_name,
                                   os.O_RDONLY)
            # Open a file
            new_file = os.open(directory_name + "/" + file_name, os.O_RDWR | os.O_CREAT)
            # Copy the file content
            while True:
                data = os.read(packets_file, 2048)
                if not data:
                    break
                os.write(new_file, data)
            # Close the files
            os.close(packets_file)
            os.close(new_file)
            # Create pop-up
            pop_up_window(root, None, "Downloaded successfully")
        except Exception as e:
            if len(directory_name) == 0:
                return
            else:
                pop_up_window(root, None, "Download operation is failed because of\n{0}".format(e), justify=CENTER)


class ProtocolsPage(Frame):
    """
    This page displays the possible options for protocols.
    """

    def __init__(self, parent_window):
        Frame.__init__(self, parent_window)
        # Configure the window
        self.configure(background=window_background_color)
        # Create the header
        Header(self).grid(row=0, columnspan=2)
        # Get protocols
        protocols = get_protocols()
        # Current row index
        row_index = 1
        # Create a button for each protocols
        for protocol in protocols:
            # Create the button for the protocol
            CustomButton(self, protocol["protocol"].get_protocol_name(),
                         lambda selected_protocol=protocol: change_frame(self, AttacksPage(root,
                                                                                           selected_protocol)),
                         row_index, None, E, 0)

            CustomButton(self, "?",
                         lambda selected_protocol=protocol: pop_up_window(root,
                                                                          selected_protocol[
                                                                              "protocol"].get_protocol_name(),
                                                                          selected_protocol[
                                                                              "protocol"].get_definition()),
                         row_index, None, W, 1)
            # Increment the row index
            row_index = row_index + 1
        # Back to menu button
        CustomButton(self, back_to_menu_label, lambda: change_frame(self, HomePage(root)), row_index, 2)
        # Make it visible
        self.grid()


class ExtensionPage(Frame):
    """
    This page displays the extension options and help button that explains how to extend for PENIOT.
    """

    def __init__(self, parent_window):
        Frame.__init__(self, parent_window)
        # Configure the window
        self.configure(background=window_background_color)
        # Create the header
        Header(self).grid(row=0, columnspan=2)
        # Current row index
        row_index = 1

        # Export button
        CustomButton(self, "Export", lambda: change_frame(self, ExportPage(root)), row_index, None, E, 0)
        row_index = row_index + 1

        # Import button
        CustomButton(self, "Import", lambda: change_frame(self, ImportPage(root)), row_index, None, E, 0)
        row_index = row_index + 1

        # Help button
        CustomButton(self, help_label, lambda: change_frame(self, ExtensionHelp(root)), row_index, 2)
        row_index = row_index + 1

        # Back to menu button
        CustomButton(self, back_to_menu_label, lambda: change_frame(self, HomePage(root)), row_index, 2)

        # Make it visible
        self.grid()


class ImportPage(Frame):
    """
    These pages make the user select import or export options
    """

    def __init__(self, parent_window):
        Frame.__init__(self, parent_window)
        self.file_path = ""
        self.option = ImportOptions.ATTACK_OR_ATTACK_SUITE
        # Configure the window
        self.configure(background=window_background_color)
        # Create the header
        Header(self).grid(row=0, columnspan=4)

        row_index = 1

        CustomLabel(self, text="Option:", row=row_index, column=0, sticky=E)
        option_combo_box = ttk.Combobox(self, values=["Protocol", "Attack or Attack Suite"], font=("Arial", 15))
        option_combo_box.grid(row=row_index, column=1, sticky=W + E, columnspan=2)
        option_combo_box.bind("<<ComboboxSelected>>",
                              lambda x: combobox_element_changed(option_combo_box, protocol_name_label,
                                                                 self.protocol_name_combo_box))
        option_combo_box.current(1)
        row_index = row_index + 1

        protocol_name_label = CustomLabel(self, text="Protocol Name:", row=row_index, column=0, sticky=E)
        self.protocol_name_combo_box = ttk.Combobox(self, font=("Arial", 15))
        self.protocol_name_combo_box.grid(row=row_index, column=1, sticky=W + E, columnspan=2)
        self.protocol_name_combo_box.bind("<<ComboboxSelected>>",
                                          lambda x: combobox_protocol_name_changed(self.protocol_name_combo_box))
        row_index = row_index + 1

        # Names of available protocols
        self.protocol_names = []
        # Get protocol names
        self.get_protocol_names()

        self.selected_protocol = self.protocol_names[0]

        CustomLabel(self, text="File Path:", row=row_index, column=0, sticky=E)
        file_path_entry = Entry(self, font=("Arial", 15))
        file_path_entry.grid(row=row_index, column=1, sticky=W + E, columnspan=2)

        CustomButton(self, "Select File", lambda: get_file_path(file_path_entry), row_index, None, W, 3, height=1)
        row_index = row_index + 1

        CustomButton(self, "Import",
                     lambda: self.import_button_click(file_path_entry.get(), self.option, self.selected_protocol),
                     row_index, None, W, 3)

        CustomButton(self, back_to_menu_label, lambda: change_frame(self, ExtensionPage(root)), row_index, None, E, 0)

        for col in range(5):
            self.columnconfigure(col, weight=1)
        for row in range(8):
            self.rowconfigure(row, weight=1)

        self.grid()

        def get_file_path(entry):
            self.file_path = tkFileDialog.askopenfilename()
            entry.delete(0, END)
            entry.insert(0, self.file_path)

        def combobox_element_changed(combo, label, combobox):
            if combo.get() == "Protocol":
                label.grid_forget()
                combobox.grid_forget()
                self.option = ImportOptions.PROTOCOL
            else:
                label.grid(row=2, column=0, sticky=E)
                combobox.grid(row=2, column=1, sticky=W + E, columnspan=2)
                self.option = ImportOptions.ATTACK_OR_ATTACK_SUITE

        def combobox_protocol_name_changed(combo):
            self.selected_protocol = combo.get()

    def import_button_click(self, file_path, option, selected_protocol):
        try:
            if not os.path.isfile(file_path):
                pop_up_window(root, None, "Please select a valid file.")
                return
            ImportUtil.import_action(file_path, option, selected_protocol)
            # Update the protocol list since the user may import a new protocol
            self.get_protocol_names()
            pop_up_window(root, None, "Files are imported successfully")

        except Exception as e:
            pop_up_window(root, None, "Import operation is failed because of\n{0}".format(e), justify=CENTER)

    def get_protocol_names(self):
        protocols = get_protocols()
        self.protocol_names = []
        for protocol in protocols:
            self.protocol_names.append(protocol["protocol"].get_protocol_name())
        self.protocol_name_combo_box['values'] = self.protocol_names


class ExportPage(Frame):
    def __init__(self, parent_window):
        Frame.__init__(self, parent_window)
        # Configure the window
        self.configure(background=window_background_color)
        # Create the header
        Header(self).grid(row=0, columnspan=4)

        s = ttk.Style()
        s.configure(".", font=("Arial", 15))

        tab_control = ttk.Notebook(self)
        attack_tab = TabFrame(tab_control, ExportOptions.ATTACK)
        tab_control.add(attack_tab, text="Attack")

        attacksuite_tab = TabFrame(tab_control, ExportOptions.ATTACK_SUITE)
        tab_control.add(attacksuite_tab, text="Attack Suite")

        protocol_tab = TabFrame(tab_control, ExportOptions.PROTOCOL)
        tab_control.add(protocol_tab, text="Protocol")

        tab_control.grid(row=1, column=0, columnspan=4, rowspan=3, sticky=W + E + S + N)
        CustomButton(self, back_to_menu_label, lambda: change_frame(self, ExtensionPage(root)), 7, None, E, 1)
        self.grid()


class TabFrame(Frame):
    def __init__(self, parent_window, option):
        Frame.__init__(self, parent_window)
        # Configure the window
        self.configure(background=window_background_color)
        self.file_path = None
        row = 0
        CustomLabel(self, text="Protocol Name:", row=row, column=1, sticky=E)
        protocol_name_entry = Entry(self, font=("Arial", 15))
        protocol_name_entry.grid(row=row, column=2, sticky=W + E, columnspan=2)
        row = row + 1

        attack_name_entry = Entry(self, font=("Arial", 15))
        if option == ExportOptions.ATTACK:
            CustomLabel(self, text="Attack Name:", row=row, column=1, sticky=E)
            attack_name_entry.grid(row=row, column=2, sticky=W + E, columnspan=2)
            row = row + 1

        attack_suite_name_entry = Entry(self, font=("Arial", 15))
        if option == ExportOptions.ATTACK_SUITE:
            CustomLabel(self, text="Attack Suite Name:", row=row, column=1, sticky=E)
            attack_suite_name_entry.grid(row=row, column=2, sticky=W + E, columnspan=2)
            row = row + 1

        CustomLabel(self, text="File Path:", row=row, column=1, sticky=E)
        file_path_entry = Entry(self, font=("Arial", 15))
        file_path_entry.grid(row=row, column=2, sticky=W + E, columnspan=2)

        CustomButton(self, "Select File Path", lambda: get_file_path(file_path_entry), row, None, W, 4, height=1)
        row = row + 1

        CustomLabel(self, text="File Name:", row=row, column=1, sticky=E)
        file_name_entry = Entry(self, font=("Arial", 15))
        file_name_entry.grid(row=row, column=2, sticky=W + E, columnspan=2)
        row = row + 1

        rad_var = IntVar()
        for export_index, export_option in enumerate(ExportUtil.get_export_texts_and_values()):
            export_value = export_option.get("value")
            if export_index == 0:
                rad_var.set(export_value)
            CustomRadiobutton(self, text=export_option.get("text"), row=row, column=2, sticky=W + S, variable=rad_var,
                              value=export_value)
            row = row + 1

        CustomButton(self, "Export",
                     lambda: export_button_click(protocol_name=protocol_name_entry.get(),
                                                 attack_name=attack_name_entry.get(),
                                                 attack_suite_name=attack_suite_name_entry.get(),
                                                 file_path=file_path_entry.get(),
                                                 file_name=file_name_entry.get(), extension=rad_var.get(),
                                                 option=option),
                     row, None, W, 4)

        for col in range(5):
            self.columnconfigure(col, weight=1)
        for row in range(8):
            self.rowconfigure(row, weight=1)

        self.grid()

        def get_file_path(entry):
            self.file_path = tkFileDialog.askdirectory()
            entry.delete(0, END)
            entry.insert(0, self.file_path)

        def export_button_click(protocol_name, attack_name, attack_suite_name, file_path, file_name, extension, option):
            try:
                if not os.path.exists(file_path):
                    pop_up_window(root, None, "Please enter a valid file path.")
                    return
                ExportUtil.export_action(protocol_name=protocol_name,
                                         attack_name=attack_name,
                                         attack_suite_name=attack_suite_name,
                                         file_path=file_path,
                                         file_name=file_name, extension=extension,
                                         option=option)
                pop_up_window(root, None, "Files are exported successfully.")
            except Exception as e:
                pop_up_window(root, None, "Export operation is failed because of\n{0}".format(e), justify=CENTER)


class ExtensionHelp(Frame):
    """
    This page gives detailed information on how to extend PENIOT.
    """

    def __init__(self, parent_window):
        Frame.__init__(self, parent_window)
        # Configure the window
        self.configure(background=window_background_color)
        # Create the header
        Header(self).grid(row=0)
        # information about us
        extension_info = Label(self, text=get_extension_help(), width=70, justify=CENTER, font=("Arial", 15), height=10)
        extension_info.grid(row=1)
        extension_info.configure(background=window_background_color)
        # Back to menu button
        CustomButton(self, back_to_menu_label, lambda: change_frame(self, ExtensionPage(root)), 2)
        # Make it visible
        self.grid()


class AttacksPage(Frame):
    """
    This page displays the possible attacks for the selected protocol.
    """

    def __init__(self, parent_window, protocol):
        Frame.__init__(self, parent_window)
        # Configure the window
        self.configure(background=window_background_color)
        # Set the selected protocol
        self.protocol = protocol
        # Create the header
        Header(self).grid(row=0)
        # Get protocol's attack suites
        attacks_suites = get_attacks(protocol["package_name"])
        # current row index
        row_index = 1
        # Create a button for each attack
        for attack_suite in attacks_suites:
            if isinstance(attack_suite, Attack):
                # Create the button for the attack
                CustomButton(self, attack_suite.get_attack_name(),
                             lambda selected_attack=attack_suite: change_frame(self,
                                                                               AttackDetailsPage(root,
                                                                                                 self.protocol,
                                                                                                 selected_attack,
                                                                                                 None)),
                             row_index)
                # Increment the row index
                row_index = row_index + 1
            elif isinstance(attack_suite, AttackSuite):
                # Create the button for the attack suite
                CustomButton(self, attack_suite.get_attack_suite_name(),
                             lambda selected_attack_suite=attack_suite: change_frame(self,
                                                                                     AttackSuiteDetailsPage(root,
                                                                                                            self.protocol,
                                                                                                            selected_attack_suite)),
                             row_index)
                # Increment the row index
                row_index = row_index + 1
        if not is_default_protocol(self.protocol["protocol"].get_protocol_name()):
            # Back to attack selection page button
            CustomButton(self, "Delete Protocol", lambda: self.delete_protocol(), row_index, foreground="red")
        row_index = row_index + 1
        # Back to menu button
        CustomButton(self, back_to_menu_label, lambda: change_frame(self, ProtocolsPage(root)), row_index)
        # Make it visible
        self.grid()

    def delete_protocol(self):
        is_successful = delete_protocol(self.protocol["protocol"].get_protocol_name())
        if is_successful:
            change_frame(self, ProtocolsPage(root))


class AttackSuiteDetailsPage(Frame):
    """
        This page displays the details of the selected attack suite.
    """

    def __init__(self, parent_window, protocol, attack_suite):
        Frame.__init__(self, parent_window)
        # Configure the window
        self.configure(background=window_background_color)
        # Set the selected protocol
        self.protocol = protocol
        # Set the selected attack suite
        self.attack_suite = attack_suite
        # Create the header
        Header(self).grid(row=0, columnspan=2)
        # row index
        row_index = 1
        # Create buttons for attacks
        for attack_in_suite in attack_suite.get_attacks():
            # Create the button for the attack
            CustomButton(self, attack_in_suite.get_attack_name(),
                         lambda selected_attack=attack_in_suite: change_frame(self,
                                                                              AttackDetailsPage(root, self.protocol,
                                                                                                selected_attack,
                                                                                                attack_suite)),
                         row_index, 2)
            # Increment row index
            row_index = row_index + 1
        # Back to attack selection page button
        CustomButton(self, back_to_attack_selection_page, lambda: change_frame(self, AttacksPage(root, self.protocol)),
                     row_index, 2)
        # Make it visible
        self.grid()


class AttackDetailsPage(Frame):
    """
        This page displays the details of the selected attack.
    """

    def __init__(self, parent_window, protocol, attack, attack_suite):
        Frame.__init__(self, parent_window)
        # Configure the window
        self.configure(background=window_background_color)
        # Set the selected protocol
        self.protocol = protocol
        # Set the attack suite
        self.attack_suite = attack_suite
        # Set the selected attack
        self.attack = attack
        # Create the header
        Header(self).grid(row=0, columnspan=2)
        # Definition of the attack
        attack_definition = Label(self, text=self.attack.get_definition(), width=70, justify=CENTER,
                                  font=("Arial", 15),
                                  height=10)
        attack_definition.grid(row=1)
        attack_definition.configure(background=window_background_color)
        # Back to the previous page
        if self.attack_suite is None:
            # Back to attack selection page button
            CustomButton(self, back_to_attack_selection_page,
                         lambda: change_frame(self, AttacksPage(root, self.protocol)),
                         2, None, W)
        else:
            # Back to attack suite details page button
            CustomButton(self, back_to_attack_suite_page,
                         lambda: change_frame(self, AttackSuiteDetailsPage(root, self.protocol, attack_suite)),
                         2, None, W)
        if not is_default_protocol(self.protocol["protocol"].get_protocol_name()):
            # Delete attack button
            CustomButton(self, "Delete Attack", lambda: self.delete_attack(), 2, foreground="red")
        # Go to input page button
        CustomButton(self, go_to_input_page,
                     lambda: change_frame(self, InputsPage(root, self.protocol, self.attack, self.attack_suite)),
                     2, None, E)
        # Make it visible
        self.grid()

    def delete_attack(self):
        is_successful = delete_attack(self.attack.get_attack_name())
        if is_successful:
            # Back to the previous page
            if self.attack_suite is None:
                # Back to attack selection page button
                change_frame(self, AttacksPage(root, self.protocol))
            else:
                # Back to attack suite details page button
                change_frame(self, AttackSuiteDetailsPage(root, self.protocol, self.attack_suite))


class InputsPage(Frame):
    """
        This page is used to get inputs from the user.
    """

    def __init__(self, parent_window, protocol, attack, attack_suite):
        Frame.__init__(self, parent_window)
        # Configure the window
        self.configure(background=window_background_color)
        # Set the selected protocol
        self.protocol = protocol
        # Set the attack suite
        self.attack_suite = attack_suite
        # Set the selected attack
        self.attack = attack
        # file path if necessary
        self.file_path = ""
        # Create the header
        Header(self).grid(row=0, columnspan=3)
        # Inputs of the attack
        row_index = 1
        # Get inputs
        self.inputs = self.attack.get_inputs()
        # Create an empty list for input values
        self.input_values = []
        # For each input, create a Label-Entity pair
        for _input in self.inputs:
            label = Label(self, text=_input.get_label_name())
            label.grid(row=row_index)
            label.configure(background=window_background_color)

            # Create a StringVar for the input
            string_var = StringVar(value=str(_input.get_value()))
            # Add it to the list
            self.input_values.append(string_var)
            # Create an entry for the input
            if _input.is_secret():
                # Bind it to the string var
                entry = Entry(self, show="*", textvariable=string_var)
            else:
                # Bind it to the string var
                entry = Entry(self, textvariable=string_var)
            entry.grid(row=row_index, column=1)
            if _input.is_mandatory():
                entry.configure(background=mandatory_fields_background_color)
            else:
                entry.configure(background=window_background_color)
            if _input.is_from_captured_packets():
                CustomButton(self, "Select File", lambda: self.get_file_path(entry), row_index, None, W, 2,
                             height=1)
            # Increment the row index
            row_index = row_index + 1

        # Back to attack details page button
        CustomButton(self, back_to_attack_details,
                     lambda: change_frame(self,
                                          AttackDetailsPage(root, self.protocol, self.attack, self.attack_suite)),
                     row_index, None,
                     None, 0)
        # Perform the attack page button
        CustomButton(self, perform_attack, lambda: self.navigate_to_attack_reporting_page(), row_index, None,
                     None, 1)

        # Set default parameters of the current protocol
        row_index += 1
        CustomButton(self, load_default_parameters, lambda: (
            self.attack.load_default_parameters(),
            self.load_default_parameters_to_variables()
        ), row_index, 2, None, None)
        # Make it visible
        self.grid()

    def get_file_path(self, entry):
        path_to_captured_packets = os.path.dirname(os.path.abspath(__file__)) + "/../captured_packets"
        self.file_path = tkFileDialog.askopenfilename(initialdir=path_to_captured_packets,
                                                      filetypes=[("pcap-files", "BLE*.pcap")])
        entry.delete(0, END)
        entry.insert(0, self.file_path)

    def set_input_values(self):
        """
        This function sets the values of the inputs using the self.input_values field.
        """
        for i in range(0, len(self.inputs)):
            # Get the input from the user
            value = self.input_values[i].get()
            # If this is a mandatory field, but user did not provide any value for it,
            # Then simply create a pop-up explaining the situation
            if self.inputs[i].is_mandatory() and value.strip() is "":
                pop_up_window(root, "Input Validation",
                              "Please, be sure that you provide valid values for the mandatory fields.")
                # input validation failed
                return False
            # If the user provide a value for the input, use it
            # Otherwise, use the default one
            if value is not "":
                # convert string to the expected type
                try:
                    value = InputsPage._check_value_type(self.inputs[i], value)
                except Exception:
                    return False
            else:
                value = self.inputs[i].get_default_value()
            # Set the value
            self.inputs[i].set_value(value)
        return True

    def navigate_to_attack_reporting_page(self):
        """
        This function is called when we want to start testing
        """
        # Set the input values
        is_valid = self.set_input_values()
        # If we have valid inputs, then continue with the attack
        if is_valid:
            # Change page to the attack reporting page
            change_frame(self, AttackReportingPage(root, self.protocol, self.attack, self.attack_suite))
        else:
            pop_up_window(root, "Input Validation",
                          "Please, be sure that you provide valid values for input fields.")

    def load_default_parameters_to_variables(self):
        for _input_index, _input in enumerate(self.inputs):
            self.input_values[_input_index].set(str(_input.get_value()))

    @staticmethod
    def _check_value_type(_input, _value):
        try:
            if _input.type == bool:
                return CommonUtil.get_boolean_value(_value)
            else:
                return _input.type(_value)
        except TypeError as _:
            raise _


class AttackReportingPage(Frame):
    """
    This page is used to show the results of the attack.
    """

    def __init__(self, parent_window, protocol, attack, attack_suite):
        Frame.__init__(self, parent_window)
        # Configure the window
        self.configure(background=window_background_color)
        # Set the selected protocol
        self.protocol = protocol
        # Set the attack suite
        self.attack_suite = attack_suite
        # Set the selected attack
        self.attack = attack
        # Create the header
        Header(self).grid(row=0, columnspan=2)
        # Create the console
        self.console = Text(self)
        self.console.grid(row=1, columnspan=2, sticky="nsew")
        self.console.configure(background=console_background_color, foreground=console_foreground_color, wrap='word')
        # Change the default output stream
        sys.stdout = self
        # Change the default input stream
        sys.stdin = self

        # Create a stream handler
        stream_handler = logging.StreamHandler(self)
        stream_handler.setLevel(logging.INFO)
        # Create a formatter
        formatter = logging.Formatter(logging_format)
        stream_handler.setFormatter(formatter)
        # Create a logger
        self.logger = logging.getLogger(logger_name)
        self.logger.addHandler(stream_handler)
        # Start the testing after 1 seconds. Create a Timer object so we can stop execution later
        self.timer = Timer(1.0, self.perform_attack)
        self.timer.start()

        # Stop the attack and back to menu button
        CustomButton(self, stop_attack_go_back, lambda: self.attack_stopper(), 2, 1, None, 0)
        CustomButton(self, generate_report, lambda: self.report_generator(), 2, 1, None, 1)
        # Make it visible
        self.grid()

    # Override write function
    def write(self, text):
        self.console.insert(END, str(text))
        # Change the state of the console to Disabled so that nobody can write
        # Update the tasks so that the user can see the logs
        self.update_idletasks()

    # Override readline function
    def readline(self):
        return_value = None
        while return_value is None:
            # Get the return value
            return_value = self.get_number()
            # continue until we have a valid return value
            if return_value is None:
                continue
            return return_value

    # Used to get user selection for BLE sniffing attack
    def get_number(self):
        return_value = None
        text = self.console.get(1.0, END)[::-1].encode("ascii")

        if text[0] == '\n' and text[1] == '\n':
            for i in text:
                if i == ">":
                    break
                elif str.isdigit(i):
                    if return_value is None:
                        return_value = ""
                    return_value = i + return_value
        return return_value

    def perform_attack(self):
        # Start message
        self.logger.info("Performing the attack")
        # Run the attack
        self.attack.run()
        # Exit message
        self.logger.info("Attack is performed successfully")

    # Define the attack stopper function to end attacks
    def attack_stopper(self):
        # Remove handlers
        self.attack.stop_attack()  # Call the underlying attack's own stopper
        for handler in self.logger.handlers:
            handler.close()
            self.logger.removeHandler(handler)
        # There will be some more changes here to close open pipes and so on.
        # Then, change the frame and go back
        change_frame(self, InputsPage(root, self.protocol, self.attack, self.attack_suite))

    def report_generator(self):
        directory = tkFileDialog.askdirectory()
        try:
            if type(directory) == str and len(directory) > 0:
                directory = directory if directory.endswith('/') else directory + '/'
                GenerateReport.generate_pdf_from_text(
                    self.protocol['protocol'].get_protocol_name(),
                    self.attack.get_attack_name(),
                    self.console.get("1.0", END),
                    directory
                )
                pop_up_window(root, None, 'Report is successfully generated.', justify=CENTER)
        except Exception as e:
            pop_up_window(root, None, 'Report cannot be generated properly.\nPlease check given directory path.',
                          justify=CENTER)


def run():
    # Create the root window
    root = create_root()
    # Create HomePage and make it the current window
    HomePage(root).tkraise()
    root.mainloop()
