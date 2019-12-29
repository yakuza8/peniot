from Tkinter import *

from GUI.hard_coded_texts import get_project_name


class Header(Frame):
    def __init__(self, parent_window):
        Frame.__init__(self, parent_window)
        # configure the window
        self.configure(background="white")
        # create the header
        header = Label(self, text=get_project_name(), width=55,
                       font=("Arial", 20),
                       height=5)
        header.grid()
        header.configure(background="white")


class CustomButton(Button):
    def __init__(self, parent_window, text, _function, row, columnspan=None, sticky=None, column=None, height=2, foreground="black"):
        Button.__init__(self, parent_window, command=_function, text=text, font=("Arial", 15), borderwidth=0, height=height,
                        highlightthickness=0, background="white", foreground=foreground)
        self.grid(row=row, columnspan=columnspan, sticky=sticky, column=column)


class CustomLabel(Label):
    def __init__(self, parent_window, text, row, column, rowspan=None, columnspan=None, sticky=None):
        Label.__init__(self, parent_window, text=text, font=("Arial", 15))
        self.grid(row=row, column=column, rowspan=rowspan, columnspan=columnspan, sticky=sticky)


class CustomRadiobutton(Radiobutton):
    def __init__(self, parent_window, text, row, column, sticky, variable, value):
        Radiobutton.__init__(self, parent_window, text=text, font=("Arial", 13), variable=variable, value=value)
        self.grid(row=row, column=column, sticky=sticky)
