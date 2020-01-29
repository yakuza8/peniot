#################################################################################
#                               IMPORTANT WARNING                               #
# This file is prepared to be guidance for you while implementing your protocol #
# attack or attack suite. You can extend PENIOT with your implementations by    #
# filling necessary fields properly, then you can perform what you have created.#
# To achieve this successfully, fill the following code segment carefully and   #
# keep compulsory code fields without changing their signatures so that PENIOT  #
# could extend itself with your code and work properly.                         #
#################################################################################

# Do not change any of the import statements, we will provide their contents to you
# Moreover, you do not need to export any other file than your attack
import logging

from Entity.attack import Attack


class _ATTACK_COMBINED_NAME(Attack):

    """
    Input Fields
    ** Important Note **: Each input must appear in the following lines of code for example, you can have following
    configuration in attack input list

    * For input format class, you need to fill following fields:
        1) Label of input to be displayed in GUI
        2) Name of member variable in this class, they need to match with following declarations
        3) If exist, default value. You may set it "" or None
        4) Type of input value to check/cast
    inputs = [
        InputFormat("Port Number", "port", self.port, int),
        InputFormat("Timeout", "timeout", self.timeout, float)
        ...
    ]

    * Then your attack class must have following member variables (Values are used for exemplifying)
    port = 8080
    timeout = 0.01
    ...
    """

    """
        Miscellaneous Members
        You can much more of them here to internally use
    """
    logger = None

    def __init__(self):
        inputs = [
            # You need to decide inputs to be taken from graphical user interface to conduct attack
        ]

        # Auto generated attack name, you can change attack name to be displayed in graphical user interface
        attack_name = "_ATTACK_NAME"
        # Auto generated attack description, you can change or add description for the new attack,
        # you can browse it from ? button nearby attacks in attack menu
        description = "_ATTACK_NAME Description"

        Attack.__init__(self, attack_name, inputs, description)

        # Simple logger and registration
        logging.basicConfig(level=logging.DEBUG, format="%(asctime)s:%(levelname)s:%(name)s:%(message)s")
        self.logger = logging.getLogger("_ATTACK_NAME")

    def pre_attack_init(self):
        # You can preliminary processes here such as client initialization, sniffing of packets or similar processes
        pass

    def run(self):
        # DO NOT REMOVE!
        # Necessary to initiate obtained input values
        super(_ATTACK_COMBINED_NAME, self).run()

        # Optional field if the attack needs preliminary procedure to be done
        self.pre_attack_init()

        # Implement attack here
        # The code segment below this line will be executed when you click Run Attack button
        """"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
        "                    ||| Attack Content HERE |||                   "
        "                    vvv                     vvv                   "
        """"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
        pass
