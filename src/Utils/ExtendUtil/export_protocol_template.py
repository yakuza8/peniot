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
# Moreover, you do not need to export any other file than your protocol
from Entity.protocol import Protocol

"""
Note: You need to put your attack implementations to the attack directory that you
can find in root path of created archive. Do not forget this since we are parsing
that directory to import attack dynamically.
"""

class _PROTOCOL_NAME(Protocol):

    def __init__(self):
        # Auto generated name with respect to your protocol name input
        # If you want, you can change it, it will be showed in protocol menu
        protocol_name = "_PROTOCOL_NAME"

        # You should write definition of exported protocol
        # In case of writing, you can view protocol definition
        # by clicking question-mark-icon button while selecting target protocol
        protocol_definition = "_PROTOCOL_NAME Definition"

        # You need to add your attacks to this list in order to view and instantiate them while performing your attacks
        attack_suites = [
            # Add attacks or attack suites
        ]

        # Call parent constructor with following parameters
        # 1) Attack name to be displayed in GUI
        # 2) Attacks or attack suites to perform regression and penetration
        # 3) Protocol definition to be displayed in GUI
        Protocol.__init__(self, protocol_name, attack_suites, protocol_definition)

