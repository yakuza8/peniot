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
# Moreover, you do not need to export any other file than your attack suite
from Entity.attack_suite import AttackSuite


class _ATTACK_SUITE_COMBINED_NAME(AttackSuite):

    def __init__(self):
        attacks = [
            # List the wanted attack here to package them in a single entity
        ]

        # Auto generated attack suite name, you can change attack name to be displayed in graphical user interface
        attack_suite_name = "_ATTACK_SUITE_NAME"

        AttackSuite.__init__(self, attack_suite_name, attacks)
