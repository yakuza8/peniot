from enum import Enum
from Utils.RandomUtil import random_generated_names as random_util

import logging
import os
import re
import tarfile
import zipfile


logging.basicConfig(level=logging.DEBUG, format="%(asctime)s:%(levelname)s:%(name)s : %(message)s")
logger = logging.getLogger("Util - Export")


class ExportTypes(Enum):
    """
    Enumeration types for export modes
    """
    ZIP = 0
    TAR_GZ = 1


class ExportOptions(Enum):
    """
    Enumeration types for export options such as Protocol, Attack or Attack Suite
    """
    PROTOCOL = 0
    ATTACK = 1
    ATTACK_SUITE = 2


# noinspection PyBroadException
class ExportUtil(object):
    # Base path
    BASE_PATH = os.path.dirname(os.path.abspath(__file__))

    # Export Protocol Constants
    EXPORT_PROTOCOL_TEMPLATE_NAME = BASE_PATH + "/export_protocol_template.py"
    EXPORT_PROTOCOL_NAME_REGEX = "_PROTOCOL_NAME"

    # Export Attack Constants
    EXPORT_ATTACK_TEMPLATE_NAME = BASE_PATH + "/export_attack_template.py"
    EXPORT_ATTACK_NAME_REGEX = "_ATTACK_NAME"
    EXPORT_COMBINED_ATTACK_NAME_REGEX = "_ATTACK_COMBINED_NAME"

    # Export Attack Suite Constants
    EXPORT_ATTACK_SUITE_TEMPLATE_NAME = BASE_PATH + "/export_attack_suite_template.py"
    EXPORT_ATTACK_SUITE_NAME_REGEX = "_ATTACK_SUITE_NAME"
    EXPORT_COMBINED_ATTACK_SUITE_NAME_REGEX = "_ATTACK_SUITE_COMBINED_NAME"

    @staticmethod
    def get_export_texts_and_values():
        return [
            {"text": ".zip", "value": ExportTypes.ZIP},
            {"text": ".tar.gz", "value": ExportTypes.TAR_GZ}
        ]

    @staticmethod
    def export_function_factory(export_type):
        """
        Export function factory to decide method of archive
        :type export_type: ExportTypes
        :return: Corresponding export function
        """
        if export_type == ExportTypes.TAR_GZ:
            return ExportUtil.export_files_with_tar
        else:
            return ExportUtil.export_files_with_zip

    @staticmethod
    def export_files_with_zip(output_name, list_of_files, output_path="./"):
        if not output_name.endswith(".zip"):
            output_name = output_name + ".zip"
        zf = zipfile.ZipFile(output_path + output_name, mode='w')
        for _file in list_of_files:
            try:
                logger.info("File {0} is added to {1}".format(_file, output_name))
                if len(_file) == 2:
                    # Create file
                    zf.write(_file[0], _file[1])
                else:
                    # Create directory
                    zf.writestr(zipfile.ZipInfo(_file[0]), '')
            except RuntimeError as _:
                logger.error("Error has occurred while compressing file {0}".format(_file[0]))
        zf.close()

    @staticmethod
    def export_files_with_tar(output_name, list_of_files, output_path="./"):
        if not output_name.endswith(".tar.gz"):
            output_name = output_name + ".tar.gz"
        tar = tarfile.open(output_path + output_name, "w:gz")
        for _file in list_of_files:
            try:
                logger.info("File {0} is added to {1}".format(_file, output_name))
                if len(_file) == 2:
                    # Create file
                    tar.add(_file[0], _file[1])
                else:
                    # Create directory
                    t = tarfile.TarInfo(_file[0])
                    t.type = tarfile.DIRTYPE
                    tar.addfile(t)
            except RuntimeError as _:
                logger.error("Error has occurred while compressing file {0}".format(_file[0]))
        tar.close()

    @staticmethod
    def export_protocol(protocol_name, export_path, export_type, output_name):
        temporary_file_name = None
        try:
            logger.info("Exporting protocol is started.")

            # Check whether output name has any possible naming
            if len(output_name.split(".")[0].strip()) == 0:
                output_name = protocol_name

            temporary_file_name = ExportUtil._create_temporary_file_and_replace_regex(
                template_name=ExportUtil.EXPORT_PROTOCOL_TEMPLATE_NAME,
                regex_list=[
                    (ExportUtil.EXPORT_PROTOCOL_NAME_REGEX, protocol_name)
                ]
            )

            # Decide function and export with respect to corresponding archive
            export_func = ExportUtil.export_function_factory(export_type)
            export_func(
                output_name,
                [  # [0] represents actual file path and [1] represents the name of file in compressed file
                    (ExportUtil.BASE_PATH + "/../../Entity/protocol.py", "protocol.py"),
                    (temporary_file_name, protocol_name + "_protocol.py"),
                    (temporary_file_name, "__init__.py"),
                    ("attacks/__init__.py",)
                ],
                export_path
            )

            logger.info("Exporting protocol is finished.")
        except Exception as _:
            logger.error("Error has occurred while exporting protocol.")
        finally:
            if temporary_file_name is not None:
                # Remove temporary file
                os.remove(temporary_file_name)

    @staticmethod
    def export_attack(protocol_name, attack_name, export_path, export_type, output_name):
        temporary_file_name = None
        try:
            logger.info("Exporting attack is started.")

            # Check whether output name has any possible naming
            if len(output_name.split(".")[0].strip()) == 0:
                output_name = protocol_name + "_" + attack_name

            temporary_file_name = ExportUtil._create_temporary_file_and_replace_regex(
                template_name=ExportUtil.EXPORT_ATTACK_TEMPLATE_NAME,
                regex_list=[
                    (ExportUtil.EXPORT_ATTACK_NAME_REGEX, protocol_name + " " + attack_name + " Attack"),
                    (ExportUtil.EXPORT_COMBINED_ATTACK_NAME_REGEX, protocol_name + attack_name + "Attack")
                ]
            )

            # Decide function and export with respect to corresponding archive
            export_func = ExportUtil.export_function_factory(export_type)
            export_func(
                output_name,
                [  # [0] represents actual file path and [1] represents the name of file in compressed file
                    (ExportUtil.BASE_PATH + "/../../Entity/attack.py", "attack.py"),
                    (ExportUtil.BASE_PATH + "/../../Entity/input_format.py", "input_format.py"),
                    (temporary_file_name, protocol_name + "_" + attack_name + "_attack.py"),
                    (temporary_file_name, "__init__.py",)
                ],
                export_path
            )

            logger.info("Exporting attack is finished.")
        except Exception as _:
            logger.error("Error has occurred while exporting attack.")
        finally:
            if temporary_file_name is not None:
                # Remove temporary file
                os.remove(temporary_file_name)

    @staticmethod
    def export_attack_suite(protocol_name, attack_suite_name, export_path, export_type, output_name):
        temporary_file_name = None
        try:
            logger.info("Exporting attack suite is started.")

            # Check whether output name has any possible naming
            if len(output_name.split(".")[0].strip()) == 0:
                output_name = protocol_name + "_" + attack_suite_name + "_suite"

            temporary_file_name = ExportUtil._create_temporary_file_and_replace_regex(
                template_name=ExportUtil.EXPORT_ATTACK_SUITE_TEMPLATE_NAME,
                regex_list=[
                    (ExportUtil.EXPORT_ATTACK_SUITE_NAME_REGEX, protocol_name + " "
                     + attack_suite_name + " Attack Suite"),
                    (ExportUtil.EXPORT_COMBINED_ATTACK_SUITE_NAME_REGEX, protocol_name
                     + attack_suite_name + "AttackSuite")
                ]
            )

            # Decide function and export with respect to corresponding archive
            export_func = ExportUtil.export_function_factory(export_type)
            export_func(
                output_name,
                [  # [0] represents actual file path and [1] represents the name of file in compressed file
                    (ExportUtil.BASE_PATH + "/../../Entity/attack_suite.py", "attack_suite.py"),
                    (temporary_file_name, protocol_name + "_" + attack_suite_name + "_attack_suite.py"),
                    (temporary_file_name, "__init__.py",)
                ],
                export_path
            )

            logger.info("Exporting attack suite is finished.")
        except Exception as _:
            logger.error("Error has occurred while exporting attack.")
        finally:
            if temporary_file_name is not None:
                # Remove temporary file
                os.remove(temporary_file_name)

    @staticmethod
    def _create_temporary_file_and_replace_regex(template_name=None, regex_list=None):
        if regex_list is None:
            regex_list = []

        # Read template
        with open(template_name, "r") as export_template_file:
            content = export_template_file.read()

        temporary_file_name = random_util.get_random_file_name()
        content_replaced = \
            ExportUtil._replace_regex(content, regex_list)

        # Write template to temporary file
        with open(temporary_file_name, "w") as temporary_file:
            temporary_file.write(content_replaced)

        return temporary_file_name

    @staticmethod
    def _replace_regex(content, substitution_list_as_tuples):
        for pair in substitution_list_as_tuples:
            content = re.sub(pair[0], pair[1], content)
        return content

    @staticmethod
    def export_action(protocol_name, attack_name, attack_suite_name, file_path, file_name, extension, option):
        file_path = file_path if file_path.endswith("/") else file_path + "/"
        if option == ExportOptions.PROTOCOL:
            ExportUtil.export_protocol(protocol_name, file_path, extension, file_name)
        elif option == ExportOptions.ATTACK:
            ExportUtil.export_attack(protocol_name, attack_name, file_path, extension, file_name)
        elif option == ExportOptions.ATTACK_SUITE:
            ExportUtil.export_attack_suite(protocol_name, attack_suite_name, file_path, extension, file_name)
        else:
            raise ValueError("Unknown export option!")


if __name__ == '__main__':
    ExportUtil.export_protocol("KNX", "./", ExportTypes.ZIP, "hey")
