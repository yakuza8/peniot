from enum import Enum
from os import listdir
from os.path import isfile, join

import logging
import os
import shutil
import tarfile
import zipfile

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s:%(levelname)s:%(name)s : %(message)s")
logger = logging.getLogger("Util - Import")


class ImportOptions(Enum):
    """
    Enumeration types for import options such as Protocol, Attack_OR_Attack Suite
    If user chooses PROTOCOL, then s/he can directly import without selecting any other input
    Otherwise, we need to provide currently loaded protocols to select to which one we will import
    """
    PROTOCOL = 0
    ATTACK_OR_ATTACK_SUITE = 1


class ImportUtil(object):
    # Path related variables
    BASE_PATH_OF_TEMP = os.path.dirname(os.path.abspath(__file__))
    PROTOCOLS_DIR_NAME = "../../protocols/tmp"
    TEMP_FULL_PATH = BASE_PATH_OF_TEMP + "/" + PROTOCOLS_DIR_NAME
    TEMP_DIR_NAME = ".tmp"

    # Get entities
    ENTITY_PATH = BASE_PATH_OF_TEMP + "/../../Entity/"
    ENTITIES = [_ for _ in listdir(ENTITY_PATH) if
                isfile(join(ENTITY_PATH, _)) and not _.startswith("__") and not _.endswith(".pyc")]

    @staticmethod
    def startup():
        """
        Startup function that will be called program starting point in order to create necessary containers
        Currently creates the followings:
            * Temporary directory imported files
        """
        try:
            if os.path.isdir(ImportUtil.TEMP_FULL_PATH):
                shutil.rmtree(ImportUtil.TEMP_FULL_PATH)
            os.mkdir(ImportUtil.TEMP_FULL_PATH)
            # make this directory a package
            os.open(ImportUtil.TEMP_FULL_PATH + "/__init__.py", os.O_CREAT)
        except OSError:
            logger.error("Creation of the directory {0} failed.".format(ImportUtil.TEMP_DIR_NAME))
        else:
            logger.info("Creation of the directory {0} successfully done.".format(ImportUtil.TEMP_DIR_NAME))
        pass

    @staticmethod
    def shutdown():
        """
        Shutdown function that will be exit stage of program in order to clean everything that are already created
        """
        try:
            if os.path.isdir(ImportUtil.TEMP_FULL_PATH):
                shutil.rmtree(ImportUtil.TEMP_FULL_PATH)
        except OSError:
            logger.error("Deletion of the directory {0} failed.".format(ImportUtil.TEMP_DIR_NAME))
        else:
            logger.info("Deletion of the directory {0} successfully done.".format(ImportUtil.TEMP_DIR_NAME))
        pass

    @staticmethod
    def trigger_import(input_path, protocol_name=None):
        try:
            import_action = ImportUtil.import_function_factory(input_path)
            dir_name, file_name = os.path.split(input_path)

            # If the protocol name is provided, it means that we are importing a attack/attack suite
            # Therefore, put the imported files to corresponding attacks directory
            if protocol_name is not None:
                full_path_to_out_dir = ImportUtil.TEMP_FULL_PATH + "/" + protocol_name + "/attacks/" + \
                                       file_name.split(".", 1)[0]
            else:
                full_path_to_out_dir = ImportUtil.TEMP_FULL_PATH + "/" + file_name.split(".", 1)[0]

            try:
                os.mkdir(full_path_to_out_dir)
            except OSError:
                logger.error("Creation of the directory {0} failed.".format(full_path_to_out_dir))
            else:
                logger.info("Creation of the directory {0} successfully done.".format(full_path_to_out_dir))

            import_action(input_path, full_path_to_out_dir)

        except RuntimeError as _:
            logger.error(_.message)

    @staticmethod
    def import_function_factory(input_path):
        options = [
            (zipfile.is_zipfile, ImportUtil.import_zip),
            (tarfile.is_tarfile, ImportUtil.import_tar)
        ]
        for option in options:
            try:
                if option[0](input_path):
                    return option[1]
                else:
                    continue
            except Exception:
                pass
        raise RuntimeError("Unknown import extension!")

    @staticmethod
    def import_zip(input_path, full_out_dir_path):
        zf = zipfile.ZipFile(input_path, mode='r')
        namelist = zf.namelist()
        for _file in namelist:
            if ImportUtil._do_not_import_names(_file):
                continue
            try:
                zf.extract(_file, full_out_dir_path)
            except RuntimeError as _:
                logger.error("Error has occurred while extracting file {0}".format(_file))
        zf.close()

    @staticmethod
    def import_tar(input_path, full_out_dir_path):
        tar = tarfile.open(input_path)
        namelist = tar.getnames()
        for _file in namelist:
            if ImportUtil._do_not_import_names(_file):
                continue
            try:
                tar.extract(_file, full_out_dir_path)
            except RuntimeError as _:
                logger.error("Error has occurred while extracting file {0}".format(_file))
        tar.close()

    @staticmethod
    def import_protocol(file_path):
        ImportUtil.trigger_import(file_path)
        # Take actions with respect to importing of protocol

    @staticmethod
    def import_attack_or_attack_suite(file_path, protocol_name):
        ImportUtil.trigger_import(file_path, protocol_name)
        # Take actions with respect to importing of attack or attack suite

    @staticmethod
    def _is_file_name(name):
        """
        :param name: File name or directory name
        :return: Whether name represents file or not
        """
        return not name.endswith("/")

    @staticmethod
    def _do_not_import_names(name):
        return name in ImportUtil.ENTITIES

    @staticmethod
    def import_action(file_path, option, protocol_name=None):
        if option == ImportOptions.PROTOCOL:
            ImportUtil.import_protocol(file_path)
        elif option == ImportOptions.ATTACK_OR_ATTACK_SUITE:
            if protocol_name is None or protocol_name is "":
                raise ValueError("You need to provide protocol name to bind attack to that protocol!")
            ImportUtil.import_attack_or_attack_suite(file_path, protocol_name)
        else:
            raise ValueError("Unknown export option!")


if __name__ == '__main__':
    ImportUtil.startup()
