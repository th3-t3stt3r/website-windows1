import hashlib
import os
import json
import pathlib
import re
import time
from software.tools.logger import logger
from software.config.shared_config import GeneralConfig as gc


class DataCreator:
    def generateHoneypotsJson(honeypot_files_hash_list):
        """Função para gerar o JSON com as entradas de cada honeypot"""
        logger.debug("Generating JSON file.")
        json_object = json.dumps(honeypot_files_hash_list, indent=4)

        if not os.path.exists(gc.PATH_TO_CONFIG_FOLDER):
            os.makedirs(gc.PATH_TO_CONFIG_FOLDER)

        with open(os.path.join(gc.PATH_TO_CONFIG_FOLDER, gc.json_honeypot_data_file_name), 'w') as f:
            f.write(json_object)

    #

    def generateHoneypotNamesTxt(honeypot_names_list):
        """Função para gerar o .txt com os nomes de cada honeypot"""
        logger.debug("Generating Honeypot names file.")
        if not os.path.exists(gc.PATH_TO_CONFIG_FOLDER):
            os.makedirs(gc.PATH_TO_CONFIG_FOLDER)

        with open(os.path.join(gc.PATH_TO_CONFIG_FOLDER, gc.honeypot_names_file), 'w') as f:
            for name in honeypot_names_list:
                f.write(f"{name}\n")

    #

    def generateHoneypotDataDict(honeypot_file):
        """Função para gerar uma hash para o arquivo de honeypot criado"""
        file_data = honeypot_file.read()
        readable_hash = hashlib.sha1(file_data).hexdigest()

        honeypot_file_hash_dict = {
            "absolute_path": honeypot_file.name,
            "hash": readable_hash
        }
        return honeypot_file_hash_dict

    #

    def generateHoneypotIntervalCountTxt():
        if not os.path.exists(gc.PATH_TO_CONFIG_FOLDER):
            os.makedirs(gc.PATH_TO_CONFIG_FOLDER)

        with open(os.path.join(gc.PATH_TO_HONEYPOT_INTERVAL_COUNT_FILE), 'w') as f:
            f.write("1")

    #

    def generateConfigFile():
        if not os.path.exists(gc.PATH_TO_CONFIG_FOLDER):
            os.makedirs(gc.PATH_TO_CONFIG_FOLDER)

        config_dict = {
            "files": {
                "json_config_file_name": gc.json_config_file_name,
                "json_honeypot_data_file_name": gc.json_honeypot_data_file_name,
                "honeypot_names_file": gc.honeypot_names_file,
                "honeypot_interval_count_file_name": gc.honeypot_interval_count_file_name,
                "file_update_interval": gc.file_update_interval

            },
            "honeypot": {
                "honeypot_file_name": gc.honeypot_file_name,
                "honeypot_file_extension": gc.honeypot_file_extension,
                "random_honeypot_file_name": gc.random_honeypot_file_name,
                "hidden_honeypot_file": gc.hidden_honeypot_file,

            },
            "general": {
                "delete_honeypots": gc.delete_honeypots,
                "skip_to_monitor": gc.skip_to_monitor,
                "immediate_mode": gc.immediate_mode
            },
            "intervals": {
                "honeypot_interval": gc.honeypot_interval,
                "disable_honeypot_interval": gc.disable_honeypot_interval,
                "check_ransom_time": gc.check_ransom_time,
                "unknow_extension_event_count_trigger": gc.unknow_extension_event_count_trigger,
                "honeypot_modified_event_count_trigger": gc.honeypot_modified_event_count_trigger,
                "honeypot_deleted_event_count_trigger": gc.honeypot_deleted_event_count_trigger,
                "folder_with_honeypots_deleted_event_count_trigger": gc.folder_with_honeypots_deleted_event_count_trigger,
            },
            "software-paths": {
                "PATH_TO_MAIN_FOLDER": gc.PATH_TO_MAIN_FOLDER,
                "PATH_TO_SOFTWARE_FOLDER": gc.PATH_TO_SOFTWARE_FOLDER,
                "PATH_TO_CONFIG_FOLDER": gc.PATH_TO_CONFIG_FOLDER,
                "PATH_TO_CONFIG_FILE": gc.PATH_TO_CONFIG_FILE,
                "PATH_TO_HONEYPOT_INTERVAL_COUNT_FILE": gc.PATH_TO_HONEYPOT_INTERVAL_COUNT_FILE,

            }}

        json_object = json.dumps(config_dict, indent=4)

        with open(os.path.join(gc.PATH_TO_CONFIG_FILE), 'w') as f:
            f.write(json_object)

    #

    def generateSysinternalsFolder():
        if not os.path.exists(gc.PATH_TO_SYSINTERNALS_FOLDER):
            os.mkdir(gc.PATH_TO_SYSINTERNALS_FOLDER)

        if not os.path.exists(gc.PATH_TO_SYSINTERNALS_HANDLE_FOLDER):
            os.mkdir(gc.PATH_TO_SYSINTERNALS_HANDLE_FOLDER)


class DataRemover:
    def deleteHoneypotsJson():
        """Função deletar o JSON com as entradas de cada honeypot"""
        logger.debug("Deleting JSON file.")
        if os.path.exists(gc.PATH_TO_CONFIG_FOLDER):
            try:
                os.remove(os.path.join(gc.PATH_TO_CONFIG_FOLDER, gc.json_honeypot_data_file_name))
            except FileNotFoundError:
                logger.error(f'Could not find {gc.json_honeypot_data_file_name} in {gc.PATH_TO_CONFIG_FOLDER}. Quitting...')
                quit()

    #

    def deleteHoneypotNamesTxt():
        """Função para deletar o arquivo com os nomes dos honeypots"""
        logger.debug("Deleting Honeypot names file.")
        if os.path.exists(gc.PATH_TO_CONFIG_FOLDER):
            try:
                os.remove(os.path.join(gc.PATH_TO_CONFIG_FOLDER, gc.honeypot_names_file))
            except FileNotFoundError:
                logger.error(f'Could not find {gc.honeypot_names_file} in {gc.PATH_TO_CONFIG_FOLDER}.')

    #

    def deleteHoneypotIntervalCountTxt():
        """Função para deletar o arquivo com o intervalo atual de criação dos honeypots"""
        logger.debug("Deleting Honeypot interval count file.")
        if os.path.exists(gc.PATH_TO_CONFIG_FOLDER):
            try:
                os.remove(gc.PATH_TO_HONEYPOT_INTERVAL_COUNT_FILE)
            except FileNotFoundError:
                logger.error(f'Could not find {gc.honeypot_interval_count_file_name} in {gc.PATH_TO_CONFIG_FOLDER}.')

    #

    def deleteConfigFile():
        """Função para deletar o arquivo de config"""
        logger.debug("Deleting config file.")
        if os.path.exists(gc.PATH_TO_CONFIG_FOLDER):
            try:
                os.remove(gc.PATH_TO_CONFIG_FILE)
            except FileNotFoundError:
                logger.error(f'Could not find {gc.json_config_file_name} in {gc.PATH_TO_CONFIG_FOLDER}.')


class DataUpdater:
    def getJsonData(json_file):
        try:
            with open(os.path.join(gc.PATH_TO_CONFIG_FOLDER, json_file)) as f:
                json_file_data = json.load(f)
            return json_file_data

        except FileNotFoundError:
            logger.error(f'Could not find {gc.json_honeypot_data_file_name} in {gc.PATH_TO_CONFIG_FOLDER}. Quitting...')
            quit()

    #

    def getTxtData(json_file):
        try:
            honeypot_names_data = []
            with open(os.path.join(gc.PATH_TO_CONFIG_FOLDER, json_file), "r") as f:
                for line in f:
                    honeypot_names_data.append(line.rstrip())
                return honeypot_names_data

        except Exception as e:
            logger.error(e)

    #

    def updateCreate(honeypot_dicts, honeypot_old_new_dicts, json_file_data):
        """"""
        start = time.perf_counter()

        try:
            for honeypot_dict in honeypot_dicts:
                json_file_data.append(honeypot_dict)

            if honeypot_old_new_dicts:
                for element in json_file_data:
                    already_appended = False
                    for honeypot_dict in honeypot_old_new_dicts:
                        if not already_appended:
                            if honeypot_dict['old_path'] in element['absolute_path']:
                                element['absolute_path'] = honeypot_dict['new_path']
                                already_appended = True

            with open(os.path.join(gc.PATH_TO_CONFIG_FOLDER, gc.json_honeypot_data_file_name), "w") as f:
                json.dump(json_file_data, f)

            if gc.random_honeypot_file_name:
                for honeypot_dict in honeypot_dicts:
                    honeypot_file_name = pathlib.Path(re.findall("([^\/]+$)", honeypot_dict['absolute_path'])[0])
                    DataUpdater.updateHoneypotNamesTxt([honeypot_file_name], 'create')

            end = time.perf_counter()
            logger.debug(f"Updated JSON for CREATE event in {round(end - start, 3)}s.")

        except Exception as e:
            logger.error(e)

    #

    def updateMoveOrRename(honeypot_old_new_dicts, json_file_data):
        start = time.perf_counter()
        new_json_file_data = []
        try:
            for element in json_file_data:
                for honeypot_dict in honeypot_old_new_dicts:
                    if honeypot_dict['old_path'] in element['absolute_path']:
                        element['absolute_path'] = honeypot_dict['new_path']
                new_json_file_data.append(element)

            with open(os.path.join(gc.PATH_TO_CONFIG_FOLDER, gc.json_honeypot_data_file_name), 'w') as f:
                f.write(json.dumps(new_json_file_data, indent=4))

            end = time.perf_counter()
            logger.debug(f"Updated JSON for UPDATE event in {round(end - start, 3)}s.")

        except Exception as e:
            logger.error(e)

    #

    def updateDelete(event_paths, json_file_data):
        """"""
        start = time.perf_counter()

        try:
            new_json_file_data = []
            names_to_delete = []

            for element in json_file_data:
                for event_path in event_paths:
                    if event_path in element['absolute_path']:
                        if event_path not in names_to_delete:
                            names_to_delete.append(element['absolute_path'])

            for element in json_file_data:
                if element['absolute_path'] in names_to_delete:
                    pass
                else:
                    new_json_file_data.append(element)

            with open(os.path.join(gc.PATH_TO_CONFIG_FOLDER, gc.json_honeypot_data_file_name), 'w') as f:
                f.write(json.dumps(new_json_file_data, indent=4))

            end = time.perf_counter()
            logger.debug(f"Updated JSON for DELETE event in {round(end - start, 3)}s.")

            if gc.random_honeypot_file_name:
                DataUpdater.updateHoneypotNamesTxt(names_to_delete, "delete")

        except Exception as e:
            logger.error(e)

    #

    def updateHoneypotNamesTxt(honeypot_names, action):
        if gc.random_honeypot_file_name:
            if action == "create":
                try:
                    with open(os.path.join(gc.PATH_TO_CONFIG_FOLDER, gc.honeypot_names_file), 'a') as f:
                        for honeypot_name in honeypot_names:
                            f.write(f"{honeypot_name}\n")
                except Exception as e:
                    logger.error(e)

            elif action == "delete":
                try:
                    new_name_list = []
                    has_delete_num = False

                    with open(os.path.join(gc.PATH_TO_CONFIG_FOLDER, gc.honeypot_names_file), 'r') as f:
                        names_in_file = [name.rstrip() for name in f]

                    with open(os.path.join(gc.PATH_TO_CONFIG_FOLDER, gc.honeypot_names_file), 'w') as f:
                        for name in names_in_file:
                            for honeypot_name in honeypot_names:
                                if name == honeypot_name:
                                    has_delete_num = True
                            if not has_delete_num:
                                new_name_list.append(name)
                            has_delete_num = False

                        for name in new_name_list:
                            f.write(f"{name}\n")

                except Exception as e:
                    logger.error(e)
        else:
            pass
