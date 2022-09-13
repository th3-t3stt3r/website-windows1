# Module imports
import os
import pathlib
import re
import logging
import hashlib
import time
import psutil

# File Imports
from software.tools.logger import logger
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from software.config.shared_config import GeneralConfig as gc
from software.app.honeypot_generator import generateSingleHoneypot
from software.app.data_handler import DataUpdater
from software.app.proc_killer import ProcessKiller


def start():
    """Function to start an instance of File Monitor"""
    global fm
    fm = FileMonitor()
    fm.run()


class FileMonitor:
    """File Monitor class"""

    def __init__(self):
        if os.path.exists(gc.PATH_TO_CONFIG_FOLDER):
            self.started = False
            self.start_protection_time = time.time()
            self.json_honeypot_data_file_data = DataUpdater.getJsonData(gc.json_honeypot_data_file_name)
            self.honeypot_names_file_data = DataUpdater.getTxtData(gc.honeypot_names_file)
            self.honeypots_to_delete = []
            self.honeypots_to_update = []
            self.honeypots_to_create = []
            self.has_delete_changes = False
            self.has_update_changes = False
            self.has_create_changes = False
            self.process_whitelist = []
            self.path_to_honey_folder = os.path.join(gc.PATH_TO_USER_FOLDER, gc.honey_folder_name)

        else:
            logger.error(f'Could not find {gc.json_file_name} in {gc.PATH_TO_CONFIG_FOLDER}.')
            quit()

     #

    def run(self):
        """Function to run the File Monitor"""
        observers = []
        observer = Observer()
        event_handler = self.EventHandler()

        for directory in gc.selected_directories:
            observer.schedule(event_handler, directory, recursive=True)
            observers.append(observer)

        if os.path.exists(self.path_to_honey_folder):
            observer.schedule(event_handler, self.path_to_honey_folder, recursive=True)
            observers.append(observer)

        observer.start()

        try:
            current_time = time.time()
            while True:
                if not self.started:
                    if (time.time() - self.start_protection_time) > 5:
                        self.getProcessWhitelist()
                        self.started = True
                        logger.debug('File Monitor has started.')
                        logger.debug(f'Currently monitoring {len(gc.selected_directories)} directories.')

                new_time = time.time() - current_time
                if new_time > gc.file_update_interval:
                    self.updateAllData()
                    self.checkForChangesAndUpdate()
                    current_time = time.time()

                continue

        except KeyboardInterrupt or SystemExit:
            logger.debug("Stopping File Monitor.")
            for observer in observers:
                observer.unschedule_all()
                observer.stop()
                observer.join()
            logger.debug("Updating Honeypots JSON file before exit.")
            self.checkForChangesAndUpdate()

    #

    def getProcessWhitelist(self):
        """Function to get the process Whitelist"""
        for process in psutil.process_iter():
            try:
                process_dict = {
                    "pid": process.pid,
                    "name": process.name(),
                    "create_time": process.create_time()
                }
                self.process_whitelist.append(process_dict)

            except Exception as e:
                pass
    #

    def isHonepot(self, event_path):
        """Function to check if the event path is a honeypot file"""
        if re.findall("([^\\\]+$)", event_path)[0] in self.honeypot_names_file_data:
            return True

    #

    def updateAllData(self):
        """Function to update the JSON and txt data variables"""
        fm.json_honeypot_data_file_data = DataUpdater.getJsonData(gc.json_honeypot_data_file_name)
        fm.honeypot_names_file_data = DataUpdater.getTxtData(gc.honeypot_names_file)

    #

    def checkForChangesAndUpdate(self):
        """Function to check and update the JSON and txt files"""
        if self.has_create_changes:
            DataUpdater.updateCreate(self.honeypots_to_create, fm.honeypots_to_update, fm.json_honeypot_data_file_data)
            self.updateAllData()
            self.has_create_changes = False
            self.honeypots_to_create = []

        if self.has_update_changes:
            DataUpdater.updateMoveOrRename(self.honeypots_to_update, fm.json_honeypot_data_file_data)
            self.updateAllData()
            self.has_update_changes = False
            self.honeypots_to_update = []

        if self.has_delete_changes:
            DataUpdater.updateDelete(self.honeypots_to_delete, fm.json_honeypot_data_file_data)
            self.updateAllData()
            self.has_delete_changes = False
            self.honeypots_to_delete = []

    #

    class EventHandler(FileSystemEventHandler):
        """Watchdog Event Handler Class"""

        def __init__(self):
            self.unknow_extension_event_count = 0
            self.honeypot_deleted_event_count = 0
            self.folder_with_honeypots_deleted_event_count = 0
            self.honeypot_modified_event_count = 0
            self.honey_folder_edit_event_count = 0
            self.honey_folder_edit_current_time = time.time()
            self.create_current_time = time.time()
            self.delete_current_time = time.time()
            self.modify_current_time = time.time()
            self.honey_folder_edit_check_time = time.time()
            self.ransom_create_check_time = time.time()
            self.ransom_delete_check_time = time.time()
            self.ransom_modify_check_time = time.time()
            self.check_ransom = False

        #

        def HoneyfolderEdit(self):
            """Function to automatically check for ransomware if the honeyfolder was modified in any way"""
            new_ransom_honey_folder_edit_check_time = time.time() - self.honey_folder_edit_check_time
            if new_ransom_honey_folder_edit_check_time > gc.check_ransom_time:
                self.honey_folder_edit_check_time = time.time()
                ProcessKiller().checkForMaliciousProcess(fm.process_whitelist)

        #

        def on_created(self, event):
            """Function to monitor created file events in the provided directories and the honeyfolder"""
            if fm.path_to_honey_folder in event.src_path:
                new_time = time.time() - self.honey_folder_edit_current_time
                self.honey_folder_edit_event_count += 1
                if new_time > 1:
                    logger.warning(f"File created in PDF Honeyfolder{'' if self.honey_folder_edit_event_count <= 1 else ' (and ' + str(self.honey_folder_edit_event_count) + ' more)'}.")
                    self.honey_folder_edit_current_time = time.time()
                    self.honey_folder_edit_event_count = 0
                    self.HoneyfolderEdit()

            else:
                try:
                    if os.path.isdir(event.src_path):
                        new_honeypot_dict = generateSingleHoneypot(event.src_path)
                        if new_honeypot_dict:
                            fm.honeypots_to_create.append(new_honeypot_dict)
                            fm.has_create_changes = True

                    else:
                        has_know_ext = False
                        file_ext = pathlib.Path(re.findall("([^\/]+$)", event.src_path)[0]).suffix

                        if file_ext in gc.file_ext_list:
                            has_know_ext = True

                        if not has_know_ext and not file_ext == "":
                            new_time = time.time() - self.create_current_time
                            self.unknow_extension_event_count += 1

                            if new_time > 1:
                                logger.warning(f"Unknow file extension detected \"{file_ext}\"{'' if self.unknow_extension_event_count <= 1 else ' (and ' + str(self.unknow_extension_event_count) + ' more)'}.")

                                if self.unknow_extension_event_count > gc.unknow_extension_event_count_trigger or gc.immediate_mode:
                                    self.check_ransom = True

                                self.create_current_time = time.time()
                                self.unknow_extension_event_count = 0

                            if self.check_ransom:
                                new_ransom_create_check_time = time.time() - self.ransom_create_check_time
                                if new_ransom_create_check_time > gc.check_ransom_time:
                                    self.ransom_create_check_time = time.time()
                                    ProcessKiller().checkForMaliciousProcess(fm.process_whitelist)
                                    self.check_ransom = False

                except:
                    pass

        #

        def on_modified(self, event):
            """Function to monitor modified file events in the provided directories and the honeyfolder"""
            if fm.path_to_honey_folder in event.src_path:
                new_time = time.time() - self.honey_folder_edit_current_time
                self.honey_folder_edit_event_count += 1
                if new_time > 1:
                    logger.warning(f"File modified in PDF Honeyfolder{'' if self.honey_folder_edit_event_count <= 1 else ' (and ' + str(self.honey_folder_edit_event_count) + ' more)'}.")
                    self.honey_folder_edit_current_time = time.time()
                    self.honey_folder_edit_event_count = 0
                    self.HoneyfolderEdit()

            else:
                try:
                    if fm.isHonepot(event.src_path):
                        for dict in fm.json_honeypot_data_file_data:
                            if event.src_path == dict['absolute_path']:
                                with open(event.src_path, 'rb') as honeypot_file:
                                    file_data = honeypot_file.read()
                                    current_hash = hashlib.sha1(file_data).hexdigest()

                                    if current_hash != dict['hash']:
                                        new_time = time.time() - self.modify_current_time
                                        self.honeypot_modified_event_count += 1

                                        if new_time > 1:
                                            logger.warning(f"Honeypot was modified{'' if self.honeypot_modified_event_count <= 1 else ' (and ' + str(self.honeypot_modified_event_count) + ' more)'}.")

                                            if self.honeypot_modified_event_count > gc.honeypot_modified_event_count_trigger or gc.immediate_mode:
                                                self.check_ransom = True

                                            self.modify_current_time = time.time()
                                            self.unknow_extension_event_count = 0

                                        if self.check_ransom:
                                            new_ransom_modify_check_time = time.time() - self.ransom_modify_check_time
                                            if new_ransom_modify_check_time > gc.check_ransom_time:
                                                self.ransom_modify_check_time = time.time()
                                                ProcessKiller().checkForMaliciousProcess(fm.process_whitelist)
                                                self.check_ransom = False

                    else:
                        pass

                except IndexError as e:
                    pass

                except Exception as e:
                    logger.error(e)
                    pass

        #

        def on_moved(self, event):
            """Function to monitor movoed file events in the provided directories and the honeyfolder"""
            if fm.path_to_honey_folder in event.src_path:
                new_time = time.time() - self.honey_folder_edit_current_time
                self.honey_folder_edit_event_count += 1
                if new_time > 1:
                    logger.warning(f"File moved in PDF Honeyfolder{'' if self.honey_folder_edit_event_count <= 1 else ' (and ' + str(self.honey_folder_edit_event_count) + ' more)'}.")
                    self.honey_folder_edit_current_time = time.time()
                    self.honey_folder_edit_event_count = 0
                    self.HoneyfolderEdit()

            else:
                try:
                    if not os.path.isdir(event.dest_path):
                        if re.findall("([^\/]+$)", event.src_path)[0] in fm.honeypot_names_file_data and re.findall("([^\/]+$)", event.src_path)[0] in fm.honeypot_names_file_data:
                            update_honeypot_dict = {
                                "old_path": event.src_path,
                                "new_path": event.dest_path
                            }

                            fm.honeypots_to_update.append(update_honeypot_dict)
                            fm.has_update_changes = True

                except:
                    pass

        #

        def on_deleted(self, event):
            """Function to monitor deleted file events in the provided directories and the honeyfolder"""
            if fm.path_to_honey_folder in event.src_path:
                new_time = time.time() - self.honey_folder_edit_current_time
                self.honey_folder_edit_event_count += 1
                if new_time > 1:
                    logger.warning(f"File deleted in PDF Honeyfolder{'' if self.honey_folder_edit_event_count <= 1 else ' (and ' + str(self.honey_folder_edit_event_count) + ' more)'}.")
                    self.honey_folder_edit_current_time = time.time()
                    self.honey_folder_edit_event_count = 0
                    self.HoneyfolderEdit()

            else:
                try:
                    if re.findall("([^\/]+$)", event.src_path)[0] in fm.honeypot_names_file_data:
                        if not os.path.exists(event.src_path):
                            new_time = time.time() - self.delete_current_time
                            self.honeypot_deleted_event_count += 1

                            fm.honeypots_to_delete.append(event.src_path)
                            fm.has_delete_changes = True

                            if new_time > 1:
                                logger.warning(f"Honeypot was deleted{'' if self.honeypot_deleted_event_count <= 1 else ' (and ' + str(self.honeypot_deleted_event_count) + ' more)'}.")

                                if self.honeypot_deleted_event_count > gc.honeypot_deleted_event_count_trigger or gc.immediate_mode:
                                    self.check_ransom = True

                                self.delete_current_time = time.time()
                                self.honeypot_deleted_event_count = 0

                    else:
                        if not os.path.exists(event.src_path):
                            new_time = time.time() - self.delete_current_time
                            honeypot_deleted = False

                            for element in fm.json_honeypot_data_file_data:
                                if event.src_path in element['absolute_path']:
                                    honeypot_deleted = True
                                    break
                                else:
                                    continue

                            for element in fm.honeypots_to_create:
                                if event.src_path in element['absolute_path']:
                                    honeypot_deleted = True
                                    break
                                else:
                                    continue

                            for element in fm.honeypots_to_update:
                                if event.src_path in element['new_path']:
                                    honeypot_deleted = True
                                    break
                                else:
                                    continue

                            if honeypot_deleted:
                                self.folder_with_honeypots_deleted_event_count += 1

                                fm.honeypots_to_delete.append(event.src_path)
                                fm.has_delete_changes = True

                                if new_time > 1:
                                    logger.debug(f"Folder with honeypots was deleted{'' if self.folder_with_honeypots_deleted_event_count <= 1 else ' (and ' + str(self.folder_with_honeypots_deleted_event_count) + ' more)'}.")

                                if self.folder_with_honeypots_deleted_event_count > gc.folder_with_honeypots_deleted_event_count_trigger or gc.immediate_mode:
                                    self.check_ransom = True

                                self.delete_current_time = time.time()
                                self.folder_with_honeypots_deleted_event_count = 0

                    if self.check_ransom:
                        new_ransom_delete_check_time = time.time() - self.ransom_delete_check_time
                        if new_ransom_delete_check_time > gc.check_ransom_time:
                            self.ransom_delete_check_time = time.time()
                            ProcessKiller().checkForMaliciousProcess(fm.process_whitelist)
                            self.check_ransom = False

                except IndexError as e:
                    pass

                except Exception as e:
                    logger.error(e)
                    pass


# MAIN
if __name__ == "__main__":
    pass
else:
    from software.tools.logger import logger
    logging.getLogger("watchdog.observers.inotify_buffer").disabled = True
