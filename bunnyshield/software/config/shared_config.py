# IMPORTS
import os
import subprocess
from dataclasses import dataclass


@dataclass
class GeneralConfig():
    PID = os.getpid()

    # FILES
    json_config_file_name = "bs-config.json"
    json_honeypot_data_file_name = "honeypot-paths-n-hashes.json"
    honeypot_names_file = "honeypot-names.txt"
    honeypot_interval_count_file_name = "honeypot_interval_count.txt"
    honey_folder_name = 'Bunnyshield PDFs'
    file_update_interval = 30

    # HONEYPOT
    random_honeypot_file_name = True
    honeypot_file_name = "r4n50mw4r3-d373c70r.txt"
    honeypot_file_extension = ".txt"
    hidden_honeypot_file = True

    # GENERAL
    delete_honeypots = False
    skip_to_monitor = False
    immediate_mode = False

    # INTERVALS
    honeypot_interval = 20
    disable_honeypot_interval = False
    check_ransom_time = 5
    unknow_extension_event_count_trigger = 5
    honeypot_modified_event_count_trigger = 0
    honeypot_deleted_event_count_trigger = 0
    folder_with_honeypots_deleted_event_count_trigger = 5
    time_to_check_io = 1
    pdfs_to_generate = 10000

    # GETTING PATHS
    data_main_d = os.getcwd()
    data_software_d = os.path.join(data_main_d, "software")
    data_config_d = os.path.join(data_software_d, "config")
    data_file_ext_l = [line.rstrip() for line in open(os.path.join(data_main_d, "software\\tools\\file_extensions.txt"))]
    data_honeypot_interval_f = os.path.join(data_config_d, honeypot_interval_count_file_name)
    json_config_file_f = os.path.join(data_config_d, json_config_file_name)
    tools_d = os.path.join(data_software_d, "tools")
    user_f = os.environ['USERPROFILE']

    # SOFTWARE PATHS
    PATH_TO_MAIN_FOLDER = data_main_d
    PATH_TO_SOFTWARE_FOLDER = data_software_d
    PATH_TO_CONFIG_FOLDER = data_config_d
    PATH_TO_CONFIG_FILE = json_config_file_f
    PATH_TO_HONEYPOT_INTERVAL_COUNT_FILE = data_honeypot_interval_f
    PATH_TO_TOOLS_FOLDER = tools_d
    PATH_TO_USER_FOLDER = user_f

    # DYNAMIC CONFIG
    selected_directories = [
        "C:\\Users\\Matheus Heidemann\\Documents\\Github\\Challenge\\website-windows\\ransomware-test\\encrypt-test"
    ]
    file_ext_list = data_file_ext_l


if __name__ == "__main__":
    pass
else:
    pass
