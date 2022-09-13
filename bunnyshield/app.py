if __name__ == "__main__":
    # Modules imports
    import psutil
    from colorama import init
    from pyfiglet import Figlet
    from termcolor import colored

    # Files imports
    from software.tools.logger import logger
    import software.app.monitor as FileMonitor
    import software.app.honeypot_generator as HoneypotGenerator
    from software.config.shared_config import GeneralConfig as gc

    # Set BunnyShield Priority
    psutil.Process(gc.PID).nice(psutil.HIGH_PRIORITY_CLASS)

    # Start
    init()
    f = Figlet(font='slant')
    print(colored(f.renderText('BunnyShield'), 'red'))
    print(colored('--- A Ransomware Detector by Bash Bunny Group ---\n\n', 'red'))
    logger.debug("Starting BunnyShield Protection")

    # Generate Honeypots
    if not gc.skip_to_monitor:
        logger.debug("Starting Honeypot Generator")
        HoneypotGenerator.start()

    # File Monitor
    if not gc.delete_honeypots:
        logger.debug("Starting File Monitor")
        FileMonitor.start()
    else:
        quit()

    # Quit
    logger.debug("Quitting Ransomware Detector")
