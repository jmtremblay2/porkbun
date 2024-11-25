import logging
import subprocess

logger = logging.getLogger(__name__)


def stop(service_name):
    try:
        subprocess.run(["sudo", "systemctl", "stop", service_name], check=True)
        logger.info(f"Successfully stopped {service_name} service")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to stop {service_name} service: {e}")


def start(service_name):
    try:
        subprocess.run(["sudo", "systemctl", "start", service_name], check=True)
        logger.info(f"Successfully started {service_name} service")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to start {service_name} service: {e}")
