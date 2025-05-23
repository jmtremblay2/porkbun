import dns.resolver
import logging
import os
import requests
import time
import configparser
import re
import dotenv
import sys
LOG_LEVEL = os.environ.get("PORKBUN_DDNS_LOG_LEVEL", "INFO")
logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s - %(levelname)s - %(message)s")

logger = logging.getLogger(__name__)

CONFIG_PATH = os.environ.get("PORKBUN_DDNS_CONFIG", "/etc/porkbun/ddns.ini")


def get_update_url(domain: str) -> str:
    tokens = domain.split(".")
    if len(tokens) == 2:
        url = f"https://api.porkbun.com/api/json/v3/dns/editByNameType/{domain}/A"
    else:
        sudbomain = ".".join(tokens[:-2])
        domain = ".".join(tokens[-2:])
        url = f"https://api.porkbun.com/api/json/v3/dns/editByNameType/{domain}/A/{sudbomain}"   
    return url


# to dryrun and not update the DNS records
DRYRUN = "PORNBUN_DDNS_DRYRUN" in os.environ
FORCE_UPDATE =  bool(os.environ.get("PORKBUN_DDNS_FORCE_UPDATE",False))
# to manualy specify the target IP to use
MANUAL_IP_OVERRIDE = os.environ.get("PORKBUN_DDNS_IP_OVERRIDE", None)
SLEEP_TIME_OVERRIDE = os.environ.get("PORKBUN_DDNS_SLEEP_TIME_OVERRIDE")
if SLEEP_TIME_OVERRIDE:
    SLEEP_TIME_OVERRIDE = int(SLEEP_TIME_OVERRIDE)
MAX_ITER = int(os.environ.get("PORKBUN_DDNS_MAX_ITER", 0))
if MAX_ITER < 0:
    MAX_ITER = sys.maxsize

def validate_ip(ip: str) -> bool:
    return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip))


def check_config_permissions(config_path: str = CONFIG_PATH):
    mask = str(oct(os.stat(config_path).st_mode)[-3:])
    if mask != "600":
        msg = f"config file {config_path} must have permissions 600, got {mask}"
        raise PermissionError(msg)


def get_domain_ip(domain: str) -> str:
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["192.168.87.1"]
    try:
        result = resolver.resolve(domain, "A")
        for ipval in result:
            ip = ipval.to_text()
            if validate_ip(ip):
                return ip
            else:
                logger.error(f"invalid IP ({ip}) for {domain}")
                return None
    except Exception as e:
        return None


def get_lan_ip() -> str:
    if MANUAL_IP_OVERRIDE:
        logger.info(f"using manual IP override: {MANUAL_IP_OVERRIDE}")
        return MANUAL_IP_OVERRIDE
    
    response = requests.get("https://api.ipify.org?format=json")
    if response.status_code == 200:
        return response.json()["ip"]
    else:
        return None


def ping_porkbun(api_key: str, secret_key: str):
    url = "https://api.porkbun.com/api/json/v3/ping"
    body = {
        "secretapikey": secret_key,
        "apikey": api_key,
    }
    res = requests.post(url, json=body)
    if res:
        logger.info("Porkbun API is up and running")
        logger.debug(res.json())
    else:
        raise Exception("Porkbun API is down")


def update_dns_records(domains: list[str], secret_key: str, api_key: str):
    lan_ip = get_lan_ip()
    if not lan_ip:
        raise ConnectionError("can't figure out my own LAN IP")

    body = {
        "secretapikey": secret_key,
        "apikey": api_key,
        "content": lan_ip,
        "ttl": 600
    }
    for domain in domains:
        domain_ip = get_domain_ip(domain)
        logger.debug(f"lan_ip={lan_ip}, domain_ip={domain_ip}")
        if not domain_ip:
            logger.error(
                f"can't figure out the IP of {domain}. got {domain_ip}. skipping"
            )
        elif (lan_ip != domain_ip) or FORCE_UPDATE:
            logger.info(
                f"{domain}: mismatch between {lan_ip} and {domain_ip}, updating DNS record"
            )
            url = get_update_url(domain)
            res = requests.post(url, json=body)
            res.raise_for_status()
        else:
            logger.debug(f"{domain} DNS record is up to date")


def main():
    # check_config_permissions()
    config = configparser.ConfigParser()

    # get config
    config.read(CONFIG_PATH)
    porkbun_config = config["porkbun_ddns"]
    api_key = porkbun_config["API_KEY"]
    secret_key = porkbun_config["SECRET_KEY"]
    domains = porkbun_config["DOMAINS"].split(",")
    logger.info(f"domains: {domains}")
    ttl = int(porkbun_config.get("DNS_TTL_SECONDS", 600))

    assert api_key, "API Key is missing, specify API_SECRET in /etc/porkbun/ddns.ini"
    assert (
        secret_key
    ), "Secret Key is missing, specify SECRET_KEY in /etc/porkbun/ddns.ini"
    assert (
        domains
    ), "Domains are missing, specify DOMAINS=dom1,dom2,...,dom<n> in /etc/porkbun/ddns.ini"

    # maybe use this for troubleshooting but frankly it would just be restarting anyways
    # instead, we run in a loop
    # ping_porkbun(api_key=api_key, secret_key=secret_key)

    logger.info("Starting ddns loop")
    if SLEEP_TIME_OVERRIDE:
        sleep_time = SLEEP_TIME_OVERRIDE
    else:    
        sleep_time = (
            1.1 * ttl
        )  # slightly longer than TTL for updates to propagate... makes sense?
    for i in range(MAX_ITER):
        try:
            update_dns_records(domains, secret_key, api_key)
        except Exception as e:
            logger.critical(e)

        last_iter = i == MAX_ITER - 1
        if not last_iter:
            time.sleep(sleep_time)


if __name__ == "__main__":
    main()