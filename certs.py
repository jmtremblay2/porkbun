import argparse
import configparser
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import datetime
import json
import logging
import os
import requests
import sqlite3
import sys
import time
from typing import Dict

import systemd

# PORKBUN_API_KEY = os.environ["PORKBUN_API_KEY"]
# PORKBUN_SECRET_KEY = os.environ["PORKBUN_SECRET_KEY"]
LOG_LEVEL = os.environ.get("PORKBUN_CERT_LOG_LEVEL", "INFO")
logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)
time_to_look_for_new_cert = datetime.timedelta(days=21)
one_day = 24 * 60 * 60


class CertificateNotAvailable(Exception):
    pass


def get_conn(config):
    db_path = os.path.join(config["global"]["data_path"], config["global"]["database"])
    logger.info(f"connecting to database at {db_path}")
    conn = sqlite3.connect(db_path)
    return conn


def get_config_path():
    pass


def parse_config():
    CONFIG_PATH = os.environ.get("NPM_CERTS_CONFIG", "/etc/npm/certs.ini")
    config_raw = configparser.ConfigParser()
    config_raw.read(CONFIG_PATH)

    def get_proxy_host_cert_id(cur, proxy_host):
        # no exception check, this needs to work
        domain_json = json.dumps([proxy_host], ensure_ascii=False)
        stmt = """select id, certificate_id from proxy_host where domain_names = :domain_json;"""
        cur.execute(stmt, {"domain_json": domain_json})
        res = cur.fetchall()
        assert (
            len(res) == 1
        ), f"could not find certificate for {proxy_host}. found {res}"
        id, certificate_id = res[0]
        return certificate_id  # proxy_host, id, certificate_id

    def get_cert_domain_filepath_from_id(data_path, cert_id):
        fullpath = os.path.join(
            data_path, "custom_ssl", f"npm-{cert_id}", "fullchain.pem"
        )
        assert os.path.exists(fullpath), f"cant'f find domain cert for {cert_id}"
        return fullpath

    def get_cert_private_key_filepath_from_id(data_path, cert_id):
        fullpath = os.path.join(
            data_path, "custom_ssl", f"npm-{cert_id}", "privkey.pem"
        )
        assert os.path.exists(fullpath), f"cant'f find private key for {cert_id}"
        return fullpath

    config = {"domains": {}}
    for section in config_raw.sections():
        if section == "global":
            config[section] = dict(config_raw.items(section))
            # debug feature to test the update certificate
            config[section]["debug_test_update_cert"] = (
                bool(config[section].get("debug_test_update_cert", False))
            )
            if config[section]["debug_test_update_cert"]:
                logger.warning(
                    "debug_test_update_cert is enabled, running only one iteration"
                )
                config[section]["num_iter"] = 1
        else:
            config["domains"][section] = dict(config_raw.items(section))

    conn = get_conn(config)
    for domain in config["domains"]:
        d = config["domains"][domain]  # alias for simplicity
        d["domain"] = domain
        d["proxy_hosts"] = d["proxy_hosts"].split(",")

        # all the proxy hosts in the domain should have the same certificate
        certs = {
            get_proxy_host_cert_id(conn.cursor(), proxy_host)
            for proxy_host in d["proxy_hosts"]
        }
        assert (
            len(certs) == 1
        ), f"proxy hosts in section {section} have different certificates"
        cert_id = certs.pop()

        d["certificate_id"] = cert_id
        d["domain_cert"] = get_cert_domain_filepath_from_id(
            config["global"]["data_path"], cert_id
        )
        d["private_key"] = get_cert_private_key_filepath_from_id(
            config["global"]["data_path"], cert_id
        )
    return config


def get_domain_certs(global_config, config) -> Dict[str, str]:
    certs_endpoint = "https://api.porkbun.com/api/json/v3/ssl/retrieve/{domain}"
    uri = certs_endpoint.format(domain=config["domain"])
    body = {
        "apikey": global_config["pb_api_key"],
        "secretapikey": global_config["pb_secret_key"],
    }
    res = requests.post(uri, json=body)
    res.raise_for_status()
    return res.json()


def update_certificate(cur, pb_certs: Dict[str, str], domain: str, config: Dict):
    logger.info(f"updating certificate for {domain}")
    domain_config = config["domains"][domain]
    debug_test_update_cert = config["global"]["debug_test_update_cert"]

    domain_cert_tr = get_cert_time_range(domain_config["domain_cert"])
    pb_certs_tr = get_cert_time_range(pb_certs["certificatechain"])
    new_cert_not_newer = pb_certs_tr["not_after"] <= domain_cert_tr["not_after"]
    if new_cert_not_newer and not debug_test_update_cert:
        raise CertificateNotAvailable(
            f"new certificate is not newer than the current one. "
            f"current cert expires at {domain_cert_tr['not_after']} "
            f"new cert expires at {pb_certs_tr['not_after']}"
        )
    else:
        msg = f"proceeding with certificate update. old cert expires at {domain_cert_tr['not_after']} new cert expires at {pb_certs_tr['not_after']}"
        logger.debug(msg)

    cert_id = domain_config["certificate_id"]
    expires_on = pb_certs_tr["not_after"]
    expires_on_str = expires_on.strftime("%Y-%m-%d %H:%M:%S")
    meta_dict = {
        "certificate": pb_certs["certificatechain"],
        "certificate_key": pb_certs["privatekey"],
    }
    meta_str = json.dumps(meta_dict, separators=(",", ":"), ensure_ascii=False)

    logger.debug(f"updating certificate entry for {domain}")
    stmt = """
        update certificate 
        set 
            modified_on = CURRENT_TIMESTAMP,
            expires_on = :expires_on_str,
            meta = :meta_str
        where id = :cert_id;"""
    cur.execute(
        stmt,
        {"expires_on_str": expires_on_str, "meta_str": meta_str, "cert_id": cert_id},
    )

    # update the files
    def key_to_file(key: str, path: str):
        with open(path, "wb") as f:
            f.write(key.encode("utf-8"))

    logger.debug(f"updating certificate for {domain}")
    key_to_file(pb_certs["certificatechain"], domain_config["domain_cert"])
    logger.debug(f"updating private key for {domain}")
    key_to_file(pb_certs["privatekey"], domain_config["private_key"])
    logger.info(f"certificate updated for {domain}")


def get_cert_time_range(cert) -> Dict[str, datetime.datetime]:
    if os.path.exists(cert):
        with open(cert, "rb") as f:
            cert_bytes = f.read()
    elif type(cert) == str:
        cert_bytes = cert.encode("utf-8")

    cert_object = x509.load_pem_x509_certificate(cert_bytes, default_backend())
    not_before = cert_object.not_valid_before_utc
    not_after = cert_object.not_valid_after_utc

    return {"not_before": not_before, "not_after": not_after}


def cert_update_loop(
    config: configparser.SectionProxy,
):
    conn = get_conn(config)
    nginx_service_name = config["global"]["service_name"]
    global_config = config["global"]
    # find when the current certificate expires
    for domain, domain_config in config["domains"].items():
        domain_cert_tr = get_cert_time_range(domain_config["domain_cert"])
        now = datetime.datetime.now(datetime.timezone.utc)
        expires_soon = domain_cert_tr["not_after"] - now < time_to_look_for_new_cert
        debug_test_update_cert = config["global"]["debug_test_update_cert"]
        if expires_soon or debug_test_update_cert:
            # start probing for a new certificate
            try:
                pb_certs = get_domain_certs(global_config, domain_config)
            except Exception as e:
                msg = f"failed to retrieve new certificate. error:{e}"
                logger.error(msg)
                continue

            # attempt to update the certificate
            try:
                systemd.stop(nginx_service_name)
                cur = conn.cursor()
                update_certificate(cur, pb_certs, domain, config)
                conn.commit()
            except CertificateNotAvailable as e:
                msg = f"could not update certificate. error:{e}"
                logger.warning(msg)
            except Exception as e:
                msg = f"unexcepted error while updating certificate {e}"
                logger.error(msg)
            finally:
                conn.rollback()
                systemd.start(nginx_service_name)

        else:
            # nothing to do we're not due for renewal
            msg = f"not due for renewal, current cert expires at {domain_cert_tr['not_after']}"
            logger.info(msg)


def main():
    config = parse_config()
    num_iter = int(config["global"].get("num_iter", sys.maxsize))
    for i in range(num_iter):
        cert_update_loop(config)
        if i + 1 < num_iter:
            time.sleep(one_day)
        else:
            # don't sleep on the last iteration
            pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Process some integers.")
    parser.add_argument(
        "--npm-certs-config",
        type=str,
        default="/etc/npm/certs.ini",
        help="Path to the NPM certs config file",
    )
    args = parser.parse_args()
    main()
