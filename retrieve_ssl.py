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
import time
from typing import Dict

import systemd

LOG_LEVEL = os.environ.get("PORKBUN_CERT_LOG_LEVEL", "INFO")
logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

time_to_look_for_new_cert = datetime.timedelta(days=100)
time_to_wait_when_expected = datetime.timedelta(days=1)

delay_map = {
    datetime.timedelta(
        days=30
    ): 10,  # check every 10 days if expires in 30 days or more
    datetime.timedelta(days=0): 1,  # check every day if expires soon
}


def get_domain_certs(config) -> Dict[str, str]:
    certs_endpoint = "https://api.porkbun.com/api/json/v3/ssl/retrieve/{domain}"
    uri = certs_endpoint.format(domain=config["domain"])
    body = {
        "apikey": config["pb_api_key"],
        "secretapikey": config["pb_secret_key"],
    }
    res = requests.post(uri, json=body)
    res.raise_for_status()
    return res.json()


def get_host_certificate_id(cur, domain: str) -> id:
    domain_names = [domain]
    domain_names_json = json.dumps(domain_names, ensure_ascii=False)
    stmt = """select certificate_id from proxy_host where domain_names = :domain_names_json;"""
    cur.execute(stmt, {"domain_names_json": domain_names_json})
    certificate_id = cur.fetchone()
    if certificate_id:
        return certificate_id[0]
    else:
        raise ValueError(f"could not find certificate id for domain {domain}")


def update_certificate(
    cur, cert_id: int, expires_on: datetime.datetime, new_cert: Dict[str, str]
):
    # TODO: this is just the DB, update the files here too
    expires_on_str = expires_on.strftime("%Y-%m-%d %H:%M:%S")
    meta_dict = {
        "certificate": new_cert["certificatechain"],
        "certificate_key": new_cert["privatekey"],
    }
    meta_str = json.dumps(meta_dict, separators=(",", ":"), ensure_ascii=False)

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


def key_to_file(key: str, path: str):
    with open(path, "wb") as f:
        f.write(key.encode("utf-8"))


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


def get_sleep_time(cert):
    cert_time_range = get_cert_time_range(cert)
    now = datetime.datetime.now(datetime.timezone.utc)
    time_until_expiration = cert_time_range["not_after"] - now
    if time_until_expiration > time_to_look_for_new_cert:
        delay = time_until_expiration - time_to_look_for_new_cert
        return delay
    else:
        # we expected a new certificate by now but clearly it's not available
        # wait for a default time period of one day
        return time_to_wait_when_expected


def cert_update_loop(conn: sqlite3.Connection, config: configparser.SectionProxy):
    while True:
        # find when the current certificate expires
        domain_cert = config["domain_cert"]
        domain_cert_tr = get_cert_time_range(domain_cert)
        now = datetime.datetime.now(datetime.timezone.utc)

        if domain_cert_tr["not_after"] - now < time_to_look_for_new_cert:
            # start probing for a new certificate
            try:
                pb_certs = get_domain_certs(config)
            except Exception as e:
                msg = f"failed to retrieve new certificate. error:{e}"
                logger.error(msg)
                time.sleep(time_to_wait_when_expected.total_seconds())
                continue

            # check if the new certificate is really new
            pb_cert_tr = get_cert_time_range(pb_certs["certificatechain"])
            # if the new certificate has an expiration date that is different from the current one
            # then update the current certificate
            if True:  # new_not_after > not_after:
                # stop the service
                service = config["service"]
                systemd.stop(service)

                # update the certificate files
                cur = conn.cursor()
                cert_id = get_host_certificate_id(cur, config["domain"])
                key_to_file(pb_certs["certificatechain"], config["domain_cert"])
                key_to_file(pb_certs["privatekey"], config["private_key"])
                # update nginx db entry for that certificate
                update_certificate(
                    cur, cert_id, expires_on=pb_cert_tr["not_after"], new_cert=pb_certs
                )
                cur.close()
                conn.commit()

                systemd.start(service)

            else:
                # could not perform the update, does not matter we'll
                # try again soon
                msg = (
                    f"could not update certificate, current cert expires at {not_after} "
                    f"new cert expires at {new_not_after}"
                )
                logger.warning(msg)
        else:
            # nothing to do we're not due for renewal
            msg = f"not due for renewal, current cert expires at {domain_cert_tr['not_after']}"
            logger.info(msg)

        sleep_time = get_sleep_time(domain_cert)
        logger.info(f"sleeping for {sleep_time}")
        sleep_time_seconds = sleep_time.total_seconds()
        break
        time.sleep(sleep_time_seconds)


if __name__ == "__main__":
    # get config
    CONFIG_PATH = os.environ.get("NPM_CERTS_CONFIG", "/etc/npm/certs.ini")
    config = configparser.ConfigParser()
    config.read(CONFIG_PATH)
    npm_config = config["npm_certs"]

    # DB connection
    conn = sqlite3.connect(npm_config["db"])

    cert_update_loop(conn, config=npm_config)
