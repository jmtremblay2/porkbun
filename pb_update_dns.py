import dns.resolver
import os
import requests
import time

TTL = int(os.environ.get("PORKBUN_DNS_TTL_SECONDS", 600))
SLEEP_TIME = 1.1 * TTL

def get_domain_ip(domain: str) -> str:
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["1.1.1.1"]  # cloudflare
    try:
        result = resolver.resolve(domain, "A")
        for ipval in result:
            return ipval.to_text()
    except Exception:
        return None


def get_lan_ip() -> str:
    try:
        return requests.get("https://ipapi.co/ip/").text
    except Exception:
        return None


def ping_porkbun(api_key, secret_key):
    url = "https://api.porkbun.com/api/json/v3/ping"
    body = {
        "secretapikey": secret_key,
        "apikey": api_key,
    }
    res = requests.post(url, json=body)
    if res:
        print("Porkbun API is up and running")
        print(res.json())
    else:
        raise Exception("Porkbun API is down")


def update_dns_records(domains: list[str], secret_key: str, api_key: str):
    update_record_url = (
        "https://api.porkbun.com/api/json/v3/dns/editByNameType/{domain}/A"
    )
    lan_ip = get_lan_ip()
    if not lan_ip:
        raise ConnectionError("can't figure out my IP")

    body = {
        "secretapikey": secret_key,
        "apikey": api_key,
        "content": lan_ip,
    }
    for domain in domains:
        domain_ip = get_domain_ip(domain)
        if not domain_ip:
            print(f"can't figure out the IP of {domain}")
        elif lan_ip != domain_ip:
            print(
                f"for {domain}: mismatch between {lan_ip} and {domain_ip}, updating DNS record"
            )
            url = update_record_url.format(domain=domain)
            res = requests.post(url, json=body)
            if res:
                print(f"DNS record updated successfully. reponse={res.json()}")
            else:
                print("update failed")
        else:
            print(f"for {domain}: DNS record is up to date")


if __name__ == "__main__":
    api_key = os.getenv("PORKBUN_API_KEY")
    secret_key = os.getenv("PORKBUN_SECRET_KEY")
    domains = os.getenv("PORKBUN_DOMAINS", "")
    domains_list = domains.split(",") if domains else []
    domains = os.getenv("PORKBUN_DOMAINS","").split(",")

    assert api_key, "API Key is missing, specify PORKBUN_API_SECRET in your env"
    assert secret_key, "Secret Key is missing, specify PORKBUN_SECRET_KEY in your env"
    assert (
        domains
    ), "Domains are missing, specify PORKBUN_DOMAINS=dom1,dom2,...,dom<n> in your env"

    # maybe use this for troubleshooting but frankly it would just be restarting anyways
    # instead, we run in a loop
    # ping_porkbun(api_key=api_key, secret_key=secret_key)

    while True:
        try:
            update_dns_records(domains, secret_key, api_key)
        except Exception as e:
            print(e)
        time.sleep(SLEEP_TIME)

