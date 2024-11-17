# What is this?

this is a collections of utilities to manage my website with porkbun as a registrar and issuer of SSL certificates, and nginx proxy manager (NPM) as a proxy manager for SSL termination.

* ddns.py tracks local IP change and update DNS record on porkbun
* certs.py tracks NPM's internal data and requests new SSL certificates from porkbun before the current ones expires; updates NPM with new certificates.


# Python virtual environment

you can create a virtual enviroment to run a service. Assuming your reporsitory is at `/home/jm/programming/porkbun` and you want to run `certs_update.py`

```bash
cd /home/jm/programming/porkbun
python3 -m venv .venv
source .venv/bin/activate
# install dependencies
pip install -r requirements.txt
```

create a bash script `certs.sh` to run your service. this is for simplicity you could invoke python directly in your service definition. 

```bash
#!/bin/bash
# <venv location>/.venv/bin/pythn <code location>/porkbun/<program.py>
/home/jm/programming/porkbun/.venv/bin/python /home/jm/programming/porkbun/certs_update.py
```

make it executable
```
chmod +x *.sh
```

# configurations

### ddns.py
edit `/etc/porkbun/ddns.ini` with this information


```ini
[porkbun_ddns]
API_KEY=<your porkbun api key>
SECRET_KEY=<your porkbun secret key>
DOMAINS=<your coma separated domains/subdomains. example: maisym.com,i.maisym.com>
DNS_TTL_SECONDS=600
```

make root own the file and change its permissions to 600 (read-write only by root)
```bash
sudo chown root /etc/porkbun/ddns.ini
sudo chmod 600 /etc/porkbun/ddns.ini
```

### certs.py

edit `/etc/npm/certs.ini` with this information:
```ini
[global]
# name of systemd service for NPM
service_name=nginxpm.service
# data folder, assuming it's what's NPM uses (mounted in the docker for example)
data_path=/home/jm/npm_data
# database, from data_path
database=database.sqlite
# define, to true to run just once and update the certs regardless
debug_test_update_cert=true 
# number of times to run. set to 1 for cron job, default = sys.maxval
num_iter=1

[maisym.com] # section name is your domain, you can have more than one
# porkbun API key
pb_api_key=XXXXX 
pb_secret_key=XXXX
# all proxyhosts in NPM to update
proxy_hosts=maisym.com,i.maisym.com
```

# service definitions

### ddns.py
create a service definition for systemd at `/etc/systemd/system/porkbun_ddns.service`

```ini
[Unit]
Description=Dynamic DNS updates for porkbun domains
After=network.target

[Service]
# you have to change this to wherever your ddns.sh file is
ExecStart=/home/jm/programming/porkbun/ddns.sh
# change to to wherever your code is
WorkingDirectory=/home/jm/programming/porkbun
Restart=always
RestartSec=300

[Install]
WantedBy=multi-user.target
```

###  certs.py
create a service definition for systemd at `/etc/systemd/system/porkbun_certs.service`

```ini
[Unit]
Description=Dynamic DNS updates for porkbun domains
After=network.target

[Service]
# you have to change this to wherever your ddns.sh file is
ExecStart=/home/jm/programming/porkbun/certs.sh
# change to to wherever your code is
WorkingDirectory=/home/jm/programming/porkbun
Restart=always
RestartSec=300

[Install]
WantedBy=multi-user.target
```

# enable a service and verify that it works

to enable a service (example `porkbun_certs` or `porkbun_ddns`):

assuming the service is defined in `/etc/systemd/system/porkbun_certs.service`:

```bash
# Activate your service
sudo systemctl daemon-reload
sudo systemctl enable porkbun_certs
sudo systemctl start porkbun_certs

# Check that it works
sudo systemctl status porkbun_certs
journalctl -u porkbun_certs
```