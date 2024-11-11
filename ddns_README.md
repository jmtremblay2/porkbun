# Instructions

What is this?

Porkbun has poor support for dynamic DNS updating. Apparently newer versions (as of Nov 2024) of dclient support their API but I could not find a working example. This code assumes you have domains (subdomains) registered at Porkbun and you just want to update their DNS answer when it does not match the lan's ip.

In my case I want to point `maisym.com` and `i.maisym.com` to my lan.


https://github.com/porkbundomains/porkbun-dynamic-dns-python

### Config
get an API key for your domains on porkbun.com. Then edit `/etc/porkbun/ddns.ini` with this information
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

### Create an environment

create a python virtual environment where you want this to run. Here I'm assuming the porkbun folder but you can go anywhere.
```bash
cd /home/jm/programming/porkbun
python3 -m venv .venv
source .venv/bin/activate
# install dependencies
pip install -r requirements.txt
```

create a bash script `ddns.sh` to run the ddns updater. this is for simplicity you could invoke python directly in your service definition. 

```bash
# <venv location>/.venv/bin/pythn <code location>/porkbun/ddns.py
/home/jm/programming/porkbun/.venv/bin/python /home/jm/programming/porkbun/ddns.py
```

make it executable
```
chmod +x ddns.sh
```

### Create a service 
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

### Activate your service
```bash
sudo systemctl daemon-reload
sudo systemctl enable porkbun_ddns
sudo systemctl start porkbun_ddns
```

### Check that it works
```bash
sudo systemctl status porkbun_ddns
journalctl -u porkbun_ddns
```