```
                        ___ ____   _    __  __
  ___  _ __   ___ _ __ |_ _|  _ \ / \  |  \/  |
 / _ \| '_ \ / _ \ '_ \ | || |_) / _ \ | |\/| |
| (_) | |_) |  __/ | | || ||  __/ ___ \| |  | |
 \___/| .__/ \___|_| |_|___|_| /_/   \_\_|  |_|
      |_|
               www.openipam.org
```

Copyright (C) 2007-2008 Utah State University - Information Technology
Licensed under the GNU General Public License v3. See COPYING for details.

# MACHINE SETUP

## Prerequisites

- python3.12
- pip3
- libldap2-dev
- libsasl2-dev
- postgresql

## Setup

To install dependencies, run `python3 -m pip install -r requirements.txt` in the terminal from the root directory. You may need to create a virtual environment for whichever version of python you're using (>3.12). If so, run `python3 -m venv .venv && source .venv/bin/activate`, then install the dependencies in your activated virtual environment. All python commands need to be run in this environment for the server to work.

Now we need to set up the configuration for the server. Run `cp openIPAM/openipam_config.example openIPAM/openipam_config`. Adjust the settings for `auth`, `backend`, and `dhcp` python files. Make sure that `server_listen` and `server_subnet` are both correct in the `dhcp` file (`server_subnet` is used for the test file, not the actual code, so it isn't essential unless you run the test).

## Running in Production

To allow the program to run as a service:

```bash
sudo cp openIPAM/scripts/openipam_dhcpd.service /etc/systemd/system/openipam-dhcp.service
sudo systemctl daemon-reload
sudo systemctl enable openipam-dhcp.service
sudo systemctl start openipam-dhcp.service
```

Access the logs via `journalctl -u openipam-dhcp -f`

Any time you make updates to the code, simply run `sudo systemctl restart openipam-dhcp.service`.

## Running Manually

In order to run the program, it needs to have access to port 67. There are three methods to do this:

- Run the program as sudo
- grant capabilities via `setcap`
- Using `authbind`

We'll show how to run it using Authbind, though the other methods should work:

```bash
sudo apt install authbind
sudo touch /etc/authbind/byport/67
sudo chmod 777 /etc/authbind/byport/67
# Run the command via authbind (allows python to access port 67)
authbind --deep python3 openIPAM/openipam_dhcpd.py
```

The DHCP Server should now be up and running correctly, but will stop running with `^C` or whenever the terminal closes.

## Historical Dependencies (Reference Only)

INSTALLATION & CUSTOMIZATION (LEGACY)

- http://code.google.com/p/openipam/wiki/Installation
- http://code.google.com/p/openipam/wiki/DeveloperDocumentation

DEPENDENCIES (LEGACY)

- Power DNS server
- PostgreSQL server (with table_log if you want to keep track of changes)
- python-ldap (>= 2.2.0) \*
- python-cherrypy3 (>= 3.0.3) (backend/web frontend)
- python-cjson (backend/web frontend)
- python-sqlalchemy (>= 0.4.6) (backend, dhcp)
- python-psycopg2 (backend, dhcp)
- python-openssl \*
- python-ipy
- python-processing (for DHCP server)
- python-cheetah (for web frontend)
- hacked version of pydhcplib (included in source tree)
