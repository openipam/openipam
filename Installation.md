## Notice: This documentation is out of date ##



# Installation #

openIPAM is very modular and can work in any number of single-server or multi-server configurations. There are five major components: the openIPAM backend, the web frontend, the database server, the openDHCP server, and a PowerDNS server. It is completely up to you to decide where you would like to run each of these components. You could, technically, run all of them on the same server, but we recommend setting up openIPAM in a distributed manner.

![http://openipam.org/images/uploads/setup.png](http://openipam.org/images/uploads/setup.png)

openIPAM has been developed to run on Linux and has not been tested on any other platforms. Personally, we developed and are using it on Debian, but you are free to run it on your distribution of choice. We have done some testing on RedHat Enterprise Linux and it worked well (if you can get the right packages).

# Dependencies #

Some of the following instructions will be Debian-specific—you'll have to use your own distribution's package management.

First, add a user named `openipam` to your Linux install:
```
# adduser --home /usr/local/openipam --disabled-password --gecos "openIPAM User" openipam
```

Depending on what components you'd like to install on what servers, you will need the following packages:

## For the database server ##
To install the needed packages for the database server, run:
```
# apt-get install postgresql
```

## For the backend ##
To install the needed packages for the backend, run:
```
# apt-get install python-cherrypy3 python-ldap python-psycopg2 python-openssl python-sqlalchemy python-ipy python-cjson
```

## For the web interface ##
To install the needed packages for the web interface, run:
```
# apt-get install python-cherrypy3 python-openssl python-cheetah python-ipy python-cjson
```

## For the openDHCP server ##
To install the needed packages for the openDHCP server, run:
```
# apt-get install python-processing python-psycopg2 python-sqlalchemy
```

## For the PowerDNS server ##
To install the needed packages for the PowerDNS server, run:
```
# apt-get install pdns-server pdns-backend-pgsql postgresql
```

## For SSL on the backend and web interface ##
Depending on your environment, a certificate signed by a trusted CA should be used on the production system. For testing and development purposes, however, you can install the `ssl-cert` package and Debian will create a self-signed cert for the host. To make it convenient for development and testing, the configuration files are made to use this self-signed cert by default. If you would like to do this, run the following on both your backend server and your web frontend server:
```
# apt-get install  ssl-cert
# adduser openipam ssl-cert
```

# Download and configure openIPAM #

If you're going to use the default configuration, you'll need to create and change ownership of a couple directories:
```
# mkdir -p /var/lib/openipam/sessions/backend
# mkdir -p /var/log/openipam/backend
# mkdir -p /var/lib/openipam/sessions/web
# mkdir -p /var/log/openipam/web
# chown -R openipam /var/lib/openipam /var/log/openipam
```

Then, become the `openipam` user to download the code:
```
# su - openipam
$ svn checkout http://openipam.googlecode.com/svn/trunk/ .
```

Now, you can set up the configuration files for openIPAM. There is an example folder name `openipam_config.example`. You can copy this directory to `openipam_config` and modify the configuration:
```
$ cd openIPAM/
$ cp -r openipam_config.example/ openipam_config
$ rm -rf openipam_config/.svn
```

Now, depending on what processes you are running on which server(s), you'll need to edit the `openipam_config/backend.py` and `openipam_config/auth.py` file for the backend to work, and `openipam_config/frontend.py` for the web interface to work.  If you have certificate signed by a trusted CA, you can reference it under the `SSL` section in backend and frontend config files as well.

## Setting up database server ##
Now, as root:
```
# su - postgres
$ createuser openipam
Shall the new role be a superuser? (y/n) n
Shall the new role be allowed to create databases? (y/n) n
Shall the new role be allowed to create more new roles? (y/n) n
$ createdb -O openipam openipam
$ psql
postgres=# \password openipam
Enter new password:
Enter it again:
postgres=# \q
$ logout
```

Now, to actually create the openIPAM database structure, run:
```
# su - openipam
$ psql -d openipam -f openIPAM/sql/openipam_schema.sql

... lots of CREATE TABLE messages ...

$ logout
```

Make sure there are no ERROR: messages in the output. If not, then the database schema was created successfully.

In our installation, we use table\_log (http://pgfoundry.org/projects/tablelog/) to keep track of changes.

## CherryPy Patch until 3.1.0 ##

Until the next release of CherryPy, you'll need to apply [this patch](http://www.cherrypy.org/changeset/2015) manually:

```
# cd /usr/share/python-support/python-cherrypy3/
# patch -p 1
```

Then, copy and paste the following code into your terminal and then press Control-D:

```
Index: trunk/cherrypy/lib/xmlrpc.py
===================================================================
--- trunk/cherrypy/lib/xmlrpc.py (revision 1955)
+++ trunk/cherrypy/lib/xmlrpc.py (revision 2015)
@@ -43,5 +43,5 @@
                                   allow_none=allow_none))
 
-def on_error():
+def on_error(*args, **kwargs):
     body = str(sys.exc_info()[1])
     import xmlrpclib
Index: trunk/cherrypy/test/test_xmlrpc.py
===================================================================
--- trunk/cherrypy/test/test_xmlrpc.py (revision 1955)
+++ trunk/cherrypy/test/test_xmlrpc.py (revision 2015)
@@ -69,4 +69,5 @@
     cherrypy.tree.mount(root, config={'/': {
         'request.dispatch': cherrypy.dispatch.XMLRPCDispatcher(),
+        'tools.xmlrpc.allow_none': 0,
         }})
     cherrypy.config.update({'environment': 'test_suite'})
```

## Setting up the admin user ##

Almost there! Until we write a setup script (`*`ducks`*`), you could run the following to set the `admin` user's password to `password` (that hex string below is just a SHA512 hash, so you can change the password to whatever else you want):
```
# su - openipam
$ psql -d openipam
openipam=# INSERT INTO internal_auth (id, hash, name)
VALUES (1, 'b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86', 'Administrator');
```

# Starting the server #

## apache + mod\_wsgi ##

```
apt-get install apache2 libapache2-mod-wsgi
```

Here is what looks pertinent from the VirtualHost entries:
```
        # For the backend, we use https://...:8443
        WSGIDaemonProcess ssl.xmlrpc.ipam.usu.edu user=openipam processes=2 threads=6 python-path=/usr/local/openipam/openIPAM display-name=%{GROUP}
        WSGIProcessGroup ssl.xmlrpc.ipam.usu.edu

        WSGIScriptAlias /api /usr/local/openipam/openIPAM/scripts/wsgi/openipamd.wsgi

```

```
        # For the web frontend, we use https://...:443
        Alias /images/ /usr/local/openipam/openIPAM/openipam/web/media/images/
        Alias /styles/ /usr/local/openipam/openIPAM/openipam/web/media/styles/
        Alias /scripts/ /usr/local/openipam/openIPAM/openipam/web/media/scripts/
        Alias /yaml/ /usr/local/openipam/openIPAM/openipam/web/media/styles/yaml/

        # Be sure the user you choose here exists and has read access to
        # $OPENIPAM_HOME and read/write to the necessary directories listed
        # in the config (default locations are /var/log/openipam and
        # /var/lib/openipam/*
        WSGIDaemonProcess openipam_web user=openipam processes=2 threads=15 python-path=/usr/local/openipam/openIPAM display-name=%{GROUP}
        WSGIProcessGroup openipam_web

        WSGIScriptAlias / /usr/local/openipam/openIPAM/scripts/wsgi/openipam.wsgi

```

## The openipamd/openipam\_webd scripts are deprecated no longer tested ##

This may be useful for testing, however we do not use them anymore.

To run the backend server, run this as the `openipam` user:
```
$ ./openIPAM/openipamd
```

To run the web interface server, run this as the `openipam` user:
```
$ ./openIPAM/openipam_webd
```


## As a startup script ##
Copy the openipam\_dhcpd init script to /etc/init.d and make the proper symlinks.

The script also expects to find /etc/default/openipam\_dhcpd.

Example files:
openipam/trunk/openIPAM/scripts/etc/default/openipam\_dhcpd
openipam/trunk/openIPAM/scripts/etc/init.d/openipam\_dhcpd

Be sure to edit $OPENIPAM\_HOME/openipam\_config/dhcp.py to suit your needs.

WRITEME

# Final step #

Email us! Let us know a little about who you are, where you're from or what organization, and what brought you here. Are you attempting to use openIPAM in production, or did you just feel the need to download and test out an IP address management solution? :) Let us know! http://openipam.org/htm/contact