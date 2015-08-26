# Apache and mod\_wsgi #

Possible VirtualHost configuration (doesn't handle SSL):
```
        ServerName example.com
        ServerAdmin webmaster@localhost

        DocumentRoot /usr/local/openipam/openIPAM/openipam/web/media

        Alias /images/ /usr/local/openipam/openIPAM/openipam/web/media/images/
        Alias /styles/ /usr/local/openipam/openIPAM/openipam/web/media/styles/
        Alias /scripts/ /usr/local/openipam/openIPAM/openipam/web/media/scripts/
        Alias /yaml/ /usr/local/openipam/openIPAM/openipam/web/media/styles/yaml/

        <Directory /usr/local/openipam/openIPAM/openipam/web/media>
                Order allow,deny
                Allow from all
        </Directory>

        WSGIDaemonProcess example.com user=openipam processes=2 threads=15 python-path=/usr/local/openipam/openIPAM display-name=%{GROUP}
        WSGIProcessGroup example.com

        WSGIScriptAlias / /usr/local/openipam/openIPAM/scripts/wsgi/openipam.wsgi

        <Directory /usr/local/openipam/openIPAM/scripts/wsgi>
                Order allow,deny
                Allow from all
        </Directory>

        ErrorLog /var/log/apache2/error.log

        # Possible values include: debug, info, notice, warn, error, crit,
        # alert, emerg.
        LogLevel info

        CustomLog /var/log/apache2/access.log combined
```