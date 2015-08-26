

# Introduction #

openIPAM is a suite of applications designed to provide an intuitive and powerful IP address management system and solution for DNS and DHCP. The development of these applications has been built with the open source philosophy in mind so that other universities and organizations can benefit from (and contribute to) these applications in order to efficiently manage their own network space.

![http://openipam.org/images/uploads/setup.png](http://openipam.org/images/uploads/setup.png)

# Features #
## Intuitive IP address management ##

From a high-level perspective, the most valuable feature of openIPAM is its web application interface. This interface gives users an intuitive tool for efficiently managing IP registrations. Permissions to this system can be very granular, giving large organizations or universities the tools to spread IP management out to all their network managers.

## Centralized webservice API ##

The core foundation of openIPAM is built around a single webservice. This allows the system to be customized for the specific implementation needs of different organizations. You can create smaller, more targeted systems for specific types of users that still interface with your main DNS server. For example, you may have network managers that need access to manage their areas, but also may have "normal" end-users who should see a much simpler registration system and be able to only register their machines, or simply need guest access to the network. Interfacing with the openIPAM webservices through remote procedure calls (RPC) makes setting up and integrating these sub-systems much easier.

For more information about how to customize openIPAM and create smaller sub-systems, see the webservice API section below.

## Under the hood: PowerDNS, PostgreSQL, and SQLAlchemy ##

![http://openipam.org/images/uploads/architecture.png](http://openipam.org/images/uploads/architecture.png)

For its backend DNS, openIPAM uses PowerDNS; one of the most widely-used, robust, and secure DNS solutions available on the market today. Since PowerDNS relies on a database as its data storage mechanism, we can rapidly manage information about hosts without the pain of flat text file maintenance.

For the database itself, PostgreSQL is the database of choice for systems that heavily rely on network data types such as IP addresses, MAC addresses, CIDR netmasks, etc. Postgres has built-in data types for all of these and is very efficient in querying and manipulating them, so Postgres was the natural choice of our team and the best tool for this project. Though PostgreSQL is the primary database choice of openIPAM, we use [SQLAlchemy](http://www.sqlalchemy.org/) (specifically, SQLAlchemy's [SQL Expression Language](http://www.sqlalchemy.org/docs/05/sqlexpression.html)) as our interface to the database. SQLAlchemy allows for a system to be database-agnostic, so it could be a future goal for openIPAM to support other database backends (such as MySQL, Oracle or others). However, much of the internal code in openIPAM is Postgres-specific for efficiency's sake and it would require heavy modification to make it work with other databases. **At this time, there are no plans to support non-PostgreSQL databases in openIPAM.**

It may be valuable to note that there is **enterprise support** available for Postgres if your business-model encourages this support. The company [EnterpriseDB](http://enterprisedb.com/) provides exactly this kind of support, specifically for PostgreSQL, both for their packaged versions and normal Postgres installations.

## DHCP shared leases ##

## Integration with LDAP for authentication ##

openIPAM allows for the use of an LDAP server as a source for user accounts. There is also internal authentication, so LDAP is not required, especially if few user accounts will be needed.