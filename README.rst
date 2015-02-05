==========
do_auth.py
==========

do_auth is a Python program to work as a post-authorization script for the
``tac_plus`` TACACS+ daemon to allow greater flexibility in TACACS+
authentication and authorization. For more information on tac_plus please see
http://shrubbery.net/tac_plus.

It allows a user to be part of many predefined groups that can allow different
access to different devices based on device IP address, usernmae, and source IP
address.

Do not play with do_auth until you have a firm grasp on ``tac_plus`` and the
syntax for ``do_auth.ini``!

Versions
========

Please see ``CHANGELOG.rst`` for the version history.

Usage
=====

Easier TACACS Configurations with do_auth:

http://tacacs.org/2009/09/26/easy-tacacs-control-with-do_auth/

Example line to put in tacplus user or group::

    after authorization “/root/doauth.py -i $address -u $user -d $name -l /root/log.txt -f /root/do_auth.ini” (that’s all ONE line)

tac_plus.conf
-------------

First, a starting ``tac_plus.conf`` file. Which, we’ll never have to edit again::

    # My simple tacplus config that never needs to change
    key = mykey

    accounting file = /var/log/tacplus.acct

    default authentication = file /etc/passwd

    user = DEFAULT {
        member = doauthaccess
    }

    group = doauthaccess {
        default service = permit

        service = exec { 
            priv-lvl = 15
            idletime = 10 
        }

        enable = file /etc/passwd
        after authorization "/usr/bin/python /root/doauth.pyc -i $address -u $user -d $name -l /root/log.txt -f /root/do_auth.ini" 
    }


do_auth.ini
-----------

Now, we add homer and give him access to some show commands. First, we do a
``adduser homer`` on Linux to add the user. This way, when the user wants to
change is password, he can any time he wants to with ``passwd``. Next, we edit
the ``do_auth.ini`` file::

    [users]
    homer =
        fewcommands

    [fewcommands]
    host_allow =
        .* 
    device_permit = 
        .* 
    command_permit = 
        show users
        show int.* 
        show ip int.* 
        show controllers.*

To add an admin user it's even easier::

    admin = 
        adminuser

    [adminuser]
    host_allow =
        .* 
    device_permit = 
        .* 
    command_permit = 
        .*

So our final config is::

    [users]
    homer =
        fewcommands 
    admin = 
        adminuser 

    [fewcommands] 
    host_allow = 
        .* 
    device_permit = 
        .* 
    command_permit = 
        show users 
        show int.* 
        show ip int.* 
        show controllers.* 

    [adminuser] 
    host_allow = 
        .* 
    device_permit = 
        .* 
    command_permit = 
        .*

Wouldn’t it be nice to just do an adduser and be done without any config
modification? All we need is a default user. In our example above we would
change to this::

    [users] 
    default = 
        fewcommands 

Multiple Groups
---------------

Users may be in multiple groups.

http://tacacs.org/2009/05/08/granular-tacacs-control/

Configuration is fairly simple; as an example, let’s say I wanted to have user
Homer have full access to 192.168.1.1 and 10.1.1.0/24, but only do show
commands for everything else in 10.0.0.0/8.  For the heck of it, let’s say we
only want Homer to connect from 192.168.1.0/24, but never 192.168.1.4, which
host can only do the show commands.   The config file would simply be as
follows::

    [users]
    homer =
        simpsongroup
        televisiongroup

    [simpsongroup]
    host_deny =
        192.168.1.4
    host_allow =
        192.168.1.*
    device_permit =
        192.168.1.1
        10.1.1.* 
    command_permit = 
        .* 

    [televisiongroup] 
    host_allow = 
        192.168.1.* 
    device_permit = 
        10.* 
    command_permit = 
        show.*

Custom AV Pairs
---------------

One of the long promised features has finally been added, the ability to modify
av pairs. Let’s say you have a group which you simply want a user to have
enable access to. Simply add this to the group::

    av_pairs =
        priv-lvl=1

This assumes you have ``priv-lvl`` in your ``tac_plus.conf``. (Like examples previous)
Note, of course, you’ll also need to add a ``command_deny`` for enable or they’ll
just type "en" if they have an enable password. Now, this should open all sorts
of opportunities for wlc and roles. For reasons unknown, this does not work. If
you have a wlc that you can lab up & wireshark, please contact me on the
tac_plus listserv.

Users
=====

To define users you must specify a ``[users]`` section. A user must be assigned
to one or more groups, one per line::

    [users]
    homer =
        simpson_group
        television_group
    stimpy =
        television_group

Groups
======

Groups are assigned to users in the ``[users]`` section. Groups are defined in
brackets, and can have any name. Each group can have up to eight options as
defined below:

host_deny
    (Optional) Deny any user coming from this host.

host_allow
    (Mandatory if -i is specified) Allow users from this range.

device_deny
    (Optional) Deny any device with this IP.

device_permit
    (Mandatory if -d is specified) Allow this range.

command_deny
    (Optional) Deny these commands.

command_permit
    (Mandatory) Allow these commands.

av_pairs
    (Advanced - Use with care) List of av pairs to replace if found.

exit_val
    (Advanced - Use with care) hard code return value.

These options are parsed in order until a match is found. For login authentication,
the commands section is not parsed. If a match is not found, or a deny is
found, we move on to the next group. At the end, we have an implicit deny if no
groups match.

An simple example is as follows::

    [users]
    homer =
        simpson_group
        television_group
    stimpy =
        television_group

    [simpson_group]
    host_deny =
        1.1.1.1
        1.1.1.2
    host_allow =
        1.1.1.*
    device_permit =
        10.1.1.*
    command_permit =
        .*

    [television_group]
    host_allow =
        .*
    device_permit =
        .*
    command_permit =
        show.*

Example tac_plus config line::

    after authorization "/usr/bin/python /root/do_auth.pyc -i $address -fix_crs_bug -u $user -d $name -l /root/log.txt -f /root/do_auth.ini"

The following ``av_pair`` example will replace any ``priv-lvl`` with
``priv-lvl=1`` **only** if passed. Think of it as a find/replace function::

    av_pairs =
        priv-lvl=1

Brocade devices
---------------

Brocade has a vendor-specific attribute called ``brocade-privlvl``. It maps
``priv-lvl`` to ``brocade-privlvl``, but the result is an account that has some
privileges. Here is an example of how to map ``brocade-privlvl=5`` which has no
modification rights. Unfortunately, it also requires you to specify the IP
addresses of your
Brocade devices.

You could also put ``priv-lvl=15,brocade-privlvl=5`` or whatever your tac_plus
deamon is passing. As long as the A/V pairs match the results are the same. In
this example, we essentially replace the whole ``av_pair`` resulting in the user
having read-only access.

To work the Brocade-specific group must be above the other groups::

    [brocade_readonly]
    host_allow =
        .*
    device_permit =
        192.168.1.*
    command_permit =
        .*
    av_pairs =
        priv-lvl,brocade-privlvl=5

Cisco Nexus devices
-------------------

Due to a slight change in the Nexus, ``do_auth`` is able to identify a device as
a Cisco Nexus. In ``tac_plus.conf``, do the following::

    service = exec {
        priv-lvl = 1
        shell:roles=\"\\"network-operator\\""
        idletime = 3
        timeout = 15
    }
    after authorization "<do_auth yada yada>"

This configuration **WILL NOT** work without ``do_auth``, however, with
``do_auth`` the ``shell:roles`` A/V pair will only be sent to Nexus switches,
allowing your other devices to work correctly. These roles can also be modified
in a ``do_auth`` group, as below::

    av_pairs =
        priv-lvl=15
        shell:roles="network-admin"

NOTE: You **must** use double quotes to get ``tac_plus`` to correctly pass
"network-operator" in the ``service`` definition example above. Unless you are
explicitly modifying the attribute with ``do_auth`` in ``av_pairs``, it will be
adjusted for you!

HP Procurve devices
-------------------

This is the worst TACACS+ implementation I've ever seen and is the whole reason
for the ``exit_val`` group option. This is to work around the incorrect
implementation by HP. NOT MY FAULT!

Setting ``exit_val`` to ``0`` makes it work (the Procurve doesn't like
``AUTHOR_STATUS_PASS_REPL``). Unfortunately, this means you need to define your
Procurves in a distinct group and it must be the **very first**
group defined::

    [fix_procurve]
    host_allow =
        .*
    device_permit =
        192.168.1.*
    command_permit =
        .*
    exit_val =
        0

Known Issues
============

You must know your regular expressions. If you enter a bad expression, such as
"*." instead of ".*", Python's "re" module will freak out and not evaluate the
expression.

Caveats
=======

Ordering of groups is crucial. One group can not take away what another group
grants. If a match is not found, it will go on to the next group. If a deny is
matched, it will go on to the next group. The groups should go from
most-specific to least-specific.

For example::

    [users]
    homer =
        simpson_group
        television_group
    stimpy =
        television_group

    [simpson_group]
    host_deny =
        1.1.1.1
        1.1.1.2
    host_allow =
        1.1.1.*
    device_permit =
        10.1.1.*
    command_permit =
        .*

    [television_group]
    host_allow =
        .*
    device_permit =
        .*
    command_permit =
        show.*

In this example, if ``television_group`` was put before ``simpson_group``,
``simpson_group`` would never be called because ``televsion_group`` catches
everything in ``device_permit``.

License
=======

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License version 3 or any later version as
published by the Free Software Foundation, http://www.gnu.org/

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See LICENSE in the ``do_auth`` source distribution for more
details.
