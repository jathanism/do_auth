==========
do_auth.py
==========

Versions
========

1.8
---

+ Nexus support (tac_pair format different)


1.7
---

http://www.pastie.org/2499657

1.2
---

http://pastie.org/506002


Usage
=====

Easier TACACS Configurations with do_auth

http://tacacs.org/2009/09/26/easy-tacacs-control-with-do_auth/

Example line to put in tacplus user or group::

    after authorization “/root/doauth.py -i $address -u $user -d $name -l /root/log.txt -f /root/do_auth.ini” (that’s all ONE line)

tac_plus.conf
-------------

First, a starting tacplus.conf file. Which, we’ll never have to edit again::



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

Now, we add homer and give him access to some show commands. Fist, we do a
adduser homer on linux to add the user. This way, when the user wants to change
is password, he can any time he wants to with passwd. Next, we edit the
do_auth.ini file::

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

This assumes you have priv-lvl in your tac_plus.conf. (Like examples previous)
Note, of course, you’ll also need to add a command_deny for enable or they’ll
just type ‘en’ if they have an enable password. Now, this should open all sorts
of opportunities for wlc and roles. For reasons unknown, this does not work. If
you have a wlc that you can lab up & wireshark, please contact me on the
tac_plus listserv.