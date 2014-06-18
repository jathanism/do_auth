#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim: ts=4:sw=4:expandtab

"""
do_auth is a Python program to work as an authorization script for the
``tac_plus`` TACACS+ daemon to allow greater flexibility in TACACS+
authentication and authorization. For more information on tac_plus please see
http://shrubbery.net/tac_plus.

It allows a user to be part of many predefined groups that can allow different
access to different devices based on device IP address, usernmae, and source IP
address.

Do not play with do_auth until you have a firm grasp on ``tac_plus`` and the
syntax for ``do_auth.ini``!

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
"""

__author__ = 'Dan Schmidt, Jathan McCollum'
__maintainer__ = 'Dan Schmidt, Jathan McCollum'
__email__ = 'daniel.schmidt@wyo.gov'
__copyright__ = 'Dan Schmidt'
__license__ = 'GPL-3.0'
__version__ = '1.12'

try:
    import configparser
except ImportError:
    import ConfigParser as configparser
import logging
import optparse
import os
import sys
import re
from time import strftime
try:
    from os import getgrouplist as os_getgrouplist
    got_getgrouplist = True
    from pwd import getpwnam as pwd_getpwnam
    from grp import getgrgid as grp_getgrgid
except ImportError:
    got_getgrouplist = False
try:
    import netaddr
except ImportError:
    netaddr = None

# Defaults
CONFIG = 'do_auth.ini'
LOG_FILE = '/dev/null'
LOG_LEVEL = logging.INFO
LOG_FORMAT = "%(asctime)s [%(levelname)s]: %(message)s"
DEBUG = os.getenv('DEBUG', False)

# Placeholder for global logging object
log = None

# Only display debug messages if we've set the DEBUG env variable
if DEBUG:
    LOG_LEVEL = logging.DEBUG


# Functions
def _setup_logging(filename=LOG_FILE, format=LOG_FORMAT, level=LOG_LEVEL):
    """Returns a logging object. Intended to be called by main before any
    logging occurs."""
    logging.basicConfig(
        level=level,
        format=format,
        filename=filename
    )
    return logging.getLogger(__name__)

def dprint(*args, **kwargs):
    """Pretty-print the passed in values if global ``DEBUG`` is set."""
    if DEBUG:
        for a in args:
            print(a)
        for k,v in kwargs.items():
            print('%s = %s' % (k.upper(), v))
        if args and kwargs:
            print('')

def _product(*args, **kwds):
    """
    Adapted from itertools.product
    Ref: http://docs.python.org/2/library/itertools.html#itertools.product

    product('ABCD', 'xy') --> Ax Ay Bx By Cx Cy Dx Dy
    product(range(2), repeat=3) --> 000 001 010 011 100 101 110 111
    """
    pools = list(map(tuple, args)) * kwds.get('repeat', 1)
    result = [[]]
    for pool in pools:
        result = [x+[y] for x in result for y in pool]
    for prod in result:
        yield tuple(prod)
# itertools.product() wasn't added until Python 2.6, so this is so we can
# support Python 2.3+
try:
    from itertools import product
except ImportError:
    product = _product

def get_attribute(config, the_section, the_option, filename):
    """
    Fetches a section by name from the config and returns a list of attributes.

    I really don't want to deal with these exceptions more than once filename
    is only used in log statements.
    """
    log.debug('get_attributes(%s)' % locals())
    if not config.has_section(the_section):
        log.critical("Section '%s' does not exist in %s" % (the_section, filename))
        sys.exit(1)
    if not config.has_option(the_section, the_option):
        log.critical("Option '%s' does not exist in section %s in file %s" % (the_option, the_section, filename))
        sys.exit(1)

    # Should not have any exceptions - BUT, just in case
    try:
        attributes = config.get(the_section, the_option)
    except configparser.NoSectionError:
        log.critical("Section '%s' Doesn't Exist!" % (the_section))
        sys.exit(1)
    except configparser.DuplicateSectionError:
        log.critical("Duplicate section '%s'" % (the_section))
        sys.exit(1)
    except configparser.NoOptionError:
        log.critical("'%s' not found in section '%s'" % (the_option, the_section))
        sys.exit(1)

    # TODO (dan): Finish exceptions.
    except configparser.ParsingError:
        log.critical("Can't parse file '%s'! (You got me)" % (filename))
        sys.exit(1)

    # This is only executed if no exceptions were thrown
    else:
        log.debug('attributes BEFORE = %r' % attributes)
        attributes = attributes.splitlines()
        log.debug('attributes AFTER = %r' % attributes)

    # Strip empty lines
    new_attributes = [line for line in attributes if line != '']
    log.debug('new_attributes = %s' % new_attributes)
    return new_attributes

# Can't make it part of get_attribute... oh well...
# We need someway to check to see if a username exists with out exit(1)
def check_username(config, user_name):
    """
    Check if a username exists in the config. Pukes if the config doesn't
    even have a "users" section.
    """
    log.debug('check_username(%s)' % locals())
    if not config.has_section('users'):
        log.critical("users section doesn't exist!")
        sys.exit(1)

    return config.has_option('users', user_name)

def match_net(ip, net):
    """
    Return whether ``ip`` is in ``net``, except: log & exit(1)

    :param ip:
        A string representing an IP address

    :param net:
        A string reprsenting an IP network prefix (CIDR)
    """
    if netaddr is None:
        log.critical("Can't use / without the netaddr egg!")
        sys.exit(1)
    try:
        the_ip = netaddr.IPAddress(ip)
    except (netaddr.AddrFormatError, ValueError) as err:
        log.critical(err)
        sys.exit(1)
        # this really should not happen
    try:
        the_net = netaddr.IPNetwork(net)
    except (netaddr.AddrFormatError, ValueError) as err:
        log.critical(err)
        sys.exit(1)
    return the_ip in the_net

def match_it(the_section, the_option, match_item, config, filename):
    """
    If match item in our_list, true, else false

    Example:

    If deny section has a match for 10.1.1.1, return True, else False.
    If the section doesn't exist, we assume an implicit deny/false
    """
    if config.has_option(the_section,the_option):
        our_list = get_attribute(config, the_section, the_option, filename)
        for item in our_list:
            # Brute force assuming that this is a network block
            if item.find('/') > -1:
                if match_net(match_item, item):
                    return True
            # Or treat it as a normal pattern match
            elif re.match(item, match_item):
                return True
    return False

class DoAuthOptionParser(optparse.OptionParser):
    """
    A custom OptionParser to work with tac_plus post-authorization:

    - Always exit 1 on option errors vs. the default of 2.
    - Log output to the log file.
    """
    def error(self, msg):
        """Print a usage message using 'msg' to stderr and exit 1."""
        # Use the global log if it exists, else instantiate it.
        global log
        print(log)
        if log is None:
            log = _setup_logging(filename=self.values.log_file)
        log.critical(msg)

        self.print_usage(sys.stderr)
        self.exit(1, "%s: error: %s\n" % (self.get_prog_name(), msg))

def is_i_before_f(argv, parser):
    """
    Make sure -i always comes before -f. This is for the CRS workaround.

    :param argv:
        The argument list passed to the parser

    :param parser:
        An OptionParser object
    """
    # Get long/short option names for -f and -l
    fopt = parser.get_option('-f')
    flags = fopt._short_opts + fopt._long_opts
    iopt = parser.get_option('-i')
    ilags = iopt._short_opts + iopt._long_opts

    # Iterate over the flag names and check their position in argv and make
    # sure that -i always comes before -f.
    for f, i in product(flags, ilags):
        dprint('Checking %s against %s' % (f, i))
        if (f in argv and i in argv) and (argv.index(f) < argv.index(i)):
            parser.error("%s must be specified after %s in the argument list." % (f, i))

    return True

def parse_args(argv=None):
    """
    Self-explanatory.

    :param argv:
        The argument list passed to the parser
    """
    if argv is None:
        argv = sys.argv

    dprint(argv=argv)

    usage = 'usage: %prog -u <username> [-i <ip-addr>] [-d <device>] [-f <config-file>] [-l <log-file>] [-D|--debug]'
    desc = 'do_auth is a Python program to work as an authorization script for the ``tac_plus`` TACACS+ daemon to allow greater flexibility in TACACS+ authentication and authorization. For more information on tac_plus please see http://shrubbery.net/tac_plus.'
    ver ='%prog ' + __version__

    parser = DoAuthOptionParser(usage=usage, description=desc, version=ver)
    parser.add_option('-u', '--username', metavar='<username>',
                      help='(Mandatory) Username. [$user]')
    parser.add_option('-i', '--ip-addr', metavar='<ip-addr>',
                      help="""(Optional) IP address of user. If not specified, all host_ entries are ignored and can be omitted. [$address] (Note: If you use IOS-XR, you MUST add '-fix_crs_bug' after $address due to a bug in IOS-XR)""")
    parser.add_option('-d', '--device', metavar='<device>',
                      help="""(Optional) Device address. If not specified, all device_ entries are ignored and can be omitted. [$name]""")
    parser.add_option('-f', '--config-file', metavar='<config-file>',
                      default=CONFIG, help='Config filename. (default: %s)' %
                      CONFIG)
    parser.add_option('-l', '--log-file', metavar='<log-file>', default=LOG_FILE,
                      help='Log filename. (default: %s)' % LOG_FILE)
    parser.add_option('--docs', action='store_true', default=False,
                      help='Display usage docs and exit.')
    parser.add_option('-D', '--debug', action='store_true', default=False,
                      help="""Debug mode. Allows you to call the program without reading from stdin. Useful to test your configuration before going live. Sets a default command of "show users wides".""")

    opts, args = parser.parse_args()

    dprint('\nBefore:', opts=opts, args=args)

    if opts.docs:
        parser.exit(1, __doc__)

    # Make sure username is provided, log, and exit if isn't.
    if opts.username is None:
        msg = 'Username not provided. Argument -u/--username is required!'
        parser.error(msg)

    # Make sure -u, -i, -f are all provided, despite being labeled as optional?
    #if len(argv) < 7:
    #    print __doc__
    #    sys.exit(1)

    # Make sure that -i always comes before -f
    is_i_before_f(argv, parser)

    # Support legacy '-fix_crs_bug' option so it does not conflict with '-f' option
    if opts.config_file == 'ix_crs_bug' and opts.ip_addr:
        opts.ip_addr = '-fix_crs_bug'
        opts.config_file = CONFIG

    dprint('\nAfter:', opts=opts, args=args)

    return opts, args

def main():
    # Defaults
    global log # So we can use and modify the global logging object
    opts, _args = parse_args()

    filename = opts.config_file
    log_name = opts.log_file
    user_name = opts.username
    ip_addr = opts.ip_addr
    device = opts.device
    is_debug = opts.debug

    # DEBUG before we have a logging object.
    if is_debug:
        print('filename: %r' % filename)
        print('log_name: %r' % log_name)

    # Define our logging object
    log = _setup_logging(filename=log_name)

    # DEBUG! We at least got CALLED (and the logger works!)
    log.debug('Hello World!')

    # Read AV pairs
    av_pairs = []
    if not is_debug:
        for line in sys.stdin:
            av_pairs.append(line)

        log.debug('AV pairs: %r' % av_pairs)

    else:
        # Default Debug command is "show users wide"
        # Later versions will allow this to be set
        av_pairs.append("service=shell\n")
        av_pairs.append("cmd=show\n")
        av_pairs.append("cmd-arg=users\n")
        av_pairs.append("cmd-arg=wide\n")
        av_pairs.append("cmd-arg=<cr>\n")

    # DEBUG - print av_pairs
    for item in av_pairs:
        log.debug('AV item: %r' % item)

    # Function to make cmd's readable
    # Not very good, but will do for now
    # I don't use any other service other than shell to test!
    the_command = ""
    return_pairs = ""

    if not len(av_pairs) > 0:
        log.info('No av pairs!!')
        if device:
            log.info('Device:%s' % device)

        log.critical('Did you forget "default service = permit" in tac_plus.conf?')
        log.critical('Confused - exiting(1)!')
        sys.exit(1)

    if (av_pairs[0] == "service=shell\n"):
        # $**@ Nexus!
        if av_pairs[1] == ("cmd=\n"): # #&*@ Nexus!
            if len(av_pairs) > 2:
                # DEBUG
                log.debug('Nexus pairs found')
                return_pairs = av_pairs[2:] # strip the "cmd=" for consistency

        #
        # Commands - Concatenate to a readable command
        #
        elif av_pairs[1].startswith("cmd="):
            our_command = av_pairs[1].split("=")
            the_command = our_command[1].strip('\n')

            if len(av_pairs) > 2:
                i = 2
                our_command = av_pairs[i].split("=")

                while not (our_command[1] == "<cr>\n"):
                    the_command = the_command + " " + our_command[1].strip('\n')
                    i = i + 1
                    if i == len(av_pairs): # Firewalls don't give a <cr>!!
                        break

                    our_command = av_pairs[i].split("=")

            # DEBUG - We got the command
            log.debug('Got command: %r' % the_command)

        #
        # Login - Get av_pairs to pass back to tac_plus
        #

        # (Note: during debugging, you may see AV pairs whose separator
        # character is a * instead of a = sign, meaning that the value in a pair
        # is optional. An = sign indicates a mandatory value. A * denotes an
        # optional value).
        elif av_pairs[1].startswith("cmd*"):  # Anybody know why it's "cmd*"?
            if len(av_pairs) > 2:
                return_pairs = av_pairs[2:] # You MUST strip the "cmd*" av-pair

            # Definitely not a Nexus, so strip any Nexus pair
            for item in return_pairs:
                if item.startswith("shell:roles"):
                    return_pairs.remove(item)
    else:
         return_pairs = av_pairs

    config = configparser.SafeConfigParser()
    try:
        config.readfp(open(filename))
    except (IOError, configparser.ParsingError):
        log.critical("Can't open/parse config file: '%s'" % (filename))
        sys.exit(1)

    log.debug('Got config: %s' % config)

    the_section = "users"

    # If the user doesn't exist, just use the default settings
    # Kind of a hack, but it works because we only get_attribute on user_name once.
    # We have the : in there which we can use to split if required
    log.debug('Checking username: %s' % user_name)
    if not check_username(config, user_name):
        log.debug('username not found; searching for default')
        user_name = (user_name + ":(default)")
        groups = get_attribute(config, "users", "default", filename)
    else:
        log.debug('username found in config')
        groups = get_attribute(config, "users", user_name, filename)

    if '_nss' in groups and got_getgrouplist:
        log.debug('Got special group _nss and have getgrouplist, importing nss groups')
        try:
                pwd_user = pwd_getpwnam(user_name)
                os_group = os_getgrouplist(user_name, pwd_user[3])
                for gid in os_group:
                        try:
                                group = grp_getgrgid(gid)
                                groups.append(group[0])
                        except KeyError:
                                # group not found in nss
                                pass
        except KeyError:
                log.debug('User not found in NSS')
        log.debug('NSS Groups: %s' % (groups)) 

    log.debug('About to check groups')
    for this_group in groups:
        # Check $address
        if ip_addr:
            # 'host_deny' attribute
            if match_it(this_group, "host_deny", ip_addr, config, filename):
                if this_group == groups[-1]:
                    log.info("User '%s' denied from source '%s' in '%s'->'%s'"
                             % (user_name, ip_addr, this_group, "host_deny"))
                    sys.exit(1)
                else:
                    # HUM... afterthought.  We need it to continue if more groups exist
                    continue

            # 'host_allow' attribute
            if not match_it(this_group, "host_allow", ip_addr, config, filename):
                # Stupid IOS-XR bug in which $address is not passed by the
                # device. This workaround just gives us a value to check and is
                # ignored otherwise.
                if ip_addr == "-fix_crs_bug":
                    pass
                elif this_group == groups[-1]:
                    log.info("User '%s' not allowed from source '%s' in '%s'->'%s'"
                             % (user_name, ip_addr, this_group, "host_allow"))
                    sys.exit(1)
                else:
                    continue

        # Check $name
        if device:
            # 'device_deny' attribute
            if match_it(this_group, "device_deny", device, config, filename):
                if this_group == groups[-1]:
                    log.info("User '%s' denied access to device '%s' in '%s'->'%s'"
                             % (user_name, device, this_group, "device_deny"))
                    sys.exit(1)
                else:
                    continue

            # 'device_permit' attribute
            if not match_it(this_group, "device_permit", device, config, filename):
                if this_group == groups[-1]:
                    log.info("User '%s' not allowed access to device '%s' in '%s'->'%s'"
                             % (user_name, device, this_group, "device_permit"))
                    sys.exit(1)
                else:
                    continue

        # Attempt to modify return pairs
        want_tac_pairs = False
        if config.has_option(this_group, "av_pairs"):
            temp_av_pairs = get_attribute(config, this_group, "av_pairs", filename)

            for idx, item in enumerate(return_pairs):
                # TODO (jathan): Turn av_pairs into a dict, not a list of
                # strings... Write a function to convert back and forth. We
                # also need to be able to account for optional pairs that may
                # be sent by the device ('*' delimited)
                splt = item.split('=') 
                if len(splt) > 1:
                    # DEBUG
                    for thing in splt:
                        log.debug('Thing: %s' % thing)

                    # TODO (jathan): item, splt, item2?  Need better var names...
                    for item2 in temp_av_pairs:
                        item2 = item2.strip()
                        
                        # Pair replacing logic.
                        if item2.find(',') > -1: 
                            splt2 = item2.split(',')
                            if len(splt2) > 1:
                                #splt3 = splt2[0].split('=')
                                if splt[0].find(splt2[0]) > -1:
                                    want_tac_pairs = True
                                    return_pairs[idx] = ('%s' % splt2[1])
                        else:
                            splt2 = item2.split('=')
                            if len(splt2) > 1:
                                if splt[0] == splt2[0].strip(): # Strip needed?
                                    want_tac_pairs = True
                                    # DEBUG
                                    pair = '%s=%s' % (splt2[0].strip(), splt2[1].strip())
                                    log.debug("Replacing pairs %s" % pair)
                                    return_pairs[idx] = pair

        # Some devices implement TACACS+ so poorly that you shouldn't even TRY to
        # mess with them. Like Procurves.
        exit_val = '2' 
        if config.has_option(this_group, "exit_val"):
            return_val = get_attribute(config, this_group, "exit_val", filename)
            return_val = return_val[0]  # more than 1 = they're stupid
            exit_val = return_val.strip()

        # The previous 4 statements are to deny, it we passed them, proceed
        # If we are logging in, return pairs, if not, go no to check the command
        # Yes, simply printing them is how you return them

        # First, let's make sure we're doing 'service = shell'. If not, just
        # allow it. I currently have little knowledge of cmd's sent by other
        # services which is why this code is a little kludgy. 
        if return_pairs:
            splt = av_pairs[0].split('=') # Removed service in return_pairs

            if len(splt) > 1:
                if not splt[1].strip() == 'shell': 
                    log.info("User '%s' granted non-shell access to device '%s' in group '%s' from '%s'"
                             % (user_name, device, this_group, ip_addr))
                    return_pairs = av_pairs[2:] # Cut the first two?

                    # DEBUG
                    for item in return_pairs:
                        log.debug("Returning: %s" % item.strip())
                        print(item.strip('\n'))

                    if want_tac_pairs:
                        log.debug("Exiting status %s" % exit_val)
                        sys.exit(int(exit_val))
                    else:
                        log.debug("Exiting status 0")
                        sys.exit(0) # Don't even TRY to mess with the tac pairs

        # Proceed with shell stuff
        if not len(the_command) > 0:
            log.debug("not len(the_command) > 0")

            for item in return_pairs:
                # DEBUG
                log.debug("Returning: %s" % item.strip())
                print(item.strip('\n'))

            log.info("User '%s' granted access to device '%s' in group '%s' from '%s'"
                     % (user_name, device, this_group, ip_addr))
            # DEBUG
            log.debug("Exiting status %s" % exit_val)
            sys.exit(int(exit_val))

        # Check command
        else:
            if match_it(this_group, "command_deny", the_command, config, filename):

                if this_group == groups[-1]:
                    log.info("User '%s' denied command '%s' to device '%s' in '%s'->'%s'"
                             % (user_name, the_command, device, this_group, "command_deny"))
                    sys.exit(1)

                else:
                    continue

            elif match_it(this_group, "command_permit", the_command, config, filename):
                log.info("User '%s' allowed command '%s' to device '%s' in '%s'->'%s'"
                         % (user_name, the_command, device, this_group, "command_permit"))
                sys.exit(0)

            # Exit & log if last group
            else:

                if this_group == groups[-1]:
                    log.info("User '%s' not allowed command '%s' to device '%s' in any group"
                             % (user_name, the_command, device))

                    #Hum... This only works if it's the last group/only group.  
                    sys.exit(1)

                else:
                    continue

    # Implicit deny at the end. This should never happen, but in case it ever
    # does, it's not failing silently and you will know! :)
    log.info("User '%s' not allowed access to device '%s' from '%s' in any group"
             % (user_name, device, ip_addr))
    sys.exit(1)
            
if __name__ == "__main__":
    main()
