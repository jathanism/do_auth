#!/usr/bin/env python
# -*- coding: utf-8 -*-
# vim: ts=4:sw=4:expandtab

"""
do_auth is a Python program to work as an post-authorization script for the
``tac_plus`` TACACS+ daemon to allow greater flexibility in TACACS+
authentication and authorization. For more information on tac_plus please see
http://shrubbery.net/tac_plus.

Please see the README.rst file bundled with this program for information on how
to use it.
"""

__author__ = 'Dan Schmidt, Jathan McCollum'
__maintainer__ = 'Jathan McCollum'
__email__ = 'jathan@gmail.com'
__copyright__ = 'Dan Schmidt'
__license__ = 'APL-2.0'
__version__ = '2.0'


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
    """
    Returns a logging object. Intended to be called by main before any
    logging occurs.

    :param filename:
        Log filename

    :param format:
        Log format

    :param level:
        Log level
    """
    logging.basicConfig(
        level=level,
        format=format,
        filename=filename
    )
    return logging.getLogger(__name__)


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
        result = [x + [y] for x in result for y in pool]
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

    I really don't want to deal with these exceptions more than once. filename
    is only used in log statements.
    """
    log.debug('get_attributes(%s)' % locals())
    if not config.has_section(the_section):
        msg = 'Section %r does not exist in %s' % (the_section, filename)
        log.critical(msg)
        sys.exit(1)
    if not config.has_option(the_section, the_option):
        msg = 'Option %r does not exist in section %s in %s' % \
            (the_option, the_section, filename)
        log.critical(msg)
        sys.exit(1)

    # Should not have any exceptions - BUT, just in case
    try:
        attributes = config.get(the_section, the_option)
    except configparser.NoSectionError:
        log.critical('Section %r is missing!' % (the_section,))
        sys.exit(1)
    except configparser.DuplicateSectionError:
        log.critical('Duplicate section %r' % (the_section,))
        sys.exit(1)
    except configparser.NoOptionError:
        msg = '%r not found in section %r' % (the_option, the_section)
        log.critical(msg)
        sys.exit(1)

    # TODO (dan): Finish exceptions.
    except configparser.ParsingError:
        log.critical("Can't parse file '%s'! (You got me)" % (filename,))
        sys.exit(1)

    # This is only executed if no exceptions were thrown
    else:
        log.debug('attributes BEFORE = %r' % (attributes,))
        attributes = attributes.splitlines()
        log.debug('attributes AFTER = %r' % (attributes,))

    # Strip empty lines
    new_attributes = [line for line in attributes if line != '']
    log.debug('new_attributes = %s' % new_attributes)
    return new_attributes


# Can't make it part of get_attribute... oh well...
# We need someway to check to see if a username exists with out exit(1)
def check_username(config, username):
    """
    Check if a username exists in the config. Pukes if the config doesn't
    even have a "users" section.
    """
    log.debug('check_username(%s)' % locals())
    if not config.has_section('users'):
        log.critical("users section doesn't exist!")
        sys.exit(1)

    return config.has_option('users', username)


def match_it(the_section, the_option, match_item, config, filename):
    """
    If match item in our_list, true, else false

    Example:

    If deny section has a match for 10.1.1.1, return True, else False.
    If the section doesn't exist, we assume an implicit deny/false
    """
    if config.has_option(the_section, the_option):
        our_list = get_attribute(config, the_section, the_option, filename)
        for item in our_list:
            if re.match(item, match_item):
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
        if (f in argv and i in argv) and (argv.index(f) < argv.index(i)):
            msg = 'Argument %s must be specified after %s.' % (f, i)
            parser.error(msg)
    return True


def parse_args(argv=None):
    """
    Self-explanatory.

    :param argv:
        The argument list passed to the parser
    """
    if argv is None:
        argv = sys.argv

    usage = (
        'usage: %prog -u <username> [-i <ip-addr>] [-d <device>] '
        '[-f <config-file>] [-l <log-file>] [-D|--debug]'
    )

    ver = '%prog ' + __version__

    parser = DoAuthOptionParser(usage=usage, description=__doc__, version=ver)
    parser.add_option(
        '-D',
        '--debug',
        action='store_true',
        default=False,
        help=(
            'Debug mode. Allows you to call the program without reading from '
            'stdin. Useful to test your configuration before going live. Sets '
            'a default command of "show users wide".'
        )
    )
    parser.add_option(
        '-d',
        '--device',
        metavar='<device>',
        help=(
            '(Optional) Device address. If not specified, all device_* '
            'entries are ignored and can be omitted. [$name]'
        )
    )
    parser.add_option(
        '--docs',
        action='store_true',
        default=False,
        help='Display usage docs and exit.'
    )
    parser.add_option(
        '-f',
        '--config-file',
        metavar='<config-file>',
        default=CONFIG,
        help='Config filename. (default: %s)' % CONFIG
    )
    parser.add_option(
        '-i',
        '--ip-addr',
        metavar='<ip-addr>',
        help=(
            'Optional) IP address of user. If not specified, all host_ '
            'entries are ignored and can be omitted. [$address] (Note: If '
            'you use IOS-XR, you MUST add "-fix_crs_bug" after $address due '
            'to a bug in IOS-XR).'
        )
    )
    parser.add_option(
        '-l',
        '--log-file',
        metavar='<log-file>',
        default=LOG_FILE,
        help='Log filename. (default: %s)' % LOG_FILE
    )
    parser.add_option(
        '-u',
        '--username',
        metavar='<username>',
        help='(Mandatory) Username. [$user]'
    )

    opts, args = parser.parse_args()

    if opts.docs:
        parser.exit(1, __doc__)

    # Make sure username is provided, log, and exit if isn't.
    if opts.username is None:
        msg = 'Username not provided. Argument -u/--username is required!'
        parser.error(msg)

    # Make sure -u, -i, -f are all provided, despite being labeled as optional?
    # if len(argv) < 7:
    #     print __doc__
    #     sys.exit(1)

    # Make sure that -i always comes before -f
    is_i_before_f(argv, parser)

    # Support legacy '-fix_crs_bug' option so it does not conflict with '-f'
    # option
    if opts.config_file == 'ix_crs_bug' and opts.ip_addr:
        opts.ip_addr = '-fix_crs_bug'
        opts.config_file = CONFIG

    return opts, args


# Default debug command is "show users wide". Later versions will allow this to
# be set.
DEBUG_AV_PAIRS = [
    'service=shell',
    'cmd=show',
    'cmd-arg=users',
    'cmd-arg=wide',
    'cmd-arg=<cr>',
]


def get_av_pairs(is_debug=False):
    """Read AV pairs from stdin."""
    if is_debug:
        return DEBUG_AV_PAIRS

    log.debug('get_av_pairs()')
    log.debug('=' * 40)
    av_pairs = []
    for line in sys.stdin:
        line = line.strip()
        log.debug('Incoming AV pair: %s' % line)
        av_pairs.append(line)

    # log.debug('AV pairs: %r' % (av_pairs,))
    log.debug('=' * 40)
    log.debug(' ')
    return av_pairs


def validate_av_pairs(av_pairs):
    # Make sure that we have AV pairs or exit(1)
    if not av_pairs:
        log.info('No AV pairs!')
        msg = 'Did you forget "default service = permit" in tac_plus.conf?'
        log.critical(msg)
        log.critical('Confused: Exiting(1)')
        sys.exit(1)


def read_config(filename):
    config = configparser.SafeConfigParser()
    try:
        config.readfp(open(filename))
    except (IOError, configparser.ParsingError):
        log.critical('Could not open/parse config file: %r' % (filename,))
        sys.exit(1)

    log.debug('Got config: %s' % config)
    return config


def main():
    # Defaults
    global log  # So we can use and modify the global logging object
    opts, _args = parse_args()

    filename = opts.config_file
    log_name = opts.log_file
    username = opts.username
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
    #log.info('do_auth started with args %s' % sys.argv[1:])
    log.debug('do_auth started with args %s' % sys.argv[1:])

    # First and foremost, can we even read the config?
    config = read_config(filename)

    # Read incoming AV Pairs from stdin
    if device:
        log.info('Device: %s' % device)
    av_pairs = get_av_pairs(is_debug)

    # Make sure that we have AV pairs
    validate_av_pairs(av_pairs)

    # Function to make cmd's readable
    # Not very good, but will do for now
    # I don't use any other service other than shell to test!
    the_command = ""
    return_pairs = ""

    #
    # Commands
    #
    # Process commands
    log.debug('validate_commands()')
    log.debug('=' * 40)
    if (av_pairs[0] == "service=shell"):
        # $**@ Nexus!
        if av_pairs[1] == ("cmd=\n"):  # #&*@ Nexus!
            if len(av_pairs) > 2:
                # DEBUG
                log.debug('Nexus pairs found')
                return_pairs = av_pairs[2:]  # Strip the "cmd=" for consistency

        #
        # Commands - Concatenate to a readable command
        #
        elif av_pairs[1].startswith("cmd="):
            our_command = av_pairs[1].split("=")
            the_command = our_command[1].strip('\n')

            if len(av_pairs) > 2:
                i = 2
                our_command = av_pairs[i].split("=")

                while our_command[1] != "<cr>\n":
                    the_command = '%s %s' % (the_command,
                                             our_command[1].strip('\n'))
                    i += 1
                    if i == len(av_pairs):  # Firewalls don't give a <cr>!!
                        break

                    our_command = av_pairs[i].split("=")

            # DEBUG - We got the command
            log.debug('Got command: %r' % the_command)

        #
        # Login - Get av_pairs to pass back to tac_plus
        #

        # (Note: during debugging, you may see AV pairs whose separator
        # character is a * instead of a = sign, meaning that the value in a
        # pair is optional. An = sign indicates a mandatory value. A * denotes
        # an optional value).
        elif av_pairs[1].startswith("cmd*"):  # Anybody know why it's "cmd*"?
            if len(av_pairs) > 2:
                return_pairs = av_pairs[2:]  # You MUST strip "cmd*" av-pair

            # Definitely not a Nexus, so strip any Nexus pair
            for item in return_pairs:
                if item.startswith("shell:roles"):
                    return_pairs.remove(item)
    else:
        return_pairs = av_pairs
    log.debug('=' * 40)
    log.debug(' ')

    #
    # Users
    #
    # def validate_user(username):

    # If the user doesn't exist, just use the default settings
    # Kind of a hack, but it works because we only get_attribute on username
    # once. We have the ':' in there which we can use to split if required
    log.debug('validate_user()')
    log.debug('=' * 40)
    log.debug('Checking username: %s' % username)
    if not check_username(config, username):
        log.debug('username not found; searching for default')
        username = (username + ":(default)")
        groups = get_attribute(config, "users", "default", filename)
    else:
        log.debug('username found in config')
        groups = get_attribute(config, "users", username, filename)

    if '_nss' in groups and got_getgrouplist:
        msg = 'Got group _nss and have getgrouplist; importing nss groups'
        log.debug(msg)
        try:
            pwd_user = pwd_getpwnam(username)
            os_group = os_getgrouplist(username, pwd_user[3])
            for gid in os_group:
                try:
                    group = grp_getgrgid(gid)
                    groups.append(group[0])
                except KeyError:
                    # group not found in nss
                    pass
        except KeyError:
            log.debug('User not found in NSS')
        log.debug('NSS Groups: %s' % (groups,))
    log.debug('=' * 40)
    log.debug(' ')

    #
    # Groups
    #
    log.debug('validate_groups()')
    log.debug('=' * 40)
    log.debug('About to check groups')
    for this_group in groups:

        # Check $address
        if ip_addr:
            # 'host_deny' attribute
            host_deny = match_it(
                this_group, 'host_deny', ip_addr, config, filename)
            if host_deny:
                if this_group == groups[-1]:
                    log.error('%r denied from source %r in %r:%r' % (
                        username, ip_addr, this_group, 'host_deny'))
                    sys.exit(1)
                else:
                    # We need it to continue if more groups exist
                    continue

            # 'host_allow' attribute
            host_allow = match_it(
                this_group, 'host_allow', ip_addr, config, filename)
            if not host_allow:
                # Stupid IOS-XR bug in which $address is not passed by the
                # device. This workaround just gives us a value to check and is
                # ignored otherwise.
                if ip_addr == "-fix_crs_bug":
                    pass
                elif this_group == groups[-1]:
                    msg = '%r not allowed from source %r in %r:%r' % (
                        username, ip_addr, this_group, 'host_allow')
                    log.error(msg)
                    sys.exit(1)
                else:
                    continue

        # Check $name
        if device:
            # 'device_deny' attribute
            device_deny = match_it(
                this_group, 'device_deny', device, config, filename)
            if device_deny:
                if this_group == groups[-1]:
                    msg = '%r denied access to device %r in %r:%r' % (
                        username, device, this_group, 'device_deny')
                    log.error(msg)
                    sys.exit(1)
                else:
                    continue

            # 'device_permit' attribute
            device_permit = match_it(
                this_group, 'device_permit', device, config, filename)
            if not device_permit:
                if this_group == groups[-1]:
                    msg = '%r denied access to device %r in %r:%r' % (
                        username, device, this_group, "device_permit")
                    log.error(msg)
                    sys.exit(1)
                else:
                    continue

        # Attempt to modify return pairs
        want_tac_pairs = False
        if config.has_option(this_group, 'av_pairs'):
            temp_av_pairs = get_attribute(
                config, this_group, 'av_pairs', filename)

            for idx, item in enumerate(return_pairs):
                # TODO (jathan): Turn av_pairs into a dict, not a list of
                # strings... Write a function to convert back and forth. We
                # also need to be able to account for optional pairs that may
                # be sent by the device ('*' delimited)
                splt = item.split('=')
                log.debug('SPLT = %s' % (splt,))
                if len(splt) > 1:
                    # DEBUG
                    for thing in splt:
                        log.debug('Thing: %s' % thing)

                    # TODO (jathan): item, splt, item2?  Need better var
                    # names...
                    log.debug('TEMP AV_PAIRS = %s' % temp_av_pairs)
                    log.debug('RETURN_PAIRS  = %s' % return_pairs)
                    for item2 in temp_av_pairs:
                        item2 = item2.strip()

                        # Pair replacing logic.
                        """
                        if item2.find(',') > -1:
                            log.debug('HAS COMMA = %s' % item2)
                            splt2 = item2.split(',')
                            log.debug('HAS SPLT2 = %s' % splt2)
                            if len(splt2) > 1:
                                #splt3 = splt2[0].split('=')
                                if splt[0].find(splt2[0]) > -1:
                                    want_tac_pairs = True
                                    return_pairs[idx] = ('%s' % splt2[1])
                                    log.debug('HAS COMMA VALUE = %s' % (
                                        return_pairs[idx],))
                        else:
                            splt2 = item2.split('=')
                            if len(splt2) > 1:
                                if splt[0] == splt2[0].strip(): # Strip needed?
                                    want_tac_pairs = True
                                    # DEBUG
                                    pair = '%s=%s' % (splt2[0].strip(),
                                                      splt2[1].strip())
                                    log.debug("Replacing pairs %s" % pair)
                                    return_pairs[idx] = pair
                        """
                        splt2 = item2.split('=')
                        if len(splt2) > 1:
                            if splt[0] == splt2[0].strip():
                                want_tac_pairs = True
                                # DEBUG
                                pair = '%s=%s' % (splt2[0].strip(),
                                                  splt2[1].strip())
                                log.debug('Replacing pairs %r' % pair)
                                return_pairs[idx] = pair

        # Some devices implement TACACS+ so poorly that you shouldn't even TRY
        # to mess with them. Like Procurves.
        exit_val = '2'
        if config.has_option(this_group, 'exit_val'):
            return_val = get_attribute(
                config, this_group, 'exit_val', filename)
            return_val = return_val[0]  # more than 1 = they're stupid
            exit_val = return_val.strip()

        # The previous 4 statements are to deny, it we passed them, proceed
        # If we are logging in, return pairs, if not, go no to check the
        # command. Yes, simply printing them is how you return them.

        # First, let's make sure we're doing 'service = shell'. If not, just
        # allow it. I currently have little knowledge of cmd's sent by other
        # services which is why this code is a little kludgy.
        if return_pairs:
            splt = av_pairs[0].split('=')  # Removed service in return_pairs

            services = ('shell', 'junos-exec')
            shell_info = splt[1].strip()
            log.info('Got shell? %s' % shell_info)
            if len(splt) > 1:
                log.info('Got shell? %s' % shell_info)
                #if not splt[1].strip() == 'shell':
                if shell_info not in services:
                    msg = (
                        '%r granted non-shell access to device %r in '
                        'group %r from %r'
                    ) % (username, device, this_group, ip_addr)
                    log.info(msg)
                    # return_pairs = av_pairs[2:]  # Cut the first two?
                    return_pairs = av_pairs[1:]  # Cut the first two?

                    # DEBUG
                    for item in return_pairs:
                        log.debug("Returning: %s" % item.strip())
                        print(item.strip('\n'))

                    if want_tac_pairs:
                        log.debug("Exiting status %s" % exit_val)
                        sys.exit(int(exit_val))
                    else:
                        log.debug("Exiting status 0")
                        sys.exit(0)  # Don't even TRY to mess with the AV pairs

        # Proceed with shell stuff
        log.info('command = %s' % the_command)
        if not len(the_command) > 0:
            log.debug("not len(the_command) > 0")

            for item in return_pairs:
                log.debug("Returning: %s" % item.strip())
                print(item.strip('\n'))

            msg = '%r granted access to device %r in group %r from %r' % (
                username, device, this_group, ip_addr)
            log.info(msg)
            log.debug('Exiting status %s' % exit_val)
            sys.exit(int(exit_val))

        # Check command
        else:
            command_deny = match_it(
                this_group, 'command_deny', the_command, config, filename)
            command_permit = match_it(
                this_group, 'command_permit', the_command, config, filename)
            if command_deny:
                if this_group == groups[-1]:
                    msg = '%r denied command %r to device %r in %r:%r' % (
                        username, the_command, device, this_group,
                        'command_deny')
                    log.info(msg)
                    sys.exit(1)
                else:
                    continue
            elif command_permit:
                msg = '%r allowed command %r to device %r in %r:%r' % (
                    username, the_command, device, this_group,
                    'command_permit')
                log.info(msg)
                sys.exit(0)

            # Exit & log if last group
            else:
                if this_group == groups[-1]:
                    msg = '%r denied command %r to device %r in any group' % (
                        username, the_command, device)
                    log.info(msg)

                    # Hum... This only works if it's the last group/only group.
                    sys.exit(1)
                else:
                    continue
    log.debug('=' * 40)

    # Implicit deny at the end. This should never happen, but in case it ever
    # does, it's not failing silently and you will know! :)
    log.info('%r not allowed access to device %r from %r in any group'
             % (username, device, ip_addr))
    sys.exit(1)


if __name__ == "__main__":
    main()
