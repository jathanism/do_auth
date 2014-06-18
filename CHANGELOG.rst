#########
Changelog
#########

The change history, in order from newest to oldest.

1.12
====

+ Added optional support for netaddr for specifying network address blocks
  within do_auth.ini.

1.11
====

+ Python 3 compatibility.
+ NSS Group support. Add group ``_nss`` to your default user to get NSS groups
  for users (Python 3 required).

1.10
====

+ Bugfix in config parser to properly report when file can't be found.
+ Option-parsing converted to use Python's optparse module.
+ Usage docs cleaned up and only displayed when --docs flag is passed.
+ LICENSE (GPLv3) file added to project root.
+ Change history moved to CHANGELOG.rst.
+ Wanted/desired features added to TODO.rst.

1.93.2
======

+ Default log destination to ``/dev/null`` unless ``-l`` is passed.

1.93.1
======

+ Replace manual file logging w/ use of Python's ``logging`` module.

1.92
====

+ Catch exception on failed ``config.read()`` for backwards-compat. w/ Python 2.4.

1.91
====

+ Error out on no "default service = permit"
+ Option to hard code return value (for Procurve)

1.9
===

+ Better Nexus Support
+ Only send roles to Nexus
+ Better av_pair replacement

1.8
===

+ Nexus support (av_pair format different)

1.7
===

+ Fixed regression
+ Added support for replacing A/V pairs.

1.6
===

Added support for other services besides service=shell (ie - they work, by they
match on IP/Source only. If you have examples of pairs other than cmd to match
on, please bring them to my attention)

1.5
===

+ Fixed a mistake in the example. (Thanks to aojea.)

1.4
===

+ CRS doesn't send $address when in conf t. Added -fix_crs_bug as as
  simple/stupid workaround.

1.3
===

Needs a default user. If most of your users have the same access, and you have
a default access in tac_plus.conf, you need it here as well.

1.2
===

Did you know a firewall doesn't end it's commands with a <cr>?

1.1
===

Simple typo - a stray 's' botched a deny statement
