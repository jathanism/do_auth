##########
To-Do List
##########

These are things that would be nice to do at some point. If you would like to
contribute, these would be great ways!

+ Possible web front end. Simple CGI shouldn't be too hard to write
+ More work on av_pairs. Need to sniff WLC traffic. If somebody has a WLC or
  other unknown network equipment, I require some t esting/sniffing done.
+ Write a better option parser to ignore options not sent (See CRS Bug).
+ Finish enumerating exceptions in config parsing. See: ``get_attribute()``
+ Convert av_pairs into a dict, not a list of strings. Write a function to
  convert back and forth. We also need to be able to account for optional pairs
  that may be sent by the device ('*' delimited). See:
  ``enumerate(return_pairs)``

