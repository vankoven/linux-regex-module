# eBPF REGEX helper

The `linux-rex` is a loadable kernel module providing eBPF helper functions
for processing regular expressions. It uses Hyperscan as a runtime and
configuration tool.

License: GPLv2

## Documentation

Refer to [the project wiki pages](https://github.com/G-Core/linux-regex-module/wiki)
to find all the necessary documentation.

## Talks and videos

The `linux-rex` module [was introduced on the Netdev 0x16, Technical Conference
on Linux Networking](https://netdevconf.info/0x16/session.html?When-regular-expressions-meet-XDP#)

## Hyperscan

Hyperscan is a high-performance multiple regex matching library. It follows the
regular expression syntax of the commonly-used libpcre library, but is a
standalone library with its own C API.

Hyperscan uses hybrid automata techniques to allow simultaneous matching of
large numbers (up to tens of thousands) of regular expressions and for the
matching of regular expressions across streams of data.

Hyperscan is typically used in a DPI library stack.

More information can be found at
[Hyperscan project repo](https://github.com/intel/hyperscan)

License: BSD
