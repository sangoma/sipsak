## sipsak-ng

Work-in-progress improvements to sipsak. I'm calling it sipsak-ng
to differentiate from the original project which hasn't seen any
development afaik for a few years and I can't promise I haven't broken
anything.

So please note that I'm not the official upstream (if one still exists)
when filing bugs (but I'd still be more then happy to hear about them).

Currently working on porting sipsak to support ipv6. Potentially python
integration.

### Optional Requirements

- [GnuTLS][1] or [OpenSSL][2] installed on your system to use their MD5
  implementations instead of sipsak own version.
- [c-ares][3] or [ruli][4] installed on your system to get DNS SRV
  lookup support compiled into your sipsak binary.

Original README: [README](README)

  [1]: http://www.gnutls.org
  [2]: http://www.openssl.org/
  [3]: http://daniel.haxx.se/projects/c-ares/
  [4]: http://www.nongnu.org/ruli/
