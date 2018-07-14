"""
Take a zone file, compute the digest, and add the appropriate ZONEMD record.

Usage:
   python3 digestify.py [filename [...]]
"""
import sys

import dns.rdatatype
import dns.zone

import zonemd

# Monkey-patch the dns.rdatatype module so we print ZONEMD when we dump
# the file.
# pylint: disable=protected-access
dns.rdatatype._by_value[zonemd.ZONEMD] = "ZONEMD"


def main():
    """
    Main function, typically invoked by the __name__ check.
    """
    for filename in sys.argv[1:]:
        zone = dns.zone.from_file(filename, check_origin=False,
                                  relativize=False)
        zonemd.add_zonemd(zone)
        zonemd.update_zonemd(zone)
        zone.to_file(sys.stdout)


if __name__ == "__main__":
    main()
