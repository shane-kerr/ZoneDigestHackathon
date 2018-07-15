"""
Take a zone file, compute the digest, and add the appropriate ZONEMD record.

Usage:
   python3 digestify.py [-c] [-a algorithm] [filename [...]]
"""
import argparse
import binascii
import sys

import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rdtypes.ANY
import dns.zone

import zonemd


def main():
    """
    Main function, typically invoked by the __name__ check.
    """
    description = 'Create and verify ZONEMD digest in zone files.'
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('--check', '-c', action='store_true',
                        help="check ZONEMD in zone file")
    parser.add_argument('--algorithm', '-a',
                        help="set algorithm to use (defaults to sha1)",
                        choices=('sha1', 'sha256', 'gost', 'sha384'),
                        default='sha1')
    parser.add_argument('--generic', '-g', action='store_true',
                        help=f"treat ZONEMD as an unknown type (RFC 3597)")
    parser.add_argument('--placeholder', '-p', action='store_true',
                        help='output a placeholder digest')
    parser.add_argument('filename', nargs='+')
    args = parser.parse_args()

    # pylint: disable=protected-access
    if args.generic:
        zonemd.ZONEMD_AS_GENERIC = True
    else:
        # Monkey-patch the dns.rdatatype module so we use the
        # presentation format.
        dns.rdatatype._by_value[zonemd.ZONEMD_RTYPE] = "ZONEMD"
        dns.rdatatype._by_text["ZONEMD"] = zonemd.ZONEMD_RTYPE
        dns.rdtypes.ANY.__all__.append("ZONEMD")
        mod_tuple = (dns.rdataclass.IN, zonemd.ZONEMD_RTYPE)
        dns.rdata._rdata_modules[mod_tuple] = zonemd

    exit_code = 0
    for filename in args.filename:
        zone = dns.zone.from_file(filename, check_origin=False,
                                  relativize=False, origin='.')
        if args.check:
            okay, err = zonemd.validate_zonemd(zone)
            if okay:
                print(f"{filename} is has a valid digest")
            else:
                print(f"{filename} does NOT have a valid digest: {err}")
                exit_code = 1
        else:
            zone_rr = zonemd.add_zonemd(zone, zonemd_algorithm=args.algorithm)
            if not args.placeholder:
                zone_rr = zonemd.update_zonemd(zone,
                                               zonemd_algorithm=args.algorithm)
            digest_hex = binascii.b2a_hex(zone_rr.digest).decode()
            zonemd_filename = filename + ".zonemd"
            with open(zonemd_filename, "w") as output_fp:
                zone.to_file(output_fp)
            print(f"Wrote ZONEMD digest {digest_hex} to {zonemd_filename}")

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
