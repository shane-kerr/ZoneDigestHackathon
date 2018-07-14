"""
The zonemd module adds support for the ZONEMD record, as documented
in:

  https://tools.ietf.org/html/draft-wessels-dns-zone-digest-02

The idea is to provide a zone digest, which is a record that basically
creates a checksum of the zone file.

Since we need to be able to sign the ZONEMD record with DNSSEC, but
also need to calculate the digest with the signature, we provide
functions to support a two-step process:

1. Invoke add_zonemd() on the zone, which removes and ZONEMD records
   in the zone and adds a placeholder ZONEMD record. The zone can be
   signed if desired.

2. Invoke the update_zonemd() on the zone, which calculates the digest
   and updates the placeholder ZONEMD record. The resulting ZONEMD
   record can be signed if desired.
"""
import binascii
import hmac
import struct

import dns.rdata
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.zone
import pygost.gost341194

# The RTYPE for ZONEMD (use private-use number for now).
ZONEMD = 65432


class ZoneMD(dns.rdata.Rdata):
    """
    ZoneMD provides a dnspython implementation of the ZONEMD RDATA
    class.
    """

    def __init__(self, rdclass, serial, algorithm, digest):
        """
        Initialize the ZONEMD RDATA.
        @param rdlass: The RDATA class.
        @type rdclass: int
        @param serial: The ZONEMD serial number for the RDATA (which should be
                       the same as the SOA serial number).
        @type serial: int
        @param algorithm: The digest algorithm to use, either "sha1",
                          "sha256", "gost", or "sha384".
        @type algorithm: str
        """
        super().__init__(rdclass, ZONEMD)
        self.serial = serial
        self.algorithm = algorithm
        self.digest = digest

    def to_digestable(self, origin=None):
        """
        Convert to a format suitable for digesting in hashes.
        """
        return struct.pack('!IB', self.serial, self.algorithm) + self.digest

    def to_text(self, origin=None, relativize=True, **kw):
        """
        Convert to text format. This is also referred to as the
        presentation format.
        """
        digest_hex = binascii.b2a_hex(self.digest).decode()
        return f'{self.serial} {self.algorithm} {digest_hex}'


class ZoneDigestUnknownAlgorithm(Exception):
    """
    Exception raised if an unknown algorithm is used with ZONEMD
    functions.
    """
    pass


def add_zonemd(zone, zonemd_algorithm='sha1', zonemd_ttl=None):
    """
    Add a ZONEMD record to a zone. This also removes any existing
    ZONEMD records in the zone.

    The ZONEMD record will be at the zone apex, and have an all-zero
    digest.

    If the TTL is not specified, then the TTL of the SOA record is
    used.

    @var zone: The zone object to update.
    @type zone: dns.zone.Zone
    @var zonemd_algorithm: The name of the algorithm to use, either "sha1",
                          "sha256", "gost", or "sha384".
    @type zonemd_algorithm: str
    @var zonemd_ttl: The TTL to use for the ZONEMD record, or None to
                     get this from the zone SOA.
    @type zonemd_ttl: int
    """
    if zonemd_algorithm == 'sha1':
        algorithm = 1
        empty_digest = b'\0' * 20
    elif zonemd_algorithm == 'sha256':
        algorithm = 2
        empty_digest = b'\0' * 32
    elif zonemd_algorithm == 'gost':
        algorithm = 3
        empty_digest = b'\0' * 32
    elif zonemd_algorithm == 'sha384':
        algorithm = 4
        empty_digest = b'\0' * 48
    else:
        msg = f'Unknown digest {zonemd_algorithm}'
        raise ZoneDigestUnknownAlgorithm(msg)

    # Remove any existing ZONEMD from the zone.
    # Also find the first name, which will be the zone name.
    for name in zone:
        zone.delete_rdataset(name, ZONEMD)
    zone_name = min(zone.keys())

    # Sort the names in the zone. This is needed for canonization,
    # and also has the benefit of putting the SOA name as the first
    # name.
    sorted_names = sorted(zone.keys())
    zone_name = sorted_names[0]

    # Get the SOA
    soa_rdataset = zone.get_rdataset(zone_name, dns.rdatatype.SOA)
    soa = soa_rdataset.items[0]

    # Get the TTL to use for our placeholder ZONEMD.
    if zonemd_ttl is None:
        zonemd_ttl = soa_rdataset.ttl

    # Build placeholder ZONEMD and add to the zone.
    placeholder = dns.rdataset.Rdataset(dns.rdataclass.IN, ZONEMD)
    placeholder.update_ttl(zonemd_ttl)
    placeholder_rdata = ZoneMD(dns.rdataclass.IN, soa.serial,
                               algorithm, empty_digest)
    placeholder.add(placeholder_rdata)
    zone.replace_rdataset(zone_name, placeholder)


def update_zonemd(zone, zonemd_algorithm='sha1'):
    """
    Calculate the digest of the zone and update the ZONEMD record's
    digest value with that.

    The ZONEMD record must already be present, for example having been
    added by the add_zonemd() function.

    This function does *not* change the serial value of the ZONEMD
    record.

    @var zone: The zone object to update.
    @type zone: dns.zone.Zone
    @var zonemd_algorithm: The name of the algorithm to use, either "sha1",
                          "sha256", "gost", or "sha384".
    @type zonemd_algorithm: str
    """
    if zonemd_algorithm == 'sha1':
        hashing = hmac.new(b'', digestmod='sha1')
    elif zonemd_algorithm == 'sha256':
        hashing = hmac.new(b'', digestmod='sha256')
    elif zonemd_algorithm == 'gost':
        # pylint: disable=no-member
        hashing = hmac.new(b'', digestmod=pygost.gost331194)
    elif zonemd_algorithm == 'sha384':
        hashing = hmac.new(b'', digestmod='sha384')

    # Sort the names in the zone. This is needed for canonization,
    # and also has the benefit of putting the SOA name as the first
    # name.
    sorted_names = sorted(zone.keys())
    zone_name = sorted_names[0]

    # Iterate across each name in canonical order.
    for name in sorted_names:
        # Save the wire format of the name for later use.
        wire_name = name.canonicalize().to_wire()

        # Iterate across each RRSET in canonical order.
        sorted_rdatasets = sorted(zone.find_node(name).rdatasets,
                                  key=lambda rdataset: rdataset.rdtype)
        for rdataset in sorted_rdatasets:
            # Skip the RRSIG for ZONEMD.
            if rdataset.rdtype == dns.rdatatype.RRSIG:
                if rdataset.covers == ZONEMD:
                    print("DEBUG - skipping RRSIG")
                    continue

            # Save the wire format of the type, class, and TTL for later use.
            wire_set = struct.pack('!HHI', rdataset.rdtype, rdataset.rdclass,
                                   rdataset.ttl)
            # Extract the wire format of the RDATA and sort them.
            wire_rdatas = []
            for rdata in rdataset:
                wire_rdatas.append(rdata.to_digestable())
            wire_rdatas.sort()

            # Finally update the digest for each RR.
            for wire_rr in wire_rdatas:
                hashing.update(wire_name)
                hashing.update(wire_set)
                hashing.update(struct.pack('!H', len(wire_rr)))
                hashing.update(wire_rr)

    # After we are done, change the digest value in the ZONEMD record.
    zonemd = zone.find_rdataset(zone_name, ZONEMD)
    zonemd.items[0].digest = hashing.digest()
