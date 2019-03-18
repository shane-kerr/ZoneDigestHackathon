"""
The zonemd module adds support for the ZONEMD record, as documented
in:

  https://tools.ietf.org/html/draft-wessels-dns-zone-digest-06

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
import hashlib
import struct

import dns.rdata
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.zone

# The RTYPE for ZONEMD (use private-use number for now).
ZONEMD_RTYPE = 63

# Flag to output ZONEMD as an unknown type.
ZONEMD_AS_GENERIC = False


class ZONEMD(dns.rdata.Rdata):
    """
    ZONEMD provides a dnspython implementation of the ZONEMD RDATA
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
        @param algorithm: The digest algorithm to use.
        @type algorithm: int
        @param digest: The digest for the zone.
        @type digest: bytes
        """
        super().__init__(rdclass, ZONEMD_RTYPE)
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
        if ZONEMD_AS_GENERIC:
            rdata = self.to_digestable()
            text = (r"\# " + str(len(rdata)) + " " +
                    binascii.b2a_hex(rdata).decode())
        else:
            digest_hex = binascii.b2a_hex(self.digest).decode()
            text = (str(self.serial) + ' 0 ' +
                    str(self.algorithm) + ' ' + digest_hex)
        return text

    # pylint: disable=too-many-arguments
    @classmethod
    def from_text(cls, rdclass, rdtype, tok, origin=None, relativize=True):
        serial = tok.get_uint32()
        algorithm = tok.get_uint8()
        digest = binascii.a2b_hex(tok.get_string())
        return cls(rdclass, serial, algorithm, digest)

    def to_wire(self, file, compress=None, origin=None):
        file.write(self.to_digestable())

    # pylint: disable=too-many-arguments
    @classmethod
    def from_wire(cls, rdclass, rdtype, wire, current, rdlen, origin=None):
        serial, algorithm = struct.unpack('!IB', wire[:5])
        digest = wire[5:]
        return cls(rdclass, serial, algorithm, digest)


class ZoneDigestUnknownAlgorithm(Exception):
    """
    Exception raised if an unknown algorithm is used with ZONEMD
    functions.
    """
    pass


# Utility dictionary with the empty digests for each algorithm
_EMPTY_DIGEST_BY_ALGORITHM = {
    # SHA384
    1: b'\0' * 48
}


def add_zonemd(zone, zonemd_algorithm='sha384', zonemd_ttl=None):
    """
    Add a ZONEMD record to a zone. This also removes any existing
    ZONEMD records in the zone.

    The ZONEMD record will be at the zone apex, and have an all-zero
    digest.

    If the TTL is not specified, then the TTL of the SOA record is
    used.

    @var zone: The zone object to update.
    @type zone: dns.zone.Zone
    @var zonemd_algorithm: The name of the algorithm to use,
                      "sha384", or the number of the algorithm to use.
    @type zonemd_algorithm: str
    @var zonemd_ttl: The TTL to use for the ZONEMD record, or None to
                     get this from the zone SOA.
    @type zonemd_ttl: int
    @rtype: dns.rdataset.Rdataset
    @raises ZoneDigestUnknownAlgorithm: zonemd_algorithm is unknown

    Returns the placeholder ZONEMD record added, as a ZONEMD object.
    """
    if zonemd_algorithm in ('sha384', 1):
        algorithm = 1
    else:
        msg = 'Unknown digest ' + zonemd_algorithm
        raise ZoneDigestUnknownAlgorithm(msg)

    empty_digest = _EMPTY_DIGEST_BY_ALGORITHM[algorithm]

    # Remove any existing ZONEMD from the zone.
    # Also find the first name, which will be the zone name.
    for name in zone:
        zone.delete_rdataset(name, ZONEMD_RTYPE)
    zone_name = min(zone.keys())

    # Get the zone name.
    zone_name = min(zone.keys())

    # Get the SOA.
    soa_rdataset = zone.get_rdataset(zone_name, dns.rdatatype.SOA)
    soa = soa_rdataset.items[0]

    # Get the TTL to use for our placeholder ZONEMD.
    if zonemd_ttl is None:
        zonemd_ttl = soa_rdataset.ttl

    # Build placeholder ZONEMD and add to the zone.
    placeholder = dns.rdataset.Rdataset(dns.rdataclass.IN, ZONEMD_RTYPE)
    placeholder.update_ttl(zonemd_ttl)
    placeholder_rdata = ZONEMD(dns.rdataclass.IN, soa.serial,
                               algorithm, empty_digest)
    placeholder.add(placeholder_rdata)
    zone.replace_rdataset(zone_name, placeholder)

    return placeholder_rdata


def calculate_zonemd(zone, zonemd_algorithm='sha384'):
    """
    Calculate the digest of the zone.

    Returns the digest for the zone.

    @var zone: The zone object to digest.
    @type zone: dns.zone.Zone
    @var zonemd_algorithm: The name of the algorithm to use,
                  "sha384", or the number of the algorithm to use.
    @type zonemd_algorithm: str
    @raises ZoneDigestUnknownAlgorithm: zonemd_algorithm is unknown
    @rtype: bytes
    """
    if zonemd_algorithm in ('sha384', 1):
        hashing = hashlib.sha384()

    # Sort the names in the zone. This is needed for canonization.
    sorted_names = sorted(zone.keys())

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
                if rdataset.covers == ZONEMD_RTYPE:
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

    return hashing.digest()


def update_zonemd(zone, zonemd_algorithm='sha384'):
    """
    Calculate the digest of the zone and update the ZONEMD record's
    digest value with that.

    The ZONEMD record must already be present, for example having been
    added by the add_zonemd() function.

    This function does *not* change the serial value of the ZONEMD
    record.

    @var zone: The zone object to update.
    @type zone: dns.zone.Zone
    @var zonemd_algorithm: The name of the algorithm to use, "sha384".
    @type zonemd_algorithm: str
    @rtype: dns.rdataset.Rdataset
    @raises ZoneDigestUnknownAlgorithm: zonemd_algorithm is unknown

    Returns the ZONEMD record added, as a ZONEMD object.
    """
    zone_name = min(zone.keys())
    digest = calculate_zonemd(zone, zonemd_algorithm)
    zonemd = zone.find_rdataset(zone_name, ZONEMD_RTYPE).items[0]
    zonemd.digest = digest
    return zonemd


def validate_zonemd(zone):
    """
    Validate the digest of the zone.

    @var zone: The zone object to validate.
    @type zone: dns.zone.Zone
    @rtype: (bool, str) tuple

    Returns a tuple of (success code, error message). The success code
    is True if the digest is correct, and False otherwise. The error
    message is "" if there is no error, otherwise a description of the
    problem.
    """
    # Get the SOA and ZONEMD records for the zone.
    zone_name = min(zone.keys())
    soa_rdataset = zone.get_rdataset(zone_name, dns.rdatatype.SOA)
    soa = soa_rdataset.items[0]
    zonemd = zone.find_rdataset(zone_name, ZONEMD_RTYPE).items[0]

    # Verify that the SOA matches between the SOA and the ZONEMD.
    if soa.serial != zonemd.serial:
        err = ("SOA serial " + str(soa.serial) + " does not " +
               "match ZONEMD serial " + str(zonemd.serial))
        return False, err

    # Verify that we understand the digest algorithm.
    if zonemd.algorithm not in _EMPTY_DIGEST_BY_ALGORITHM:
        err = "Unknown digest algorithm " + str(zonemd.algorithm)
        return False, err

    # Put a placeholder in for the ZONEMD.
    original_digest = zonemd.digest
    zonemd.digest = _EMPTY_DIGEST_BY_ALGORITHM[zonemd.algorithm]

    # Calculate the digest and restore ZONEMD.
    digest = calculate_zonemd(zone, zonemd.algorithm)
    zonemd.digest = original_digest

    # Verify the digest in the zone matches the calculated value.
    if digest != zonemd.digest:
        zonemd_hex = binascii.b2a_hex(zonemd.digest).decode()
        digest_hex = binascii.b2a_hex(digest).decode()
        err = ("ZONEMD digest " + zonemd_hex + " does not " +
               "match calculated digest " + digest_hex)
        return False, err

    # Everything matches, enjoy your zone.
    return True, ""
  
