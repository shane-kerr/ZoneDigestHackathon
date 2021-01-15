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

# The RTYPE for ZONEMD.
ZONEMD_RTYPE = 63

# Digest types for ZONEMD.
ZONEMD_DIGEST_SHA384 = 1
ZONEMD_DIGEST_SHA512 = 2

# Flag to output ZONEMD as an unknown type.
ZONEMD_AS_GENERIC = False


class ZONEMD(dns.rdata.Rdata):
    """
    ZONEMD provides a dnspython implementation of the ZONEMD RDATA
    class.
    """

    # pylint: disable=too-many-arguments
    def __init__(self, rdclass, serial, scheme, algorithm, digest):
        """
        Initialize the ZONEMD RDATA.
        @param rdlass: The RDATA class.
        @type rdclass: int
        @param serial: The ZONEMD serial number for the RDATA (which should be
                       the same as the SOA serial number).
        @type serial: int
        @param scheme: ZONEMD collation scheme
        @type scheme: int
        @param algorithm: The digest algorithm to use.
        @type algorithm: int
        @param digest: The digest for the zone.
        @type digest: bytes
        """
        super().__init__(rdclass, ZONEMD_RTYPE)
        self.serial = serial
        self.scheme = scheme
        self.algorithm = algorithm
        self.digest = digest

    def to_digestable(self, origin=None):
        """
        Convert to a format suitable for digesting in hashes.
        """
        return struct.pack('!IBB', self.serial,
                           self.scheme, self.algorithm) + self.digest

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
            text = (str(self.serial) + ' ' +
                    str(self.scheme) + ' ' +
                    str(self.algorithm) + ' ' + digest_hex)
        return text

    # pylint: disable=too-many-arguments
    @classmethod
    def from_text(cls, rdclass, rdtype, tok, origin=None, relativize=True):
        serial = tok.get_uint32()
        scheme = tok.get_uint8()
        algorithm = tok.get_uint8()
	# Not sure why calling tok.concatenate_remaining_identifiers() here
        # causes an exception.  The loop below is copied from dns/tokenizer.py
        tdigest = ""
        while True:
            token = tok.get().unescape()
            if token.is_eol_or_eof():
                tok.unget(token)
                break
            if not token.is_identifier():
                raise dns.exception.SyntaxError
            tdigest += token.value
        digest = binascii.a2b_hex(tdigest)
        return cls(rdclass, serial, scheme, algorithm, digest)

    def to_wire(self, file, compress=None, origin=None):
        file.write(self.to_digestable())

    # pylint: disable=too-many-arguments
    @classmethod
    def from_wire(cls, rdclass, rdtype, wire, current, rdlen, origin=None):
        serial, scheme, algorithm = struct.unpack('!IBB', wire[:6])
        digest = wire[6:]
        return cls(rdclass, serial, scheme, algorithm, digest)


class ZoneDigestUnknownAlgorithm(Exception):
    """
    Exception raised if an unknown algorithm is used with ZONEMD
    functions.
    """


# Utility dictionary with the empty digests for each algorithm
_EMPTY_DIGEST_BY_ALGORITHM = {
    # SHA384
    ZONEMD_DIGEST_SHA384: b'\0' * 48,
    ZONEMD_DIGEST_SHA512: b'\0' * 64
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
    @var zonemd_algorithm: The name of the algorithm to use, either "sha384",
                          or the number of the algorithm to use.
    @type zonemd_algorithm: str
    @var zonemd_ttl: The TTL to use for the ZONEMD record, or None to
                     get this from the zone SOA.
    @type zonemd_ttl: int
    @rtype: dns.rdataset.Rdataset
    @raises ZoneDigestUnknownAlgorithm: zonemd_algorithm is unknown

    Returns the placeholder ZONEMD record added, as a ZONEMD object.
    """
    if zonemd_algorithm in ('sha384', ZONEMD_DIGEST_SHA384):
        algorithm = 1
    elif zonemd_algorithm in ('sha512', ZONEMD_DIGEST_SHA512):
        algorithm = 2
    else:
        msg = 'Unknown digest ' + zonemd_algorithm
        raise ZoneDigestUnknownAlgorithm(msg)

    empty_digest = _EMPTY_DIGEST_BY_ALGORITHM[algorithm]

    # Get the zone name.
    zone_name = min(zone.keys())

    # Remove any existing ZONEMD from the apex.
    zone.delete_rdataset(zone_name, ZONEMD_RTYPE)

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
                               1, algorithm, empty_digest)
    placeholder.add(placeholder_rdata)
    zone.replace_rdataset(zone_name, placeholder)

    return placeholder_rdata

def rdataset_sorter(rdataset):
    wire_rdata = rdataset[0].to_digestable()
    wire_rdata_len = len(wire_rdata)
    return (rdataset.rdtype, wire_rdata_len, wire_rdata)


def calculate_zonemd(zone, zonemd_algorithm='sha384'):
    """
    Calculate the digest of the zone.

    Returns the digest for the zone.

    @var zone: The zone object to digest.
    @type zone: dns.zone.Zone
    @var zonemd_algorithm: The name of the algorithm to use, either "sha384",
                          or the number of the algorithm to use.
    @type zonemd_algorithm: str
    @raises ZoneDigestUnknownAlgorithm: zonemd_algorithm is unknown
    @rtype: bytes
    """
    if zonemd_algorithm in ('sha384', ZONEMD_DIGEST_SHA384):
        hashing = hashlib.sha384()
    elif zonemd_algorithm in ('sha512', ZONEMD_DIGEST_SHA512):
        hashing = hashlib.sha512()
    else:
        msg = 'Unknown or unsupported algorithm ' + str(zonemd_algorithm)
        raise ZoneDigestUnknownAlgorithm(msg)

    # Sort the names in the zone. This is needed for canonization.
    sorted_names = sorted(zone.keys())

    # Iterate across each name in canonical order.
    for name in sorted_names:
        # Save the wire format of the name for later use.
        wire_name = name.canonicalize().to_wire()

        # Iterate across each RRSET in canonical order.
        sorted_rdatasets = sorted(zone.find_node(name).rdatasets,
                                  key=rdataset_sorter)
        for rdataset in sorted_rdatasets:
            if name == zone.origin:
                # Skip apex ZONEMD.
                if rdataset.rdtype == ZONEMD_RTYPE:
                    continue
                # Skip apex RRSIG for ZONEMD.
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
#    zonemd = zone.find_rdataset(zone_name, ZONEMD_RTYPE).items[0]

    original_digests = {}
    for zonemd in zone.find_rdataset(zone_name, ZONEMD_RTYPE).items:
        # Verify that the SOA matches between the SOA and the ZONEMD.
        if soa.serial != zonemd.serial:
            err = ("SOA serial " + str(soa.serial) + " does not " +
                   "match ZONEMD serial " + str(zonemd.serial))
            return False, err

        # check for supported scheme
        if zonemd.scheme != 1:
            continue

        # Save the original digest.
        if zonemd.algorithm in original_digests:
            err = ("Digest algorithm " + str(zonemd.algorithm) +
                   " used more than once")
            return False, err
        original_digests[zonemd.algorithm] = zonemd.digest

        # Put a placeholder in for the ZONEMD.
        if zonemd.algorithm in _EMPTY_DIGEST_BY_ALGORITHM:
            zonemd.digest = _EMPTY_DIGEST_BY_ALGORITHM[zonemd.algorithm]
        else:
            zonemd.digest = b'\0' * len(zonemd.digest)

    # Calculate the digest.
    digest = calculate_zonemd(zone, zonemd.algorithm)

    # Restore ZONEMD.
    for zonemd in zone.find_rdataset(zone_name, ZONEMD_RTYPE).items:
        zonemd.digest = original_digests[zonemd.algorithm]

    # Verify the digest in the zone matches the calculated value.
    if digest != original_digests[zonemd.algorithm]:
        zonemd_b2a = binascii.b2a_hex(original_digests[zonemd.algorithm])
        zonemd_hex = zonemd_b2a.decode()
        digest_hex = binascii.b2a_hex(digest).decode()
        err = ("ZONEMD digest " + zonemd_hex + " does not " +
               "match calculated digest " + digest_hex)
        return False, err

    # Everything matches, enjoy your zone.
    return True, ""
