# ZoneDigestHackathon
Prototype implementation of ZONEMD for the IETF 102 hackathon.

This implementation provides code to generate or validate zone digests
as described in this Internet draft:

https://tools.ietf.org/html/draft-wessels-dns-zone-digest-06

The basic idea is to make a digest - sort of like a checksum - of the
contents of the zone and include that in the zone as a record.

This version is basically complete, and includes both a module to do
the digest and a command-line program to exercise it.

## Installing

This is a Python 3 module. To use it you need Python 3 installed.

It requires the **dnspython** module. You can install
these from PyPI in the usual way with `pip`:

```
$ pip install -r requirements.txt
```

## Running

You can generate the digest across any number of zone files:

```
$ python3 digestify.py vanaheimr.cf.zone zonnestelsel.tk.zone
Wrote ZONEMD digest 3858b487874286ff34b47aa9190596bc3c9d29c4 to vanaheimr.cf.zone.zonemd
Wrote ZONEMD digest 9dd24e284e7af7141d09d50c6360b80a823e9d54 to zonnestelsel.tk.zone.zonemd
```

This writes the zone out with the ZONEMD record added or replaced, in
a new file with ".zonemd" added:

```
$ grep ZONEMD vanaheimr.cf.zone.zonemd zonnestelsel.tk.zone.zonemd
vanaheimr.cf.zone.zonemd:vanaheimr.cf 300 IN ZONEMD 2017122152 1 0 3858b487874286ff34b47aa9190596bc3c9d29c4
zonnestelsel.tk.zone.zonemd:zonnestelsel.tk 300 IN ZONEMD 2017120219 1 0 9dd24e284e7af7141d09d50c6360b80a823e9d54
```

You can specify an alternate algorithm with the "-a" flag:

```
$ python3 digestify.py -a sha384 vanaheimr.cf.zone
Wrote ZONEMD digest 71f03c16524686592b85e2ea732afef7685563c1e127e66da83212cc3a532eb6 to vanaheimr.cf.zone.zonemd
$ grep ZONEMD vanaheimr.cf.zone.zonemd
vanaheimr.cf 300 IN ZONEMD 2017122152 1 0 71f03c16524686592b85e2ea732afef7685563c1e127e66da83212cc3a532eb6
```

If you are planning on importing the zone file into a server that does
not yet support the ZONEMD type, you can use the "-g" flag to get a
generic output in the style of RFC 3597:

```
$ python3 digestify.py -g zonnestelsel.tk.zone
Wrote ZONEMD digest 9dd24e284e7af7141d09d50c6360b80a823e9d54 to zonnestelsel.tk.zone.zonemd
$ grep TYPE zonnestelsel.tk.zone.zonemd
zonnestelsel.tk 300 IN TYPE63 \# 26 783acfdb019dd24e284e7af7141d09d50c6360b80a823e9d54BlaBlaEtc
```

Validation involves using the "-c" flag to check the file(s):

```
$ python3 digestify.py -c zonnestelsel.tk.zone.zonemd
zonnestelsel.tk.zone.zonemd is has a valid digest
```

Any error will be reported with some hopefully helpful information:

```
$ python3 digestify.py -a sha384 zonnestelsel.tk.zone
Wrote ZONEMD digest ae0b88b5d9784ded8ed2e497791c71e8accb70ea3c708fdc73f34255da66cb69 to zonnestelsel.tk.zone.zonemd
$ sed 's/ 2 / 9 /' zonnestelsel.tk.zone.zonemd > broken.zone.zonemd
$ python3 digestify.py -c broken.zone.zonemd
broken.zone.zonemd does NOT have a valid digest: Unknown digest algorithm 9
$ python3 digestify.py zonnestelsel.tk.zone
Wrote ZONEMD digest 9dd24e284e7af7141d09d50c6360b80a823e9d54 to zonnestelsel.tk.zone.zonemd
$ sed 's/ZONEMD 2/ZONEMD 3/' zonnestelsel.tk.zone.zonemd > broken.zone.zonemd
$ python3 digestify.py -c broken.zone.zonemd
broken.zone.zonemd does NOT have a valid digest: SOA serial 2017120219 does not match ZONEMD serial 3017120219
$ python3 digestify.py zonnestelsel.tk.zone.zonemd
Wrote ZONEMD digest 9dd24e284e7af7141d09d50c6360b80a823e9d54 to zonnestelsel.tk.zone.zonemd
$ sed 's/900/901/' zonnestelsel.tk.zone.zonemd > broken.zone.zonemd
$ python3 digestify.py -c broken.zone.zonemd
broken.zone.zonemd does NOT have a valid digest: ZONEMD digest 9dd24e284e7af7141d09d50c6360b80a823e9d54 does not match calculated digest 3aed2facd15590f8b819827dac2f8e046ab32536
```

## Working with Signed Zones

_Note: Signed zone support is completely untested_

There are several steps required to add a zone digest to a secure zone:

1. Add a placeholder ZONEMD record to the zone.
2. Sign the zone.
3. Update the ZONEMD with the digest of the signed zone.
4. Sign the resulting ZONEMD record.

You can use the "-p" flag to add the placeholder record:

```
$ python3 digestify.py -p vanaheimr.cf.zone
Wrote ZONEMD digest 0000000000000000000000000000000000000000 to vanaheimr.cf.zone.zonemd
$ dnssec-signzone vanheimr.cf.zone.zonemd ...
   ...
$ python3 digestify.py vanaheimr.cf.zonemd.signed
   ...
$ dnssec-signzone vanaheimr.cf.zone.zonemd.signed.zonemd ...
   ...
```

## Development

There is a `Makefile` included which runs `flake8` and `pylint` across
the software. The files have been annotated to quiet `pylint` for
expected warnings and errors. You can run the checks via `make`:

```
$ pip install flake8
$ pip install pylint
$ make
```
