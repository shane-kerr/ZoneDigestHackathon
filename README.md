# ZoneDigestHackathon
Prototype implementation of ZONEMD for the IETF 102 hackathon.

This implementation provides code to generate or validate zone digests
as described in this Internet draft:

https://tools.ietf.org/html/draft-wessels-dns-zone-digest-02

The basic idea is to make a digest - sort of like a checksum - of the
contents of the zone and include that in the zone as a record.

This version is basically complete, and includes both a module to do
the digest and a command-line program to exercise it.

## Installing

This is a Python 3 module. To use it you need Python 3 installed.

It requires the **dnspython** and **pygost** modules. You can install
these from PyPI in the usual way with `pip`:

```
$ pip install -r requirements.txt
```

In principle the software can be run without GOST support, and so the
**pygost** module is not strictly required, however since it's so easy
to install I opted against updating the code to work without it.

## Running

You can generate the digest across any number of zone files:

```
$ python3 digestify.py vanaheimr.cf.zone zonnestelsel.tk.zone
Wrote ZONEMD digest 77a11b969b88122c3ac53d8409fdba5e38e2ec50 to vanaheimr.cf.zone.zonemd
Wrote ZONEMD digest 8894b1decd04c49575ea717318f57bea2cc3589e to zonnestelsel.tk.zone.zonemd
```

This writes the zone out with the ZONEMD record added or replaced, in
a new file with ".zonemd" added:

```
$ grep ZONEMD vanaheimr.cf.zone.zonemd  vanaheimr.cf.zone.zonemd
vanaheimr.cf.zone.zonemd:vanaheimr.cf 300 IN ZONEMD 2017122152 1 77a11b969b88122c3ac53d8409fdba5e38e2ec50
vanaheimr.cf.zone.zonemd:vanaheimr.cf 300 IN ZONEMD 2017122152 1 77a11b969b88122c3ac53d8409fdba5e38e2ec50
```

You can specify an alternate algorithm with the "-a" flag:

```
$ python3 digestify.py -a gost vanaheimr.cf.zone
Wrote ZONEMD digest 5ac0a398ee0f5c3bcfc1e78e0a976bf8916cab4a6c3c0f97362a23dbc79f6fdb to vanaheimr.cf.zone.zonemd
$ grep ZONEMD vanaheimr.cf.zone.zonemd
vanaheimr.cf 300 IN ZONEMD 2017122152 3 5ac0a398ee0f5c3bcfc1e78e0a976bf8916cab4a6c3c0f97362a23dbc79f6fdb
```

If you are planning on importing the zone file into a server that does
not yet support the ZONEMD type, you can use the "-g" flag to get a
generic output in the style of RFC 3597:

```
$ python3 digestify.py -g zonnestelsel.tk.zone
Wrote ZONEMD digest 8894b1decd04c49575ea717318f57bea2cc3589e to zonnestelsel.tk.zone.zonemd
$ grep TYPE6543 zonnestelsel.tk.zone.zonemd
zonnestelsel.tk 300 IN TYPE65432 \# 25 783acfdb018894b1decd04c49575ea717318f57bea2cc3589e
```

Validation involves using the "-c" flag to check the file:

```
$ python3 digestify.py -c zonnestelsel.tk.zone.zonemd
zonnestelsel.tk.zone.zonemd is has a valid digest
```

Any error will be reported with some hopefully helpful information:

```
$ python3 digestify.py -a sha256 zonnestelsel.tk.zone
Wrote ZONEMD digest 8c3701dee6b211c6e5d4d26b030f307e8b6312001cdebaa70ff80ac2f88187a5 to zonnestelsel.tk.zone.zonemd
$ sed 's/ 2 / 9 /' zonnestelsel.tk.zone.zonemd > broken.zone.zonemd
$ python3 digestify.py -c broken.zone.zonemd
broken.zone.zonemd does NOT have a valid digest: Unknown digest algorithm 9
$ python3 digestify.py zonnestelsel.tk.zone
Wrote ZONEMD digest 8894b1decd04c49575ea717318f57bea2cc3589e to zonnestelsel.tk.zone.zonemd
$ sed 's/ZONEMD 2/ZONEMD 3/' zonnestelsel.tk.zone.zonemd > broken.zone.zonemd
$ python3 digestify.py -c broken.zone.zonemd
broken.zone.zonemd does NOT have a valid digest: SOA serial 2017120219 does not match ZONEMD serial 3017120219
$ python3 digestify.py zonnestelsel.tk.zone.zonemd
Wrote ZONEMD digest 8894b1decd04c49575ea717318f57bea2cc3589e to zonnestelsel.tk.zone.zonemd
$ sed 's/900/901/' zonnestelsel.tk.zone.zonemd > broken.zone.zonemd
$ python3 digestify.py -c broken.zone.zonemd
broken.zone.zonemd does NOT have a valid digest: ZONEMD digest 8894b1decd04c49575ea717318f57bea2cc3589e does not match calculated digest b378c94f5ae01484bb0e3665bbc61a8844bbca6a
```

## Working with Signed Zones

T.B.D.

## Development

There is a `Makefile` included which runs `flake8` and `pylint` across
the software. The files have been annotated to quiet `pylint` for
expected warnings and errors. You can run the checks via `make`:

```
$ pip install flake8
$ pip install pylint
$ make
```
