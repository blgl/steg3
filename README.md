Steganography with SQLite 3
===========================

SQLite's text encoding validation principle is "garbage in, garbage
out".  In particular, it will cheerfully store text values with odd byte
sizes in a database that uses UTF-16 encoding.

The extra byte at the end of such a value is highly elusive.  At the C
API level, any function returning a UTF-8 value ignores it.  This in
turn means that the `.dump` and `.sha3sum` commands of the standard
`sqlite3` CLI tool also ignore it, making it a good place to store
hidden data.

The `steg3` tool
================

Run it with a single database argument and no options to learn how many
bytes of hidden data the database contains and the maximum number of
bytes it could contain.

Use the `--extract` option to write any bytes hidden in the source
database to the specified file.

Run it with two database arguments to make a copy of the source database
with any old hidden data removed and (optionally) new hidden data
inserted.

The `--insert` option lets you specify the name of a regular file whose
contents you want to hide in the destination database.

These options select the text encoding of the destination database:

* `--utf8`

* `--utf16`

* `--utf16le`

* `--utf16be`

This tool can't store any hidden data in a UTF-8 database.

The default encoding is the same as the source database, except when
that is UTF-8 and there is data to insert, in which case it is
native-endian UTF-16.

