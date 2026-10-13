# Hostile archive corpus

Evil-but-harmless ZIP fixtures for the future real `ArchiveReader` backend.
Payloads are inert text; the threat is in entry **names, counts, metadata,
and compression methods**. No test opens these yet — `ZipArchiveReader`
fails closed until a ZIP backend lands. When it does, each fixture gets a
test asserting the listed verdict.

| Fixture | Threat | Expected verdict |
|---|---|---|
| `traversal.zip` | `../../evil.sh`, `a/../../b.dat` entries | `PathRejected`, no write outside staging |
| `absolute.zip` | `/etc/evil` entry | `PathRejected` |
| `duplicate.zip` | `dup.txt` twice with different bytes | `PathRejected`, second entry never overwrites the first |
| `symlink.zip` | `link` entry with symlink unix-mode bits | `PathRejected`, never followed |
| `entry-bomb.zip` | 5,000 entries (exceeds production `max_entries = 1024`) | `LimitExceeded` before payload reads |
| `odd-compression.zip` | bzip2 entry alongside stored/plain | `UnsupportedCompression` for the bzip2 entry |

Regeneration: the exact `python3 -c` invocation that built these is not
checked in as a script — recreate with Python `zipfile` using the names,
counts, symlink `external_attr = 0o120777 << 16`, and compression methods
above. Keep payloads inert and the bomb at 5,000 entries.
