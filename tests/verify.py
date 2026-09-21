"""Compare a btrfs-peek copy (via its --manifest) against the manifest made on Linux."""
import hashlib, json, os, stat, sys

linux_manifest, peek_manifest, src_root = sys.argv[1:4]

want = {}
for line in open(linux_manifest, encoding="utf-8"):
    line = line.rstrip("\n")
    if line.startswith("f "):
        _, mode, size, sha, path = line.split(" ", 4)
        want[path] = ("file", mode, int(size), sha)
    elif line.startswith("d "):
        _, mode, path = line.split(" ", 2)
        want[path] = ("dir", mode)
    elif line.startswith("l "):
        target, path = line[2:].split("\t", 1)
        want[path] = ("symlink", target)

got = {}
for line in open(peek_manifest, encoding="utf-8"):
    m = json.loads(line)
    rel = m["path"][len(src_root):].lstrip("/")
    if not rel:
        continue
    if m["type"] == "file":
        h = hashlib.sha256()
        with open(m["dest"], "rb") as f:
            for block in iter(lambda: f.read(1 << 20), b""):
                h.update(block)
        mode = m["mode"]
        # On POSIX the copy must actually carry the mode onto disk, not merely
        # record it in the manifest. Windows has no mode to compare against.
        if os.name == "posix":
            mode = oct(stat.S_IMODE(os.stat(m["dest"]).st_mode))[2:]
        got[rel] = ("file", mode, m["size"], h.hexdigest())
    elif m["type"] == "dir":
        got[rel] = ("dir", m["mode"])
    else:
        got[rel] = ("symlink", m["target"])

bad = 0
for path in sorted(set(want) | set(got)):
    if want.get(path) != got.get(path):
        bad += 1
        if bad <= 20:
            print("MISMATCH", path, "\n   linux:", want.get(path), "\n   peek: ", got.get(path))
print(f"{len(want)} expected, {len(got)} copied, {bad} mismatches")
sys.exit(1 if bad else 0)
