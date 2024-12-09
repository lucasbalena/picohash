# picohash

**Alpha version!**

Everything can change at any time (including flags).

English translation coming soon.

---

## Why?

- How can I know my files are not corrupted?
  - ...on an old hard drive sitting in the basement?
  - ...during a transfer from one hard drive to another?
  - ...during usage?
- Which backup is healthier?
- _"Wait, there is a conflict between the local version and cloud version on a
  file I haven't touched in years?"_
- **Damn cosmic rays!**

> _"Oh, there’s ZFS, which generates the file content checksum automatically."_

> Oh, really? Try using ZFS on macOS, Windows, or even Linux. Then come back and
> appreciate the portability of this program.

---

## Install

```console
go install github.com/lucasbalena/picohash
```

## Hash

```console
picohash
```

**Using rapidhash**

```console
picohash -rapid
```

**Without sidecar files (creates hashes.b3)**

```console
picohash -a
```

**Using rapidhash (creates hashes.rph)**

```console
picohash -a -rapid
```

**Specify another directory**

```console
picohash -a ../storage
```

**If you are using a hard drive**

```console
picohash -hdd
```

This will pass the flags `--no-mmap --num-threads=1` to `b3sum`.

**If you want to use cat to read the files for some reason**

```console
picohash -cat
```

## Check

```console
picohash -c
```

**Using the hashes.b3 file**

```console
picohash -c -a
```

**Using the hashes.rph file**

```console
picohash -c -a -rapid
```

## Manage the hashes

**Use `-rapid` if you hashed with `rapidhash`. This will change the extension
from _.b3_ to _.rph_**

**Delete all sidecar hash files**

```console
picohash -d
```

**Split hashes.b3 into sidecar files**

```console
picohash -s
```

**Join the sidecar files into a single hashes.b3**

```console
picohash -j
```

It reads hashes.b3 (if it exists) and adds any new hashes found in the directory
to it.

If you want to copy only a subfolder that was hashed with `-a`, you can split
the hashes, copy the subfolder along with its associated hashes, paste them in
the destination, and then join the hashes. This ensures that all relative paths
remain correct.

**Rename a file or directory**

    1.	Rename the file.
    2.	Rename the sidecar file.
    3.	Run the following to rewrite the sidecar content to match the new filename.

```console
picohash -r
```

If you used `-a`:

```console
picohash -s                     # Who wants to deal with a long .txt?
# Rename the file and sidecar
picohash -r                     # Rename the inside contents
# Delete hashes.b3              # To prevent duplicates
picohash -j                     # Recreate hashes.b3
picohash -d                     # Delete the sidecar files
```

Or

```console
picohash -s                     # Who wants to deal with a long .txt?
# Rename the file
# Delete the sidecar
# Delete hashes.b3              # To prevent duplicates
picohash -j                     # Recreate hashes.b3
picohash -d                     # Delete the sidecar files
picohash -a                     # Hash the renamed file
```

**Perhaps there are better ways to handle renaming**

The current structure for _.b3_ and _.rph_ is as follows:

```
hash name
```

This format ensures compatibility with other hash-checking programs but requires
using `-r` to update the sidecar file content to match the new name.

However, even if we change the structure to:

```
hash
```

all other steps would still be necessary with you use `-a`.

In a folder with thousands of files and subfolders, having sidecar files becomes
overwhelming.

## Subtitles

| Symbol | Meaning                                             |
| ------ | --------------------------------------------------- |
| ✅     | Passed                                              |
| ❌     | Mismatch                                            |
| 🔍 📂  | File not found (hash exists)                        |
| 🔍 ⛏️  | Hash not found (file exists)                        |
| ❗     | Unexpected error (big problem)                      |
| ⚙️     | Hash generated successfully                         |
| ⏭️     | Skipped a file already hashed                       |
| 🤞     | Expected hash (but does not match, appears with ❌) |
