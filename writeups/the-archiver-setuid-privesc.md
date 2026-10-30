# The Archiver — Linux SetUID Privilege Escalation

**Type:** CTF / lab exercise · **Severity:** High · **Class:** CWE-269 (Improper
Privilege Management) / CWE-732 (Incorrect Permission Assignment)

> Lab exercise against a fictional "rKive" archive service. Educational; no real
> system was targeted.

## Summary

A SetUID privilege-escalation vulnerability was identified in a binary named
`archiver`, owned by `admin` with the SetUID bit set. Because the SUID bit makes
the binary execute with the **owner's** privileges, a regular, unprivileged user
could use it to read files that only `admin` should access — crossing the trust
boundary.

## Discovery

- Located the binary at `/home/<user>/.../tools/archiver`.
- `ls -la` showed it owned by `admin` with the SetUID bit (`-rws...`).
- `./archiver -h` revealed a `-l` flag that backs up a list of files into
  `/var/backups`, running with the owner's privileges.

## Exploitation (proof of concept)

1. Create a file `steal.txt` whose contents are the path to an admin-only file,
   e.g. `/home/admin/.bash_history`.
2. Invoke the SUID binary on that list:
   ```sh
   ./archiver -l steal.txt
   ```
3. The binary — running as `admin` — copies the restricted file into
   `/var/backups/backed-up-from-list.gz`.
4. Reading that backup exposed the protected contents, confirming privilege
   escalation from an unprivileged user to admin-readable data.

## Impact

An unprivileged local user can read admin-restricted files (command history,
credential material, configuration), providing a direct path toward fuller
compromise of the host.

## Remediation

- Remove the SetUID bit where it is not strictly required: `chmod u-s archiver`.
- Audit every SUID/SGID binary on the host:
  `find / -perm -4000 -o -perm -2000 -type f 2>/dev/null`.
- Inside the tool, drop privileges as early as possible and canonicalize +
  validate any user-supplied path before acting on it.
- Apply least privilege: the archiver should not run as a high-privilege owner.

## Lessons

SUID is one of the first things to enumerate in Linux privesc. A SUID binary that
takes a user-controlled file path and performs a privileged action is a classic
escalation primitive.
