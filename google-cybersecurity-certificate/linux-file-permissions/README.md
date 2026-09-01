# 🐧 Linux File Permissions

**Track:** Google Cybersecurity Professional Certificate · **Course:** Assets, Threats, and Vulnerabilities · **Environment:** Linux Bash shell

## What this lab was about

A research team's `projects` directory had file and directory permissions that no longer matched the required authorization levels, and the task was to audit and correct them using standard Linux commands. The lab works through reading `ls -la`'s 10-character permission strings and then using targeted `chmod` operations to fix three separate issues: an overly permissive regular file, a hidden archived file, and a directory with broader group access than it should have.

## Files in this folder

| File | Description |
|---|---|
| [`Study_Guide.pdf`](./Study_Guide.pdf) | Full walkthrough of the permission audit and every chmod fix applied. Quick reference on the last page. |
| `source-files/File permissions in Linux_.docx` | Original lab worksheet (given) |
| `source-files/Current file permissions.docx` | Original lab worksheet — starting permission state (given) |

## Complete walkthrough

`ls -la` lists every entry in a directory, including hidden files, with a 10-character permission string at the start of each line: a `d` or `-` for directory vs. file, then three `rwx` triplets for user, group, and other. Reading `project_t.txt`'s `-rw-rw-r--` breaks down as a regular file where user and group can read and write, other can only read, and nobody has execute permission.

Three fixes were required. First, `project_k.txt` had write access open to "other," which policy didn't allow — `chmod o-w project_k.txt` removed it. Second, the hidden archived file `.project_x.txt` needed to lose write access for both user and group while keeping group read access, done with `chmod u-w,g-w,g+r .project_x.txt`. Third, the `drafts` directory needed its group execute permission removed so that only `researcher2` (who already had individual access) could still enter it — `chmod g-x drafts` handled that without disturbing researcher2's own access.

---

*Chayan Panchal · [github.com/akatetron](https://github.com/akatetron) · Google Cybersecurity Professional Certificate*
