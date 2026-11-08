#!/usr/bin/env python3
"""check-invisible-chars.py: refuse invisible Unicode in text files.

Copy of tactiq-os scripts/check-invisible-chars.py. That file is the one
to change; this copy follows it, and the test beside it is the same test.

Three classes of code point change what a reader, human or model, takes a
file to say without changing what it shows on screen:

  tags        U+E0000..U+E007F, the Unicode Tags block. A string of them
              decodes to ASCII (code point minus 0xE0000) and renders as
              nothing. No source file has a legitimate use for them; they
              are the channel used to hide instructions to a model in code
              (nullpt.rs, "fingerprinting-bioweapons").
  bidi        U+202A..U+202E and U+2066..U+2069, the bidirectional
              embedding, override and isolate controls. They reorder what
              is displayed relative to what is compiled (CVE-2021-42574).
  zero-width  U+200B, U+200C, U+200D, U+2060, U+FEFF, U+00AD, U+180E.
              They split or join identifiers and strings invisibly.

  check-invisible-chars.py                 every file tracked by git
  check-invisible-chars.py <file>...       the named files (for example a
                                           third-party file before it is
                                           read or reviewed)

Exit 0 when clean, 1 when any code point of the three classes is found
(file, line, column and code point are printed), 2 on a usage error.

Files that do not decode as UTF-8 are skipped and counted: they are binary
for the purposes of this check. A file named on the command line that does
not decode is an error, since the caller asked for that file specifically.
"""

import os
import subprocess
import sys

ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD, 0x180E}


def classify(cp):
    if 0xE0000 <= cp <= 0xE007F:
        return 'tags'
    if 0x202A <= cp <= 0x202E or 0x2066 <= cp <= 0x2069:
        return 'bidi'
    if cp in ZERO_WIDTH:
        return 'zero-width'
    return None


def scan_text(text):
    """Yield (line, column, code point, class) for every finding, 1-based."""
    line, col = 1, 0
    for ch in text:
        if ch == '\n':
            line, col = line + 1, 0
            continue
        col += 1
        kind = classify(ord(ch))
        if kind:
            yield line, col, ord(ch), kind


def tags_payload(text):
    """The ASCII a run of Tags code points decodes to, for the report."""
    return ''.join(chr(ord(c) - 0xE0000) for c in text
                   if 0xE0020 <= ord(c) <= 0xE007E)


def tracked_files(root):
    out = subprocess.run(['git', '-C', root, 'ls-files', '-z'],
                         check=True, capture_output=True).stdout
    return [os.path.join(root, p) for p in out.decode().split('\0') if p]


def main(argv):
    explicit = bool(argv)
    if any(a.startswith('-') for a in argv):
        print('usage: check-invisible-chars.py [<file>...]', file=sys.stderr)
        return 2
    files = argv if explicit else tracked_files('.')

    findings, skipped, errors = 0, 0, 0
    for path in files:
        if os.path.islink(path) or not os.path.isfile(path):
            continue
        try:
            with open(path, 'rb') as f:
                text = f.read().decode('utf-8')
        except UnicodeDecodeError:
            if explicit:
                print(f'{path}: not UTF-8, not checked', file=sys.stderr)
                errors += 1
            else:
                skipped += 1
            continue
        hits = list(scan_text(text))
        for line, col, cp, kind in hits:
            print(f'{path}:{line}:{col}: U+{cp:04X} ({kind})')
        payload = tags_payload(text)
        if payload:
            print(f'{path}: Tags code points decode to: {payload!r}')
        findings += len(hits)

    if not explicit:
        print(f'checked {len(files) - skipped} files, skipped {skipped} '
              f'not UTF-8', file=sys.stderr)
    if findings:
        print(f'{findings} invisible code point(s) found', file=sys.stderr)
        return 1
    return 2 if errors else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
