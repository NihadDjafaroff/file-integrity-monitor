""".gitignore-style pattern matching.

Supported syntax (a pragmatic subset of gitignore):

* ``*``  any characters except ``/``;  ``?`` one character;  ``[abc]`` / ``[!abc]``
* ``**`` matches across directories (``**/foo``, ``foo/**``, ``a/**/b``)
* a pattern with no ``/`` matches a name at any depth (``*.swp``)
* a pattern containing ``/`` is anchored to the root it is matched against
* a trailing ``/`` restricts the pattern to directories
* ``!pattern`` re-includes something an earlier pattern matched (last match wins)
* if a parent directory matches, everything beneath it matches too
"""

import os
import re
from dataclasses import dataclass


@dataclass
class _Rule:
    regex: "re.Pattern"
    negated: bool
    dir_only: bool
    basename_only: bool


def _translate(pat):
    out = []
    i = 0
    n = len(pat)
    while i < n:
        c = pat[i]
        if c == "*":
            if pat.startswith("**/", i):
                out.append("(?:.*/)?")
                i += 3
                continue
            if pat.startswith("**", i):
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
            i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        elif c == "[":
            j = pat.find("]", i + 2)
            if j == -1:
                out.append(re.escape(c))
                i += 1
            else:
                body = pat[i + 1:j].replace("\\", "\\\\")
                if body.startswith("!"):
                    body = "^" + body[1:]
                out.append("[" + body + "]")
                i = j + 1
        else:
            out.append(re.escape(c))
            i += 1
    return "".join(out)


def _parse(line, flags):
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    negated = line.startswith("!")
    if negated:
        line = line[1:]
    dir_only = line.endswith("/")
    line = line.rstrip("/")
    if not line:
        return None
    basename_only = "/" not in line
    line = line.lstrip("/")
    regex = re.compile("^" + _translate(line) + "$", flags)
    return _Rule(regex, negated, dir_only, basename_only)


class PatternSet:
    """An ordered list of gitignore-style patterns."""

    def __init__(self, patterns, case_insensitive=None):
        if case_insensitive is None:
            case_insensitive = os.name == "nt"
        flags = re.IGNORECASE if case_insensitive else 0
        self.rules = []
        for p in patterns or []:
            rule = _parse(str(p), flags)
            if rule is not None:
                self.rules.append(rule)

    def __bool__(self):
        return bool(self.rules)

    def match(self, rel_path, is_dir=False):
        """True if ``rel_path`` (posix separators) is matched.

        Each ancestor directory is checked as well, so a pattern that matches a
        directory also matches every path below it.
        """
        parts = [p for p in rel_path.strip("/").split("/") if p]
        for i in range(len(parts)):
            prefix = "/".join(parts[: i + 1])
            prefix_is_dir = is_dir or i < len(parts) - 1
            verdict = False
            for rule in self.rules:
                if rule.dir_only and not prefix_is_dir:
                    continue
                target = parts[i] if rule.basename_only else prefix
                if rule.regex.match(target):
                    verdict = not rule.negated
            if verdict:
                return True
        return False
