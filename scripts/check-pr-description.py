#!/usr/bin/env python3
# Checks that a PR description follows the AI policy (AI-POLICY.md, "GitHub
# Communication"): short, plain-language prose a reviewer can take in with a
# single read. Used by .github/workflows/pr-description.yml.
#
# A description fails when any of these hold:
#   - more than 5 top-level (#, ##) section headings: it reads as a pasted
#     document, not a description (### is free: issue forms generate it)
#   - more than 2,000 characters of prose, not counting code blocks, comments,
#     headings, checklists and URLs
#   - sentences average more than 30 words
#   - more than a quarter of the words are 14+ characters long
#   - a boilerplate phrase nobody writes by hand ("it's important to note",
#     "plays a crucial role", ...)
#   - 3 or more abstract filler words ("seamless", "delve", "furthermore", ...)
#     at a density above 1.5 per 100 words; single uses never fail
#
# The body is taken from the PR_BODY environment variable, or from stdin when
# PR_BODY is unset:
#
#   gh pr view 1234 --json body -q .body | python3 scripts/check-pr-description.py

import os
import re
import sys

CHAR_LIMIT = 2000
MAX_AVG_SENTENCE_WORDS = 30
LONG_WORD_LEN = 14
MAX_LONG_WORD_RATIO = 0.25
MIN_WORDS_FOR_RATIO = 30
MIN_SLOP_HITS = 3
MAX_SLOP_PER_100_WORDS = 1.5
MAX_HEADINGS = 5

# Level 1-2 headings only: issue forms render their fields as ### headings,
# which must not count against the author
HEADING_RE = re.compile(r"^#{1,2} ", re.MULTILINE)

# Abstract filler that reads as generated prose. Matched case-insensitively on
# word boundaries; single uses never fail a PR, only density does.
SLOP_WORDS = [
    r"leverag(?:e|es|ed|ing)",
    r"delv(?:e|es|ed|ing)",
    r"seamless(?:ly)?",
    r"holistic(?:ally)?",
    r"streamlin(?:e|es|ed|ing)",
    r"pivotal",
    r"foster(?:s|ed|ing)?",
    r"empower(?:s|ed|ing|ment)?",
    r"synerg(?:y|ies|istic)",
    r"paradigm",
    r"meticulous(?:ly)?",
    r"intricate(?:ly)?",
    r"comprehensive(?:ly)?",
    r"robust(?:ness|ly)?",
    r"elegant(?:ly)?",
    r"cutting.edge",
    r"state.of.the.art",
    r"game.chang(?:er|ing)",
    r"furthermore",
    r"moreover",
    r"additionally",
    r"crucial(?:ly)?",
    r"vital(?:ly)?",
    r"underscor(?:e|es|ed|ing)",
    r"showcas(?:e|es|ed|ing)",
    r"boast(?:s|ed|ing)?",
    r"landscape",
    r"journey",
    r"unlock(?:s|ed|ing)?",
    r"elevat(?:e|es|ed|ing)",
    r"tapestry",
    r"testament",
    r"deep.dive",
    r"commendable",
    r"paramount",
    r"unwavering",
    r"transformative",
    r"groundbreaking",
    r"myriad",
    r"embark(?:s|ed|ing)?",
    r"endeavor(?:s|ed|ing)?",
    r"realm(?:s)?",
    r"resonat(?:e|es|ed|ing)",
    r"compelling",
    r"navigat(?:e|es|ed|ing)",
    r"facilitat(?:e|es|ed|ing)",
    r"encompass(?:es|ed|ing)?",
    r"cultivat(?:e|es|ed|ing)",
    r"exemplif(?:y|ies|ied|ying)",
    r"multifaceted",
    r"profound(?:ly)?",
    r"vibrant",
    r"renowned",
    r"ever.evolving",
    r"valuable insights?",
    r"a? ?diverse array of",
    r"in summary",
    r"a wide range of",
    r"it is worth noting",
    r"dramatically",
    r"drastically",
    r"fundamentally",
    r"inherently",
    r"genuinely",
    r"effortlessly",
    r"disproportionately",
    r"remarkably",
    r"decompos(?:e|es|ed|ing|ition)",
]
SLOP_RE = re.compile(r"\b(?:" + "|".join(SLOP_WORDS) + r")\b", re.IGNORECASE)

# Phrases that read as generated boilerplate on their own: one hit fails.
SLOP_PHRASES = [
    r"it'?s important to note",
    r"it should be noted",
    r"plays? a (?:vital|crucial|key|significant|important) role",
    r"in conclusion",
    r"in the realm of",
    r"rich tapestry",
]
SLOP_PHRASES_RE = re.compile(
    r"\b(?:" + "|".join(SLOP_PHRASES) + r")\b", re.IGNORECASE
)


def prose(body: str) -> str:
    """Strip everything that is not the author's own prose: code blocks,
    inline code, HTML comments (the template's guidance), markdown headings,
    checklist lines (the template's validation section) and link URLs."""
    body = re.sub(r"```.*?```", " ", body, flags=re.S)
    body = re.sub(r"`[^`]*`", " ", body)
    body = re.sub(r"<!--.*?-->", " ", body, flags=re.S)
    body = re.sub(r"^#{1,6} .*$", " ", body, flags=re.M)
    body = re.sub(r"^\s*- \[[ xX]\] .*$", " ", body, flags=re.M)
    body = re.sub(r"\]\(\S+\)", "]", body)
    body = re.sub(r"https?://\S+", " ", body)
    return re.sub(r"\s+", " ", body).strip()


def problems(text: str) -> list[str]:
    found = []

    if len(text) > CHAR_LIMIT:
        found.append(
            f"the description is {len(text)} characters of prose "
            f"(limit {CHAR_LIMIT}). Trim it: a reviewer must understand "
            "what changed and why in a single read."
        )

    words = text.split()
    sentences = [s for s in re.split(r"[.!?:;]+(?:\s|$)", text) if s.split()]

    if sentences and words:
        avg = len(words) / len(sentences)
        if avg > MAX_AVG_SENTENCE_WORDS:
            found.append(
                f"sentences average {avg:.0f} words "
                f"(limit {MAX_AVG_SENTENCE_WORDS}). Use shorter sentences."
            )

    if len(words) >= MIN_WORDS_FOR_RATIO:
        long_words = sum(
            1 for w in words if len(re.sub(r"\W", "", w)) >= LONG_WORD_LEN
        )
        ratio = long_words / len(words)
        if ratio > MAX_LONG_WORD_RATIO:
            found.append(
                f"{ratio:.0%} of the words have {LONG_WORD_LEN}+ characters "
                f"(limit {MAX_LONG_WORD_RATIO:.0%}). Use plain language."
            )

    phrases = SLOP_PHRASES_RE.findall(text)
    if phrases:
        sample = "; ".join(sorted({p.lower() for p in phrases})[:4])
        found.append(
            f'generated boilerplate phrasing ("{sample}"). '
            "Rewrite in your own words."
        )

    slop = SLOP_RE.findall(text)
    if words and len(slop) >= MIN_SLOP_HITS:
        per_100 = 100 * len(slop) / len(words)
        if per_100 > MAX_SLOP_PER_100_WORDS:
            sample = ", ".join(sorted({s.lower() for s in slop})[:8])
            found.append(
                f"{len(slop)} abstract filler words in {len(words)} words "
                f"({sample}). Use concrete, plain language."
            )

    return found


def structure_problems(body: str) -> list[str]:
    headings = len(HEADING_RE.findall(body))
    if headings > MAX_HEADINGS:
        return [
            f"{headings} section headings (limit {MAX_HEADINGS}). "
            "A description is not a design document — keep it flat."
        ]
    return []


def main() -> int:
    body = os.environ.get("PR_BODY")
    if body is None:
        body = sys.stdin.read()

    text = prose(body)
    found = structure_problems(body) + problems(text)

    if found:
        print("The PR description does not follow the AI policy")
        print("(AI-POLICY.md, 'GitHub Communication'):")
        for p in found:
            print(f"  - {p}")
        return 1

    print(f"PR description OK: {len(text)} characters of prose.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
