#!/usr/bin/env python3
# Checks that a PR description follows the AI policy (AI-POLICY.md, "GitHub
# Communication"): short, plain-language prose a reviewer can take in with a
# single read. Used by .github/workflows/pr-description.yml.
#
# A description fails when any of these hold:
#   - the body is completely empty or unchanged from the PR template: any
#     text of the author's own passes, a link to an issue included
#   - more than 5 top-level (#, ##) section headings: it reads as a pasted
#     document, not a description (### is free: issue forms generate it;
#     headings inside code blocks and comments never count)
#   - more than 2,000 characters of prose, not counting code blocks, comments,
#     headings, checklists and URLs
#   - sentences average more than 30 words, judged only when there are at
#     least 3 sentences so one long sentence in a short description does not
#     fail on its own; above 60 it fails regardless (list items count as
#     their own sentences, so bullet lists are never concatenated)
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
MIN_SENTENCES_FOR_AVG = 3
MAX_AVG_SENTENCE_WORDS_HARD = 60
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

# A markdown list item: bullet or numbered
LIST_ITEM_RE = re.compile(r"^(?:[-*+]|\d+[.)])\s+(.*)$")


def strip_generated(body: str) -> str:
    """Remove the regions that are not the author's own text and must not feed
    any check: fenced code blocks (an unclosed fence runs to the end), inline
    code and HTML comments (the template's guidance)."""
    body = body.replace("\r\n", "\n")
    body = re.sub(r"```.*?```", " ", body, flags=re.S)
    body = re.sub(r"```.*\Z", " ", body, flags=re.S)
    body = re.sub(r"`[^`]*`", " ", body)
    body = re.sub(r"<!--.*?-->", " ", body, flags=re.S)
    return body


def author_text(body: str) -> str:
    """The author's own text: the body without generated regions, markdown
    headings and checklist lines (the template's validation section)."""
    body = strip_generated(body)
    body = re.sub(r"^#{1,6} .*$", "", body, flags=re.M)
    body = re.sub(r"^\s*- \[[ xX]\] .*$", "", body, flags=re.M)
    return body


def empty_problems(body: str) -> list[str]:
    """Fails only a body with no text of the author's own: completely empty,
    or unchanged from the PR template (comments, headings and checklists)."""
    if author_text(body).split():
        return []
    return [
        "the description is empty or unchanged from the template. "
        "Please say what changed and why."
    ]


def prose(body: str) -> str:
    """Reduce the body to the author's own prose, one segment per line: each
    list item is its own segment and paragraph lines are joined, so sentence
    counting sees the same boundaries a reader does. Link URLs and list
    markers are dropped."""
    body = author_text(body)
    body = re.sub(r"\]\(\S+\)", "]", body)
    body = re.sub(r"https?://\S+", " ", body)

    segments = []
    paragraph = []
    for raw_line in body.split("\n"):
        line = raw_line.strip()
        item = LIST_ITEM_RE.match(line)
        if item:
            if paragraph:
                segments.append(" ".join(paragraph))
                paragraph = []
            if item.group(1).strip():
                segments.append(item.group(1).strip())
        elif line:
            paragraph.append(line)
        else:
            if paragraph:
                segments.append(" ".join(paragraph))
                paragraph = []
    if paragraph:
        segments.append(" ".join(paragraph))

    return "\n".join(re.sub(r"\s+", " ", s) for s in segments)


def problems(text: str) -> list[str]:
    found = []

    if len(text) > CHAR_LIMIT:
        found.append(
            f"the description is {len(text)} characters of prose "
            f"(limit {CHAR_LIMIT}). Please make it shorter."
        )

    words = text.split()
    # a line break is a sentence boundary: list items stay separate sentences
    sentences = [s for s in re.split(r"[.!?:;]+(?:\s|$)|\n", text) if s.split()]

    if sentences and words:
        avg = len(words) / len(sentences)
        over = (len(sentences) >= MIN_SENTENCES_FOR_AVG
                and avg > MAX_AVG_SENTENCE_WORDS)
        if over or avg > MAX_AVG_SENTENCE_WORDS_HARD:
            found.append(
                f"sentences average {avg:.0f} words "
                f"(limit {MAX_AVG_SENTENCE_WORDS}). Please use shorter sentences."
            )

    if len(words) >= MIN_WORDS_FOR_RATIO:
        long_words = sum(
            1 for w in words if len(re.sub(r"\W", "", w)) >= LONG_WORD_LEN
        )
        ratio = long_words / len(words)
        if ratio > MAX_LONG_WORD_RATIO:
            found.append(
                f"{ratio:.0%} of the words have {LONG_WORD_LEN}+ characters "
                f"(limit {MAX_LONG_WORD_RATIO:.0%}). Please use simpler words."
            )

    phrases = SLOP_PHRASES_RE.findall(text)
    if phrases:
        sample = "; ".join(sorted({p.lower() for p in phrases})[:4])
        found.append(
            f'boilerplate phrasing ("{sample}"). Please reword it.'
        )

    slop = SLOP_RE.findall(text)
    if words and len(slop) >= MIN_SLOP_HITS:
        per_100 = 100 * len(slop) / len(words)
        if per_100 > MAX_SLOP_PER_100_WORDS:
            sample = ", ".join(sorted({s.lower() for s in slop})[:8])
            found.append(
                f"{len(slop)} filler words in {len(words)} words "
                f"({sample}). Please use simpler words."
            )

    return found


def structure_problems(body: str) -> list[str]:
    headings = len(HEADING_RE.findall(strip_generated(body)))
    if headings > MAX_HEADINGS:
        return [
            f"{headings} section headings (limit {MAX_HEADINGS}). "
            "Please use fewer sections."
        ]
    return []


def main() -> int:
    body = os.environ.get("PR_BODY")
    if body is None:
        body = sys.stdin.read()

    text = prose(body)
    found = empty_problems(body) + structure_problems(body) + problems(text)

    if found:
        print("Please adjust the PR description")
        print("(AI-POLICY.md, 'GitHub Communication'):")
        for p in found:
            print(f"  - {p}")
        return 1

    print(f"PR description OK: {len(text)} characters of prose.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
