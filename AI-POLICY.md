# OpenTelemetry eBPF Instrumentation Generative AI Policy

Based in [Cilium Generative AI Policy](https://github.com/cilium/community/blob/main/AI-POLICY.md#unacceptable-use).

To maintain the high quality and trustworthiness of contributions to the
OpenTelemetry eBPF Instrumentation (OBI)
community, we provide the following guidance on the use of "Generative
Artificial Intelligence", including large language models (LLMs), GitHub
Copilot, ChatGPT, Codex, Claude code, or similar tools ("Generative AI"). The
guidance in this document is intended for all contributors to the community. As
a Linux Foundation project, OBI is also subject to the Linux Foundation
[Guidance Regarding Use of Generative AI Tools]. The guidance in this document
is intended to support you as a contributor in addition to the Linux Foundation
guidance.

## 1. Guiding Principle

OBI is a community-driven organization that values expertise, clear
communication, and personal responsibility. The community prides itself on a
commitment to high quality and trust amongst its members. To maintain this in
the AI era, we follow a key principle:

**What you do with Generative AI reflects on you**.

Successful ongoing contribution to this community is contingent on building
trust with the members of the organization through ongoing collaboration.
Whether or not Generative AI tools were involved, you are fully accountable for
the correctness, security, and clarity of your contributions. Human review is
required for all code, including code generated or assisted by Generative AI
tools. If you contribute regularly, other contributors will become familiar
with your work, so we request that you mindfully consider the impact that your
use of Generative AI may have on other community members.

## 2. Acceptable Use

We recognize that Generative AI can be a helpful _tool_, for example you may
use it to:

- Explain parts of the codebase you don’t understand;
- Auto-complete routines or boilerplate code (such as error handling, test
  scaffolding, function signatures);
- Reformat or refactor existing content;
- Brainstorm ideas for implementation cases, but write the actual code yourself;
- Draft test cases which you subsequently review, revise and simplify before
  submission; or
- Analyze your own content submissions.

These uses are acceptable provided you:

1. Are involved in the entire process for creating the contributions;
2. Personally review and edit generated content before you submit it to the
  organization;
3. Fully understand and review the content prior to submission;
4. Take personal responsibility for the content, in the same way as if you
  authored the content without using Generative AI;
5. Ensure the output adheres to project guidelines and licensing requirements; and
6. Report the use of Generative AI tools for non-trivial preparation of
  submissions (that is, at level 2 or higher on the [AI Influence Level]).

## 3. Unacceptable Use

It is not acceptable to use Generative AI tools to:

1. Communicate in any OBI community space with content that is substantially
  written using Generative AI tools. For example, it is not acceptable to send
  such text on Slack or GitHub, whether initiating or responding to discussion
  with other community members.
2. Submit code, documentation, or discussion content that you have not reviewed
  in careful detail, including testing the content where applicable.
3. Rely solely or primarily on Generative AI output for technical problem
  solving, architectural decision making.
4. Submit work produced via Generative AI tooling that copies from external
  sources without correct attribution or licensing.
5. Submit contributions where you cannot explain, contextualize, or justify the
  submission as part of review.

## 4. Generative AI for Translation

If you are interacting in a OBI community space which primarily uses a
language which you are not fluent in, community members will generally
appreciate your attempts to express your ideas in that language without the use
of Generative AI tools. However, we recognize that contributors from around the
world may want to participate in discussion in the OBI community, and the
community can benefit from those discussions even if Generative AI is used to
facilitate those discussions. When communicating in a language you are not
confident in, consider drafting your intended response and attempt to convey
your ideas in the target language first. If you believe the ideas are not
conveyed clearly, consider using translation tools (either non-generative or
generative). Be aware that if you rely significantly on Generative AI for
translation, this itself may inhibit communication due to limitations in
Generative AI tooling.

## 5. Transparency & Attribution

We generally expect contributors to declare when Generative AI was used to
prepare a submission. For non-trivial text or code submissions (such as new
features, documentation pages, complex design proposals), you should describe
how Generative AI was used and explain the human review process applied. For
trivial use of Generative AI (such as spelling check or simple autocomplete)
you are not expected to declare use. Suspected use of Generative AI tooling
without transparency may lead to submissions being closed or rejected without
discussion.

## DCO and Licensing

The [EasyCLA signature](https://easycla.lfx.linuxfoundation.org/#/?version=2) is required for contributions to
the OBI organization. AI tools often lack transparency into their training
data and may produce output with pre-existing copyright. If you submit
AI-assisted contributions, you are personally certifying that you have the
right to contribute the content under the project's license. The Linux
Foundation [Guidance Regarding Use of Generative AI Tools] provides a more
detailed description of your obligations as a contributor. If you’re unsure
about the licensing of code you created using Generative AI tools,
**don’t submit it**.

[AI Influence Level]: https://danielmiessler.com/blog/ai-influence-level-ail
[Guidance Regarding Use of Generative AI Tools]: https://www.linuxfoundation.org/legal/generative-ai
