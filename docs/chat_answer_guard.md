# Checking AI explanation (chat) answers

How Vulnix handles the external model's (Abliteration AI's) answers to questions before they are shown in the UI. Implementation: `aegis/chat_guard.py`; wiring: `AssessmentService._answer_question` / `ask_chat` in `aegis/assessment.py`.

## Three layers

| Layer | Who writes it | When it applies | What is shown |
|---|---|---|---|
| Verdict note (`verdict_note`) | **Code** (not the model) | Every answer about a finding that has not been proven by an approved L2 check | A fixed sentence above the answer: 「この問題の判定は「L1で検出（未実証）」です…断定できません」. When the term matches both proven and unproven findings, a dedicated note says so. |
| Caution (`caution_note`) | Code | Assertions about an unproven finding (「脆弱性があります」「悪用できます」), or claims that a breach or leak happened | The answer **is shown**, with a yellow note above it. A false positive only adds a note. |
| Withholding (`guard_note`) | Code | **Instructions** (「〜してください」「〜しましょう」「しても問題ありません」, English imperatives or "you should…") to skip approval, disable defences or delete data. Also attack tools with flags or "check it with", and attack strings meant to be entered or sent | The answer **is not shown**. The built-in explanation is shown instead, with the reason. The withheld text is not stored, audited or included in events (only the reason code is audited). |

## Why it's split this way

The rule that "something detected by L1 must never be called proven" **does not depend on text rules**. The code-generated verdict note is always shown, whatever the model writes. Text rules are only a backstop behind the system prompt (`CHAT_SYSTEM_PROMPT`).

During the independent reviews (4 rounds), wider text rules turned out to **withhold correct explanations and remediation advice**, for example 「L2 は承認なしでは実行されません」 and 「使用済みのCSRFトークンを無効化してください」. So withholding is limited to instructions, and overclaims are handled with notes.

## What it still can't catch (known limits)

- It is regex-based, so it can't fully cover paraphrases, metaphors, other languages or instructions split across several sentences. The reviews' examples are kept as regression tests (`tests/test_chat_answer_guard.py`).
- What it guarantees is "what is displayed". Execution rights are a separate matter: AI output has no execution rights in the first place, and a Worker can't be started from an AI proposal.
- It is only applied to external-model answers about the local lab. Data about real services is not sent to the external model (an existing allow-list).
