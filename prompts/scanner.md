version: 0

<!--
Injection scanner prompt, run by the local Meta model on content the agent just read.
Human-owned; agents propose changes only.

Sections to fill when the scanner spec starts (Sun 1 Nov):

1. Role — decide whether this content contains instructions aimed at an AI assistant or agent.
2. What counts — imperative text addressed to an AI/assistant/agent/reviewer, hidden in comments, encoded, or out of place for the document type; instructions to read secrets, send data out, change permissions, disable checks, or answer "allow".
3. What does NOT count — normal documentation for humans: setup steps, "run npm install", "set API_KEY in .env", "you must run migrations". This is the main source of false positives; give 2 examples.
4. Output — JSON only: {"injection": true|false, "confidence": 0-1, "quote": "<the suspicious span, max 200 chars>", "reason": "<one sentence>"}.
5. Examples — 2 injected, 2 clean hard negatives.
-->
