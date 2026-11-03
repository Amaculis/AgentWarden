# Demo video script (≤ 3:00)

Final cut, matched to the footage recorded on 2 Nov (raw takes in `D:\demo-recording\raw\`).
Every number comes from README (eval 31 Oct, cascade re-run 1 Nov). Timings are taken from the
assembled video; read each block within its window.

## Voiceover

### 1. Re-enactment — 0:00–0:14 (take A)
On screen: the README's hidden command runs without AgentWarden; fake keys land on a local
stand-in "attacker" server. Caption: "Re-enactment · no AgentWarden · fake keys, local server".
> I asked my coding agent to fix a button colour. The project's README hid one more line for
> it: send the env file to a stranger. This is that line, run without protection.

### 2. Problem — slide
> Coding agents run shell commands, edit files and read the web. Anything they read can carry
> instructions. Permission prompts don't save you: after the hundredth one, you just click yes.

### 3. Intro — title card
> This is AgentWarden: a semantic firewall between your AI agent and your machine. Every action
> gets allow, deny, or ask.

### 4a. Scanner — take B3
On screen: the agent opens README.md; a scanner warning appears on the dashboard.
> When the agent opens the README, a local Llama model scans it and flags the hidden
> instruction. The warning goes straight back to the agent: treat this as data, not orders.

### 4b. Block — take B2
On screen: the same command sent through the AgentWarden hook; red "blocked (rules)", red row
on the dashboard. Caption: "Same command, through the AgentWarden hook".
> Today's agents often refuse on their own. When one doesn't, the same command hits a
> deterministic rule: blocked, with a reason and a safer alternative. There is no model here to
> talk past.

### 4c. Real work — take B1
On screen: a real Claude Code session fixes the CSS; one `ask`, the edit `allow`ed; waits sped
up. Caption: "Real session · waits sped up".
> Everything else keeps flowing. The local model allows routine reads and edits, and asks the
> human when it isn't sure. Hard cases escalate to Muse Spark. The button is fixed, and the
> secrets stayed home.

### 5. Meta models — diagram
> Meta models do three jobs. Llama runs locally on every action the rules don't settle, so most
> code never leaves the machine. Muse Spark takes the hard cases, and it also attacks us: a
> red-team loop generates new attacks and scores the defence. Any error or timeout becomes ask.
> It fails closed.

### 6. Numbers — table, then stat tiles
> We measured it on 155 labelled agent actions. The cascade matches Spark-only accuracy, 95
> percent, catches every attack in the test set, and costs about half a cent per hundred
> actions: forty times cheaper than sending everything to Spark. The scanner catches 92 percent
> of injected documents at 96 percent precision. And across forty red-team rounds, Muse Spark
> generated 200 attacks. None got through.

### 7. Close
> AgentWarden. Let your agent work, without handing it the keys. It's open source; the link is
> below.

## Notes

- Scene 1 is a re-enactment: current Claude models refused the injection in every take, so the
  command was run by hand against a local server. The caption says so.
- Scene 4b sends the command through the real `hooks/on_tool.py` (`D:\demo-recording\tools\aw_try.py`),
  into the same daemon and session as the recorded agent run.
- No Spark escalation happened in the recorded takes (all decided locally); 4c mentions
  escalation as a capability, the diagram and numbers back it.
