---
layout: page
title: "AI Agent Security"
icon: fas fa-shield-halved
permalink: /topics/ai-agent-security/
description: >-
  In-depth articles on AI agent security: capability-based authorization,
  prompt injection prevention, taint tracking, and structural defenses
  for LLM agent systems.
---

Treating AI agents as **security principals** — not just helpful assistants that happen to execute code. This topic covers how to constrain AI agent authority so that prompt injection, confused-deputy attacks, and privilege escalation become structurally impossible rather than merely unlikely.

## The core problem

An LLM agent authenticates **once** at session start. After that, every tool call it makes — read a file, run a command, hit the network — runs with the caller's full ambient authority for the rest of the session. When that agent ingests untrusted content (a repo README, an email, a search result), an attacker can inject instructions that redirect that authority toward exfiltration or destruction.

## Key concepts

| Concept | Summary |
|---------|---------|
| **Capability-based authorization** | Agents receive *tokens* that name exactly what they're allowed to do. No operation exists to widen authority — it's not just blocked, it's **unrepresentable**. |
| **Prompt injection as authorization bug** | Injection isn't a "model alignment" problem alone; it's an **authorization boundary** problem. The fix is structural: make the runtime incapable of granting permissions the caller didn't intend. |
| **Content provenance / taint tracking** | Capability boundaries stop out-of-scope reads. But data read legitimately can still be pasted into outbound channels. Taint tracking traces data from source to sink. |
| **MCP capability gateways** | The Model Context Protocol lets agents call tools. A gateway between agent and tools can enforce both boundary checks and content-based policies. |
| **Serialization vulnerabilities** | Capabilities cross process boundaries via serialization (JSON, bincode). If the deserialized mirror isn't covered by the signature, an attacker can widen permissions after verification. |

## Reading order

Start here and read through. Each post builds on the previous one.

1. [**Prompt Injection Is an Authorization Bug**](/posts/prompt-injection-is-an-authorization-bug/)
   Capability-bounded tool calls where widening authority is unrepresentable. Two agents, same injected attack — one leaks secrets, the other *can't*.

2. [**The Signature Verified, the Authority Widened Anyway**](/posts/the-signature-verified-the-authority-widened-anyway/)
   How verified crypto signatures still allow privilege escalation when a signed token's in-memory mirror gets modified across a serialization boundary.

3. [**Capability Boundaries Have No Memory**](/posts/the-attack-a-capability-boundary-cant-stop/)
   When sandboxing isn't enough and you need content provenance too. Capsule: an MCP gateway combining capability boundaries with taint tracking.

## Related code

- **[Warden](https://github.com/senthil1216/attenuate-agent)** — Rust reference runtime enforcing strict, auditable authority limits on agent tool calls via Biscuit tokens.
- **[Capsule](https://github.com/senthil1216/capsule)** — MCP capability gateway with sandbox boundaries + content-based taint tracking.

## Related topics

- [Authorization & Capability Security](/topics/authorization/)
