---
layout: page
title: "Authorization & Capability Security"
icon: fas fa-key
permalink: /topics/authorization/
description: >-
  Articles on authorization systems, capability-based security, OAuth 2.0,
  Biscuit tokens, and designing systems where unsafe actions are
  structurally impossible at the code level.
---

How systems decide **who can do what** — and how to design those decisions so that certain violations are impossible at the code level, not just policy level.

## The core problem

Traditional authorization uses **ambient authority**: once you authenticate, you carry full permissions everywhere. A bug in any layer — a missing check, a confused deputy, a deserialization flaw — can widen access beyond what was intended. **Capability-based security** inverts this: you start with nothing and receive only the specific rights you need, encoded in unforgeable tokens that name their own scope.

## Key concepts

| Concept | Summary |
|---------|---------|
| **Capability-based security** | Authority is held in *unforgeable tokens* (capabilities) that confer specific rights. You cannot create a capability you weren't given. |
| **Attenuation** | Capabilities can be *narrowed* but not widened. A parent capability can be restricted to a subset of paths or operations, creating a child with strictly less authority. |
| **Ambient vs. capability authority** | Ambient authority: "you're logged in, so you can do everything." Capability authority: "here's a token that lets you read exactly these 3 files." |
| **OAuth 2.0 device grant** | How input-constrained devices (TVs, CLIs, IoT) obtain tokens by borrowing a second device's browser for consent. Security depends entirely on binding approval to device. |
| **Biscuit tokens** | Cryptographic capability tokens supporting logic-based attenuation (Datalog policies). Used in Warden to encode agent tool-call permissions. |

## Articles

### AI Agent Security series

These posts apply capability-based authorization specifically to AI agents:

1. [**Prompt Injection Is an Authorization Bug**](/posts/prompt-injection-is-an-authorization-bug/)
   Why prompt injection is fundamentally an authorization problem and how capability-bounded tool calls solve it structurally.

2. [**The Signature Verified, the Authority Widened Anyway**](/posts/the-signature-verified-the-authority-widened-anyway/)
   Privilege escalation through verified-but-mutable token mirrors across serialization boundaries.

3. [**Capability Boundaries Have No Memory**](/posts/the-attack-a-capability-boundary-cant-stop/)
   When boundaries aren't enough: content provenance via taint tracking for data exfiltration prevention.

### OAuth & protocol security

- [**Device Code Authorization (RFC 8628)**](/posts/device-code-authorization/)
  How OAuth 2.0's device authorization grant works, why its security rests on binding human approval to a specific device, and what goes wrong when that binding fails.

## Related code

- **[Warden](https://github.com/senthil1216/attenuate-agent)** — Biscuit-token-based capability runtime for AI agent tool calls.
- **[Capsule](https://github.com/senthil1216/capsule)** — MCP gateway combining capability boundaries with content taint tracking.

## Related topics

- [AI Agent Security](/topics/ai-agent-security/)
