---
# the default layout is 'page'
icon: fas fa-info-circle
order: 4
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "Person",
  "name": "Senthil Siva",
  "url": "https://www.senthilsiva.com/about/",
  "email": "mailto:mail@senthilsiva.com",
  "sameAs": [
    "https://github.com/senthil1216",
    "https://www.linkedin.com/in/ssivasubramanian/"
  ],
  "jobTitle": "Engineering Leader",
  "worksFor": {
    "@type": "Organization",
    "name": "Independent"
  },
  "knowsAbout": [
    "Authorization",
    "Capability-Based Security",
    "AI Agent Security",
    "OAuth 2.0",
    "Rust",
    "Systems Security"
  ],
  "description": "Engineering leader writing about security, authorization, AI agents, and systems where unsafe actions are structurally impossible."
}
</script>

I write about **security**, **authorization**, **AI agents**, and the systems challenges that come with powerful but untrusted components.

My focus is on **structural** approaches: capability-based authorization, attenuable tokens, runtime boundaries, and designs where certain classes of harm become *unrepresentable* rather than merely unlikely. I'm the author of [Warden](https://github.com/senthil1216/attenuate-agent), a Rust-based reference runtime that enforces strict, auditable authority limits on agent tool calls.

This site is the home for longer-form technical writing on these topics — and related work in Rust, infrastructure, and application security.

## Projects

- **[Warden](https://github.com/senthil1216/attenuate-agent)** — A capability-secure runtime for AI agent tool calls. Rust, Biscuit tokens, structural authority boundaries.
- **[Capsule](https://github.com/senthil1216/capsule)** — An MCP capability gateway combining sandbox boundaries with content-based taint tracking.

## Recommended reading

If you're new here, start with:

1. [**Prompt Injection Is an Authorization Bug: Capability-Bounded AI Agents**](/posts/prompt-injection-is-an-authorization-bug/) — The foundational post. Two agents, same injected attack. One leaks secrets; the other *can't*.
2. [**The Signature Verified, the Authority Widened Anyway**](/posts/the-signature-verified-the-authority-widened-anyway/) — How a verified crypto signature still lets attackers escalate privileges (Part 2).
3. [**Capability Boundaries Have No Memory**](/posts/the-attack-a-capability-boundary-cant-stop/) — When sandboxing isn't enough and you need content provenance too (Part 3).

## Contact

- **Email**: [mail@senthilsiva.com](mailto:mail@senthilsiva.com)
- **GitHub**: [senthil1216](https://github.com/senthil1216)
- **LinkedIn**: [ssivasubramanian](https://www.linkedin.com/in/ssivasubramanian/)
- **Location**: San Francisco, CA

I'm an engineering leader focused on cloud platforms, security, and agentic systems. Worked on SaaS/PaaS and modern cloud infrastructure.

The goal here is clarity over volume: posts that go deep on one hard problem, with honest threat models and reproducible examples.
