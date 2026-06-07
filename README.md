# senthilsiva.com

Technical writings on authorization, security, AI agents, and systems.

**Live site:** [https://www.senthilsiva.com](https://www.senthilsiva.com)

## Focus

This site hosts longer-form posts on:

- Capability-based authorization and attenuable authority
- Structural security (making harmful actions unrepresentable rather than merely unlikely)
- Prompt injection as an authorization problem
- Rust, runtime boundaries, and agentic systems
- Related work in OAuth, cloud infrastructure, and application security

See the [About](/about) page for more background and the current focus on [Warden](https://github.com/senthil1216/attenuate-agent), a Rust reference runtime for strict, auditable limits on agent tool calls.

## Local development

This is a [Jekyll](https://jekyllrb.com/) site using the [Chirpy](https://github.com/cotes2020/jekyll-theme-chirpy) theme.

```bash
bundle install
bundle exec jekyll serve
```

Then open http://localhost:4000.

## License / usage

The opinions expressed are my own. Post content is generally available under the terms typical for technical blogs (feel free to link, quote with attribution, and learn from the examples). Code snippets in posts are MIT unless otherwise noted in the post.

## Source

The source for this GitHub Pages site lives in this repository.

Contributions, issues, and suggestions are welcome via PR or email (mail@senthilsiva.com).
