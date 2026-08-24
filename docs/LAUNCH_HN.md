# Show HN

Post it yourself, from your own account. HN dislikes anything that reads as marketing, so the
draft below leads with the problem and the engineering, and mentions the product once.

Best time to post is a weekday morning US Eastern. Stay in the thread for the first few hours,
because on HN the comments are the story.

---

## Title

```
Show HN: ExtGuard, a local audit for your installed VS Code extensions
```

Keep it flat. No exclamation, no "finally", no adjectives. HN titles that sell get flagged.

---

## Body

VS Code has no permission model. Any extension with a `main` entry point runs as ordinary
Node.js with the full reach of your user account: your files, your environment variables, your
terminal, your network. There is nothing to over-request because everything is already granted,
and there is no prompt at install time telling you so.

Researchers cataloguing the Marketplace found 1,283 extensions carrying known malicious code,
installed 229 million times between them [1]. Three weeks ago, 77 "evil twin" extensions were
pulled from Open VSX after exfiltrating hostnames, workspace paths and CI data to a domain
registered eleven days before the first upload [2]. The attacks that worry me most are the
boring ones: a typosquatted theme, or a leaked publisher token used to push a malicious update
to an extension you already trust.

I have 81 extensions installed and have read the source of none of them. I assume that is
normal.

ExtGuard reads what is already on disk and reports what each extension can reach. It is not a
scanner and not a sandbox: it cannot stop an extension that is already running. It checks four
things, all locally.

1. **Known-malicious IDs.** 1,981 malicious records and 1,300 blocked
   publishers, aggregated from public feeds including Microsoft's own removed-packages list.
   The database ships inside the extension, so this check never touches the network.
2. **Hardcoded secrets.** Structural patterns for AWS, GitHub, Slack, Stripe, Google, npm,
   private key blocks, and Azure DevOps PATs. The last one matters most: a leaked publisher
   PAT is what lets an attacker ship an update to somebody else's extension.
3. **Capability signals.** What the manifest reveals about reach, plus what the shipped code
   actually calls: process spawning, dynamic evaluation, outbound connections, reads of
   `~/.ssh` and `~/.aws`.
4. **Optional Marketplace status.** An extension installed but no longer published was usually
   removed by Microsoft. Off by default, and the only network call in the product.

### The interesting part is the false positives

An early build produced **2,850 findings across 57 of the 82 extensions** installed on my own
machine at the time, which I have every reason to believe is clean. That is not a security tool. That is a tool you learn
to ignore, and then you ignore the one finding that mattered.

Three causes, all of which I suspect are common in this category:

- Behaviour rules ran on markdown, JSON schemas and minified bundles. The word "request" inside
  `"description": "Attribution text for pull..."` counted as a network call.
- A `[a-zA-Z0-9]{52}` rule for Azure DevOps PATs fired on any long token in a minified bundle.
- Nothing detected generated code, so matching identifiers in a webpack bundle told me about
  the bundler rather than the author.

Now behaviour rules run only on non-minified source with string bodies stripped before
matching, generic tokens must be assigned to a credential-shaped identifier and clear an
entropy floor, and structural patterns are the only ones trusted on their own. Same machine, rescanned
today: **81 extensions, zero malicious matches, zero critical or high findings**, and 26 medium
ones that are all real (build scripts that genuinely call `child_process`).

### The distinction I think matters most

The upstream feed publishes a "risky" list alongside the malicious one. It contains GitLens,
Microsoft's own PowerShell extension, and Jupyter, because those execute code and read your
codebase by design.

Merging those two lists flags six entirely legitimate extensions on my machine on first run:
GitLens, PowerShell, Jupyter, Continue, Cline and Copilot Chat. ExtGuard keeps them apart in the type system rather than by convention: malicious IDs
produce findings, capability produces an explanation with a lightbulb next to it. A tool that
opens by calling Microsoft's PowerShell extension a threat has told you nothing except that it
cannot be trusted.

### Limits worth stating

- **Recall is the weak axis, not precision.** Obfuscated or dynamically-fetched payloads will
  not be caught by pattern matching. A clean result means these checks found nothing.
- **The threat database is a point-in-time snapshot**, because shipping it bundled is what
  keeps scanning offline. A threat published after your last update will not be detected, so
  the extension shows you the snapshot date rather than implying its knowledge is current.
- **It reports, it does not remove.** Deciding what to uninstall is yours.

Free, MIT, no telemetry, no account. Works on VS Code, Cursor and Windsurf.

Marketplace: https://marketplace.visualstudio.com/items?itemName=babstudios.extguard-security
Source: https://github.com/BAB78/extguard

I would rather hear that a check is wrong than that the idea is nice. If it flags something of
yours incorrectly, the extension id and the finding are enough for me to fix it.

[1] https://www.scworld.com/news/vscode-extensions-with-malicious-code-installed-229m-times
[2] https://www.bleepingcomputer.com/news/security/77-open-vsx-extensions-found-harvesting-developer-info/

---

## Prepared answers

**"Why not just read the source of your extensions?"**

> You should, for anything you actually depend on. Nobody does it for eighty of them, and the
> ones worth worrying about ship minified. This is the pass you run before deciding which two
> are worth reading properly.

**"Pattern matching will not catch a competent attacker."**

> Agreed, and I say so in the README. It catches the careless ones, which is most of what has
> actually been found on the Marketplace: typosquats, credential stealers with the keys in
> plain text, and extensions that were already removed but are still installed. The
> Marketplace-status check is the one that generalises, because Microsoft acts before any
> aggregator does.

**"Is this not security theatre?"**

> It would be if it reported everything as risky, which is exactly what the first version did
> and why most of the work went into the opposite. The number I would judge it on is zero hard
> findings on a clean 82-extension machine.

**"What about Open VSX, Cursor and Windsurf?"**

> It reads the extension directories directly, so Cursor and Windsurf work today. Open VSX as a
> threat-intelligence source is not in yet, which matters because two of the recent incidents
> were there.

**"Would ExtGuard have caught the 77 Open VSX extensions?"** (expect this one)

> Honestly, probably not on day one. They were newly uploaded, so no feed listed them yet, and
> they exfiltrated over plain HTTPS to a normal-looking domain, which is not a pattern you can
> match on without flagging every extension that makes a network call. What ExtGuard would have
> shown you is that a freshly published extension with no history was reaching the network and
> reading workspace paths, and after August 3rd the Marketplace-status check would have flagged
> every one of them as removed-but-still-installed. That second part is the real value: the
> gap between a takedown and you noticing is currently forever.

**"How is this different from just checking the removed-packages list?"**

> That list is one of the inputs. The parts it does not cover are secrets in shipped code,
> capability, and the extension that is installed on your machine but quietly disappeared from
> the Marketplace last week.

**If someone reports a false positive:** get the extension id and the finding, fix it, ship a
patch, and reply in the thread saying it is fixed. Doing that publicly is worth more than the
original post.
