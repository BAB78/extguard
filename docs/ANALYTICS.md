# Analytics

## Recommendation: do not add telemetry to ExtGuard

The original brief asks for a minimal analytics event, extension activated and scan run, sent
to PostHog or Plausible, so real usage is visible. For most products that is a reasonable ask
and I would just build it. For this one it is the single change most likely to kill it, so the
argument is worth making before writing any code.

### Why it is different here

Every claim ExtGuard makes rests on one sentence, repeated in the README, in SECURITY.md and on
the Marketplace listing:

> No telemetry, no analytics, no account, and no network calls during a scan.

That is not a feature note. It is the reason anyone installs a security scanner from a publisher
they have never heard of. The product audits your editor for software that phones home. A
version of it that phones home is arguing against itself, and the audience most likely to try it
is exactly the audience most likely to notice.

There is also a practical trap. ExtGuard's own scanner reports outbound network calls in other
extensions as a finding. Adding an analytics beacon would mean the tool contains the behaviour
it flags, which is the sort of detail that ends up as the top comment on Show HN, quoted from
our own source.

And the claim would simply become false. The listing, the README and SECURITY.md would all need
rewriting to say "no telemetry except", which is a materially weaker sentence and reads as one.

### What actually answers the question

The reason for wanting analytics is to know whether anyone is using it. The Marketplace already
reports that, for free, with no code and no privacy cost:

- **Installs, unique installs and downloads**, per version
- **Ratings and reviews**
- **Trend over time**

at https://marketplace.visualstudio.com/manage/publishers/babstudios

That covers the whole of the original intent. Install count is the number that decides whether
the Team tier has anybody to sell to, and it is right there without shipping a single event.

For qualitative signal, GitHub issues and Marketplace reviews tell you far more than an
activation counter ever would. "Nobody filed anything" and "200 people installed it" together
are a clearer read than a graph of activations.

### If you decide to add it anyway

It is your product and this is a judgement call, not a rule. If you do, these are the
conditions that keep it defensible:

1. **Opt in, never opt out.** Default off, with a clear prompt explaining exactly what is sent.
2. **Say so everywhere the current claim appears.** README, SECURITY.md and the Marketplace
   listing, in the same release. A privacy claim that lags the code by even one version is the
   kind of thing that ends a small publisher's credibility permanently.
3. **Never send extension IDs, findings, paths or file contents.** A count of scans, nothing
   describing what was scanned. The list of extensions someone has installed is itself
   sensitive: it identifies their stack, their employer's stack, and sometimes them.
4. **Self-host it.** Sending developer telemetry to a third-party endpoint is a supply-chain
   dependency inside a supply-chain security tool.

### The Team tier is a separate question

Phase 5's Team tier legitimately reports to a backend, because that is the feature: continuous
scanning with org-wide alerts is not deliverable without a server. That is honest, because the
customer is buying exactly that behaviour and knows it.

Keep the free tier clean and let the paid tier be the thing that talks to a server. That is a
much easier story to tell than a free tier that quietly measures its users.
