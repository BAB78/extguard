# LinkedIn

Reddit is not available, so this replaces r/vscode. Different audience and different rules.

**Format rules that decide whether this works:**

- The first two lines are all anyone sees before "see more". They decide everything.
- **Put the link in the first comment, not the post.** LinkedIn demotes posts with external
  links, sometimes heavily.
- Around 200 words. Line breaks between nearly every sentence, because most reads are on a phone.
- Attach an image. Image posts get materially more reach than text alone.
- Three to five hashtags. More reads as spam.

---

## Post

My editor runs 82 extensions. I had read the source of none of them.

That is not laziness, it is the normal state of every developer I know.

Here is the part I had not thought about properly: VS Code has no permission model. Any
extension you install runs as ordinary Node.js with the full reach of your user account. Your
files, your SSH keys, your environment variables, your terminal.

There is no prompt. There is no sandbox. There is no list of what it asked for, because it did
not have to ask.

Between 2024 and 2026, researchers found over 1,200 extensions on the official Marketplace
carrying confirmed malicious code, together reaching hundreds of millions of installs.

So I built ExtGuard, a free extension that audits the ones you already have. It checks them
against 1,981 known-malicious records, looks for hardcoded credentials in the shipped
code, and reports what each one can actually reach.

The hard part was not detection. My first version flagged 57 of my 82 extensions, which makes a
security tool worse than useless: you learn to ignore it, and then you ignore the one that
mattered. The current build flags none of them, and I trust it more for that.

Everything runs locally. Nothing is uploaded.

Free and open source. Link in the comments.

#softwaredevelopment #cybersecurity #vscode #developertools

---

## First comment, posted immediately after

Marketplace: https://marketplace.visualstudio.com/items?itemName=babstudios.extguard-security

Source, and the write-up of how the false-positive rate went from 57 of 82 extensions to zero:
https://github.com/BAB78/extguard

Works with VS Code, Cursor and Windsurf.

---

## Image to attach

A screenshot of the ExtGuard sidebar mid-scan, showing a mix of green rows and one expanded
extension with its findings. Include green rows. A screenshot showing only problems looks like
every other security ad, and the entire argument of the post is that it does not flag
everything.

If you want a second image, the capability row is the one worth showing: Jupyter or PowerShell
displaying `Capability: risky-code-execution` with a lightbulb rather than a warning.

---

## Notes

**Reply to every comment for the first few hours.** LinkedIn's ranking is driven by early
engagement more than almost any other platform. Ten replies in the first hour beats a hundred
views on day three.

**Be honest about the audience.** LinkedIn is mostly recruiters, founders and business contacts
rather than the developers this is built for. The realistic return is credibility with people
who already know you. Installs are a bonus, and the Show HN post is the one aimed at people who
will actually use it.

**Do not post both on the same day.** Space Show HN and LinkedIn by two or three days, and lead
with Show HN, because that audience will find the false-positive story genuinely interesting
and their reaction is worth having before a wider one.
