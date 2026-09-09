# Opt-in `Subject` prefix (e.g. `[dev]`), mailman3's `subject_prefix`.
#
# This is DKIM-*breaking* and off by default: unlike carriers' other transforms, which only
# prepend headers, rewriting the signed `Subject` header invalidates the author's original DKIM
# signature. It runs only for a list that sets `subject_prefix` (see `list::ListConfig`), and is
# meant to be paired with From/Reply-To munging (`fileinto "munge-from"`) so a post from a
# `p=reject`/`p=quarantine` domain still passes DMARC at the recipient via the list's own aligned
# identity rather than the author's now-broken one.
#
# The full rewritten value (`<prefix> <original subject>`, or just the prefix when the message had
# no `Subject`) is computed once in Rust — including the "don't stack the prefix on a reply that
# already has it" rule, which decides whether this script runs at all — and exposed here as
# `${env.vnd.carriers.subject}`. `deleteheader` then `addheader` replaces any existing `Subject`
# outright, matching how `munge-from.sieve` replaces `From`/`Reply-To`.

require ["editheader", "variables", "environment"];

deleteheader "Subject";
addheader "Subject" "${env.vnd.carriers.subject}";
