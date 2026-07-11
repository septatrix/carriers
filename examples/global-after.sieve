# Example global "after" Sieve policy — see the README's "Global policy" section and
# `examples/carriers.toml`'s `[global_policy]` table.
#
# This runs for every list, after that list's own `policy` has already decided. It's the
# last-word tier: it still gets a chance to run even if the list's own policy (or an earlier
# "before" script) already decided to hold the message for moderation, and can tighten that hold
# further — e.g. escalating it to an outright reject — but it can never turn a hold or a reject
# back into an approval.

require ["envelope", "reject"];

# Escalate anything already flagged as suspicious by an upstream spam filter, regardless of what
# the list's own policy decided.
if header :contains "X-Spam-Flag" "YES" {
    reject "This message was flagged as spam and is rejected instance-wide.";
}
