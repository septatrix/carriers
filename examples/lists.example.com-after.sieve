# Example per-domain "after" Sieve policy, scoped to lists whose posting address is under
# `lists.example.com` — see the README's "Global policy" section and `examples/carriers.toml`'s
# `[global_policy.domains."lists.example.com"]` table.
#
# Unlike the instance-wide `examples/global.sieve`/`examples/global-after.sieve`, this only runs
# for lists in that one domain, after that list's own `policy` has already decided (and after
# any instance-wide "before" script, but before the instance-wide "after" script). Domain scripts
# have no sibling-file auto-discovery — they must be listed explicitly in `carriers.toml`.

require ["envelope", "reject"];

# This domain requires a stricter compliance footer notice be present on every outgoing message;
# reject anything missing it rather than silently distributing a non-compliant post.
if not header :contains "X-Compliance-Ack" "yes" {
    reject "Messages to lists.example.com require compliance acknowledgement; contact the list owner.";
}
