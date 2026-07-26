# Example per-domain "after" Sieve drop-in, scoped to lists whose posting address is under
# `lists.example.com` — one file in that domain's `after` drop-in directory. See the README's
# "Global policy" section and `examples/carriers.toml`'s
# `[global_policy.domains."lists.example.com"]` table.
#
# Unlike the instance-wide `global-before.d`/`global-after.d`, this only runs for lists in that
# one domain, after that list's own `policy` has already decided (and after any instance-wide
# "before" drop-ins, but before the instance-wide "after" drop-ins). Domain drop-in directories
# have no sibling auto-discovery — they must be listed explicitly in `carriers.toml`.

require ["envelope", "reject"];

# This domain requires a stricter compliance footer notice be present on every outgoing message;
# reject anything missing it rather than silently distributing a non-compliant post.
if not header :contains "X-Compliance-Ack" "yes" {
    reject "Messages to lists.example.com require compliance acknowledgement; contact the list owner.";
}
