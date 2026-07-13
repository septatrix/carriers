# Example global "before" Sieve drop-in — one file in the `global-before.d` directory (all its
# `*.sieve` files run in filename order). See the README's "Global policy" section and
# `examples/carriers.toml`'s `[global_policy]` table.
#
# This runs for every list, ahead of that list's own `policy`, so it can enforce rules that
# should apply everywhere while still seeing the current list's membership. An implicit keep
# (nothing matches) means "no opinion": the list's own policy still decides normally afterwards.
# Only an explicit `fileinto "moderate"`, `discard`, or `reject` here is authoritative and skips
# that list's own policy — there is no way for this script to force an *approval* that bypasses
# the list's own policy, only to hold/discard/reject ahead of it.

require ["envelope", "extlists", "fileinto", "reject"];

# A shared abuse blocklist, checked before any list-specific rule.
if address :is "from" "known-spammer@evil.example" {
    discard;
} elsif address :is "from" "banned@evil.example" {
    reject "This address is banned from posting to any list here.";
}
