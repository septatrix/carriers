# Built-in "after" gate: the last word before a message is signed and distributed.
#
# Re-checks the same condition as `dmarc-before.sieve` defensively — a message can sit held for
# moderation for a while, and the author domain's DNS state (or DMARC policy) may have changed
# between the original submission and a moderator's approval, so this independent verification
# must not assume the "before" gate's verdict still holds.
#
# For a message that still doesn't pass DMARC but whose domain does not request enforcement (no
# DMARC record published, or an explicit `p=none` — both collapse to `dmarc_policy = "none"`), the
# message is still distributed, but must never carry the list's own DKIM signature: an ARC seal
# alone truthfully records what was observed, without lending it the list's reputation.

require ["variables", "environment", "reject", "fileinto"];

if string :is "${env.vnd.carriers.dmarc_pass}" "no" {
    if not string :is "${env.vnd.carriers.dmarc_policy}" "none" {
        reject "This message failed DMARC and its domain requests enforcement on failure.";
    } else {
        fileinto "no-dkim";
    }
}
