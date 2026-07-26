# Built-in "before" gate: never distribute a message whose author domain requests DMARC
# enforcement (p=quarantine/reject) but which does not align. The verdict is computed once per
# message in Rust (see `sign::evaluate_dmarc`) and exposed here as `${env.vnd.carriers.*}`
# variables — a domain with no DMARC record at all, or an explicit `p=none`, both collapse to
# `dmarc_policy = "none"` and are left to the "after" gate (`dmarc-after.sieve`) to decide whether
# the list may still sign it with its own DKIM key.

require ["variables", "environment", "reject"];

if string :is "${env.vnd.carriers.dmarc_pass}" "no" {
    if not string :is "${env.vnd.carriers.dmarc_policy}" "none" {
        reject "This message failed DMARC and its domain requests enforcement on failure.";
    }
}
