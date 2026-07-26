# From/Reply-To munging (mailman3's `munge_from` DMARC mitigation): rewrites `From` to the list's
# own posting address (embedding the original sender's name) and points `Reply-To` back at the
# original sender, so replies still reach the human rather than just the list.
#
# This is an available mechanism, not automatically triggered by anything built-in today: a custom
# before/after drop-in can request it by filing into the `munge-from` pseudo-mailbox (e.g. for a
# future DKIM-breaking transform like a footer or Subject prefix, where preserving the author's
# original identity is no longer possible anyway). The values are computed once in Rust (see
# `transform::munge_from_env`) and exposed here as `${env.vnd.carriers.*}` variables; any
# pre-existing `From`/`Reply-To` is replaced outright, not merged.

require ["editheader", "variables", "environment"];

deleteheader "From";
addheader "From" "${env.vnd.carriers.munge_from}";
deleteheader "Reply-To";
addheader "Reply-To" "${env.vnd.carriers.reply_to}";
