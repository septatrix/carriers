# Opt-in `Subject` prefix, mailman3's `subject_prefix`. The list configures a bare tag (e.g. `dev`)
# and this script wraps it in square brackets, so a distributed post's `Subject` reads `[dev] ...`.
#
# This is DKIM-*breaking* and off by default: unlike carriers' other transforms, which only
# prepend headers, rewriting the signed `Subject` header invalidates the author's original DKIM
# signature. It runs only for a list that sets `subject_prefix` (see `list::ListConfig`), and is
# meant to be paired with From/Reply-To munging (`fileinto "munge-from"`) so a post from a
# `p=reject`/`p=quarantine` domain still passes DMARC at the recipient via the list's own aligned
# identity rather than the author's now-broken one.
#
# Unlike `munge-from.sieve` (which reformats a parsed address) or `list-headers.sieve` (config-
# derived URLs), the whole transform is expressible in Sieve: the only value carriers supplies is
# the bare tag, as `${env.vnd.carriers.subject_prefix}`. The script captures the current `Subject`
# with a `:matches "*"` wildcard and re-`addheader`s it behind the bracketed tag. A `Subject` that
# already carries the bracketed tag at the front is left untouched, so the prefix is never stacked.

require ["editheader", "variables", "environment"];

# Already prefixed at the front: leave the message exactly as-is. The tag counts as "at the front"
# either at the very start of the `Subject`, or right after a run of reply/forward markers —
# anything ending in a colon-space, e.g. `Re: `, `Fwd: `, `Re: Fwd: `. It deliberately does *not*
# match the tag appearing arbitrarily later in the `Subject` (that is treated as ordinary text and
# still gets prefixed), so a genuine `[dev]` mid-subject isn't mistaken for the list prefix.
if anyof(
    header :matches "Subject" "[${env.vnd.carriers.subject_prefix}]*",
    header :matches "Subject" "*: [${env.vnd.carriers.subject_prefix}]*"
) {
    stop;
}

if header :matches "Subject" "*" {
    # A `Subject` header is present (possibly empty): keep its text behind the bracketed tag.
    set "subject" "${1}";
    deleteheader "Subject";
    addheader "Subject" "[${env.vnd.carriers.subject_prefix}] ${subject}";
} else {
    # No `Subject` header at all — it is optional in RFC 5322, and list posts do arrive without one.
    # The bracketed tag becomes the whole `Subject`.
    addheader "Subject" "[${env.vnd.carriers.subject_prefix}]";
}
