# Example carriers moderation policy.
#
# Decisions are signalled with ordinary Sieve actions:
#   keep;                    -> approve (distribute now)   [also the default if nothing runs]
#   fileinto "moderate";     -> hold the post for moderation
#   discard;                 -> silently drop the post, no reply to the sender
#   reject "some reason";    -> refuse the post; the sender is told why
#
# Membership is exposed as external lists, resolved against the current mailing list. These are
# independent flags, not a hierarchy: a subscriber is not automatically a poster, and vice versa.
#   "subscribers"  addresses that receive the list
#   "posters"      addresses that may post directly, independent of subscription
#   "moderators"   addresses flagged as moderators
#
# The current list's short name is available as the environment variable
# "vnd.carriers.list" (requires the "environment" extension).

require ["envelope", "extlists", "fileinto", "reject"];

# Moderators and subscribers post directly; posters (who may not be subscribed) are moderated;
# everyone else is rejected and told why, so a legitimate sender knows to subscribe.
if anyof(address :list "from" "moderators", address :list "from" "subscribers") {
    keep;
} elsif address :list "from" "posters" {
    fileinto "moderate";
} else {
    reject "Only subscribers and approved posters may write to this list.";
}
