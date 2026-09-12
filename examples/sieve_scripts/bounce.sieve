# Example bounce script — `bounce.sieve` in the Sieve root *replaces* the built-in one (unlike
# the `.d` drop-in directories, which add to what is already there). See the README's "Bounce
# handling" section.
#
# This is the shape a deployment whose subscription state lives somewhere else needs: carriers
# reports every bounce to that system and changes nothing locally, leaving it to decide whether
# a subscription should end. Note what is *missing* compared to the built-in script — there is
# no `disable_delivery()` call anywhere, so a bouncing address keeps receiving list mail until
# the external system says otherwise.
#
# The message here is the DSN itself, so ordinary Sieve tests apply to it; everything carriers
# worked out about the bounce is in `${env.vnd.carriers.bounce_*}` (see the built-in
# `bounce.sieve` for the full list).

require ["variables", "environment", "ihave", "vnd.stalwart.expressions"];

# `${...}` interpolation happens in `set`, not inside an expression — so build the body first
# and hand the expression the variable.
set "body" "{\"list\": \"${env.vnd.carriers.list}\", \"address\": \"${env.vnd.carriers.bounce_address}\", \"message_id\": \"${env.vnd.carriers.bounce_message_id}\", \"kind\": \"${env.vnd.carriers.bounce_kind}\", \"status\": \"${env.vnd.carriers.bounce_status}\", \"score\": ${env.vnd.carriers.bounce_score}}";

let "status" "http_request('POST', 'https://db.example.org/api/mailinglist/bounce', body)";

# `http_request` reports the HTTP status it got, or 0 if the request could not be made at all, so
# a bounce that could not be reported can be escalated rather than lost. `error` aborts the
# script and fails the DSN's SMTP transaction, which leaves the sending MTA to retry it later.
# Note that a retried DSN is scored again — carriers records the bounce before this script runs,
# so escalating this way trades a slightly inflated score for not losing the report.
if eval "status == 0 || status >= 500" {
    error "Could not report the bounce to the member database.";
}
