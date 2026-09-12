# Built-in bounce policy: what follows from a delivery failure for a subscriber.
#
# The message this script sees is the DSN itself, so it can be tested like any other message
# (`header`, `body`, `envelope`, …). What carriers already worked out about the bounce is in the
# `vnd.carriers.bounce_*` environment variables:
#
#   bounce_address         the subscriber the DSN is about
#   bounce_kind            "hard" (permanent, 5.x.x) or "soft" (transient, 4.x.x)
#   bounce_status          the DSN status it was classified from, e.g. "5.1.1"
#   bounce_score           the subscriber's running score, including this bounce
#   bounce_weight          what this bounce added to that score
#   bounce_threshold       the configured score at which delivery is meant to stop
#   bounce_over_threshold  "yes" if bounce_score has reached bounce_threshold
#   bounce_disabled        "yes" if delivery was already disabled before this bounce
#
# The score has already been recorded by the time this runs — this script decides only what
# *follows* from it, by calling one of the two primitives carriers exposes here:
#
#   disable_delivery()              stop delivering this list to bounce_address until an
#                                   operator runs `carriers member enable`
#   http_request(method, url, body) tell an external system; evaluates to the HTTP status code,
#                                   or 0 if the request could not be made at all
#
# A DSN is never distributed, held or refused, so ordinary Sieve actions (`keep`, `discard`,
# `reject`, `fileinto`) have nothing to act on in this tier and are ignored.
#
# This default reproduces carriers' historical hardcoded behaviour: disable delivery once the
# score reaches the threshold, and otherwise do nothing. A deployment where an external system
# owns subscription state will want something else entirely — report the bounce and change
# nothing locally — which is why a `bounce.sieve` in the Sieve root replaces this file rather
# than running alongside it.
#
# Two things to know when writing your own:
#
#   - Comparing an environment variable against a literal number in an expression compares them
#     numerically (`eval "env.vnd.carriers.bounce_score >= 10"`), but comparing two environment
#     variables against each other compares them as text. That is why the one comparison this
#     script needs, score against threshold, is precomputed as bounce_over_threshold above.
#   - `${...}` interpolation does not happen inside an expression: a quoted string in there is a
#     literal. Build a value with `set` first and pass the variable in bare:
#
#         set "body" "{\"address\": \"${env.vnd.carriers.bounce_address}\"}";
#         let "status" "http_request('POST', 'https://db.example.org/bounces', body)";

require ["variables", "environment", "vnd.stalwart.expressions"];

if string :is "${env.vnd.carriers.bounce_over_threshold}" "yes" {
    # An expression statement needs somewhere to put its value; the result (whether the address
    # was still a member) tells this script nothing it can act on.
    let "disabled" "disable_delivery()";
}
