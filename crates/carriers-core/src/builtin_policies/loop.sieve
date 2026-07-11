# Built-in loop detection. A message that already carries this list's own List-Id has already
# been distributed through this list and is looping back, so it is silently discarded.
#
# The list's List-Id is exposed as the `vnd.carriers.list_id` environment variable; this is a
# header check, matching it against the incoming `List-Id` header.
require ["variables", "environment"];

if header :contains "List-Id" "${env.vnd.carriers.list_id}" {
    discard;
}
