# Built-in policy: posters. Posters post directly, independent of subscription; anyone else is
# held for moderation.
require ["extlists", "fileinto"];

if not address :list "from" "posters" {
    fileinto "moderate";
}
