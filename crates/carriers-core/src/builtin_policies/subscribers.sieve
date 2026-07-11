# Built-in policy: subscribers. Subscribers post directly; anyone else is held for moderation.
require ["extlists", "fileinto"];

if not address :list "from" "subscribers" {
    fileinto "moderate";
}
