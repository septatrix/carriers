# Built-in List-* header injection (RFC 2369 + RFC 8058), replacing a hand-rolled byte-prepend.
#
# Each header's value is supplied as an environment variable (empty when the list has no value
# for it). `addheader` inserts at the top of the header block, so the original headers and body
# are untouched and the author's DKIM signature stays valid. The statements run from the last
# header up to the first so the output keeps the usual List-Id, List-Post, List-Help, … order.
require ["editheader", "variables", "environment"];

if not string :is "${env.vnd.carriers.hdr_list_owner}" "" {
    addheader "List-Owner" "${env.vnd.carriers.hdr_list_owner}";
}
if not string :is "${env.vnd.carriers.hdr_list_archive}" "" {
    addheader "List-Archive" "${env.vnd.carriers.hdr_list_archive}";
}
if not string :is "${env.vnd.carriers.hdr_list_unsubscribe_post}" "" {
    addheader "List-Unsubscribe-Post" "${env.vnd.carriers.hdr_list_unsubscribe_post}";
}
if not string :is "${env.vnd.carriers.hdr_list_unsubscribe}" "" {
    addheader "List-Unsubscribe" "${env.vnd.carriers.hdr_list_unsubscribe}";
}
if not string :is "${env.vnd.carriers.hdr_list_subscribe}" "" {
    addheader "List-Subscribe" "${env.vnd.carriers.hdr_list_subscribe}";
}
if not string :is "${env.vnd.carriers.hdr_list_help}" "" {
    addheader "List-Help" "${env.vnd.carriers.hdr_list_help}";
}
addheader "List-Post" "${env.vnd.carriers.hdr_list_post}";
addheader "List-Id" "${env.vnd.carriers.hdr_list_id}";
