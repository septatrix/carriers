# Built-in duplicate suppression (RFC 7352 "duplicate" extension). A message whose Message-ID
# this list has already seen is silently discarded. Messages without a Message-ID are never
# treated as duplicates (the `duplicate` test yields nothing to key on).
require ["duplicate"];

if duplicate {
    discard;
}
