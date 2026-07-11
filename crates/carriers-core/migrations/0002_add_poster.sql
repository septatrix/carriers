-- A poster may post directly under the `posters` built-in policy (and is exposed to custom
-- Sieve policies as the `posters` external list), independent of whether they are subscribed.
-- Subscribers and posters are disjoint by default: subscribing does not imply posting rights,
-- and being a poster does not imply receiving the list.
ALTER TABLE members ADD COLUMN poster INTEGER NOT NULL DEFAULT 0;
