# Built-in policy: moderated. Every post is held for moderation, regardless of sender.
require ["fileinto"];

fileinto "moderate";
