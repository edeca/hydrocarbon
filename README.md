# Introduction

TODO

# FAQ

## How can I delete indicators?

The Carbon Black Response server prefers to do an 'incremental' sync against feeds.  This means that deleted items will not be removed.

To delete an item change `enabled` to `False` and regenerate the feed.
