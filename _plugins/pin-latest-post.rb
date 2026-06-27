#!/usr/bin/env ruby
#
# Automatically pin the single most recent post.
#
# Runs once after all posts are read. The newest post (by date) gets
# pin = true; every other post is forced to pin = false, so exactly one
# post is featured on the home page regardless of any manual `pin:`
# front matter.

Jekyll::Hooks.register :site, :post_read do |site|
  posts = site.posts.docs
  next if posts.empty?

  latest = posts.max_by { |post| post.date }
  posts.each { |post| post.data['pin'] = post.equal?(latest) }

  Jekyll.logger.info "PinLatest:", "pinned => #{latest.data['title']} (#{latest.date})"
end
