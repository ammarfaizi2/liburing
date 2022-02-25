#!/bin/sh

git status > /tmp/status.log;

(grep "nothing to commit, working tree clean" /tmp/status.log >> /dev/null) && \
exit 0 || \
(
	echo "git status is dirty, maybe something needs to be added to .gitignore?"; \
	cat /tmp/status.log; \
	exit 1
);
