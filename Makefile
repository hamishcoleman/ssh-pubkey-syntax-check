
NAME := ssh_known_hosts_checker
INSTALLROOT := installdir
INSTALLBIN := $(INSTALLROOT)/usr/local/bin
INSTALLLIB := $(INSTALLROOT)/usr/local/lib/site_perl

describe := $(shell git describe --always --dirty)
tarfile := $(NAME)-$(describe).tar.gz

all: test

build_dep:
	aptitude install perl libdevel-cover-perl

install: clean
	mkdir -p $(INSTALLBIN)
	cp -pr check_syntax_ssh_known_hosts $(INSTALLBIN)
	cp -pr check_syntax_ssh_authorized_keys $(INSTALLBIN)

tar: $(tarfile)

$(tarfile):
	$(MAKE) install
	tar -v -c -z -C $(INSTALLROOT) -f $(tarfile) .

clean:
	rm -rf $(INSTALLROOT)

cover:
	cover -delete
	-COVER=true $(MAKE) test
	cover

test:
	./test_harness
	./check_syntax_ssh_known_hosts test.known_hosts.good
	./check_syntax_ssh_authorized_keys test.authorized_keys.good
	! ./check_syntax_ssh_known_hosts test.known_hosts.bad
	! ./check_syntax_ssh_authorized_keys test.authorized_keys.bad

