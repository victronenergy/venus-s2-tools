FILES =									\
	s2-cem-cli.py						\
	s2-sniffer.py						\

all:

install:
	install -d $(DESTDIR)$(bindir)
	install -m 0644 $(FILES) $(DESTDIR)$(bindir)
	chmod +x $(addprefix $(DESTDIR)$(bindir)/,$(FILES))

testinstall:
	$(eval TMP := $(shell mktemp -d))
	$(MAKE) DESTDIR=$(TMP) install
	(cd $(TMP) && ./s2-cem-cli.py --help > /dev/null)
	(cd $(TMP) && ./s2-sniffer.py --help > /dev/null)
	-rm -rf $(TMP)

clean:

.PHONY: help install testinstall clean
