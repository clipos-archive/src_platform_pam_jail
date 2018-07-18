# SPDX-License-Identifier: GPL-2.0
# Copyright © 2007-2018 ANSSI. All Rights Reserved.

CC := gcc
CFLAGS := $(CFLAGS) -Wall -Werror 

PAM := pam_jail.so
MANFILE := pam_jail.8

all: $(PAM) $(MANFILE)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

%.so: %.o
	$(CC) -shared $(LDFLAGS) -o $@ $< -lc -lpam -lutil -lclipvserver -ldl

%.8: %.pod
	pod2man -c="CLIP Utilities" -s=8 -r=CLIP $< > $@

clean:
	$(RM) *.o $(PAM) $(MANFILE)

install: $(OUT)
	install -D -o0 -g0 -m755 $(PAM) $(PAMDIR)/$(PAM)
	install -D -o0 -g0 -m755 $(MANFILE) $(MANDIR)/man8/$(MANFILE)

