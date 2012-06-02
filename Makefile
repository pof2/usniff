CC ?= "gcc"

CFLAGS ?= -O2 -g
CFLAGS += -Wall -Wundef -Wstrict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common -Werror-implicit-function-declaration

OBJS = usniff.o wireless.o
ALL = usniff

LIBS = -lnl-genl -lnl

all: $(ALL)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

usniff:	$(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) $(LIBS) -o usniff

clean:
	$(Q)rm -f usniff *.o *~ *.gz *-stamp

install:
	cp usniff /usr/bin/
	chmod a+s /usr/bin/usniff

