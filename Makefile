CFLAGS += -Wall -static

ifeq ($(HAVE_LIBMOUNT),1)
CFLAGS += -DCHECKNS_HAVE_LIBMOUNT -lmount
endif

.PHONY: all clean

all: checkns

checkns: checkns.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f checkns
