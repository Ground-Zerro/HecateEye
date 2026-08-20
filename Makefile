CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -std=gnu11
LDFLAGS ?= -lpthread

SRCS = main.c session.c ppp_mode.c relay.c netif.c wire.c
HEADERS = config.h util.h wire.h session.h ppp_hdlc.h ppp_mode.h relay.h netif.h log.h
TARGET ?= hecate-eye

.PHONY: all clean lint

all: $(TARGET)

lint:
	cppcheck --enable=warning,style,performance,portability --std=c11 \
	  --language=c --suppress=missingIncludeSystem \
	  --suppressions-list=.cppcheck-suppressions --error-exitcode=1 $(SRCS)

$(TARGET): $(SRCS) $(HEADERS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS) $(LDFLAGS)

clean:
	rm -f hecate-eye
