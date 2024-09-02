CONTIKI_PROJECT = sender
all: $(CONTIKI_PROJECT)

#PROJECT_SOURCEFILES += utils.c
CFLAGS += -std=gnu99

CONTIKI = ../

TARGET=z1

PLATFORMS_EXCLUDE = nrf52dk
LDLIBS += -lcontiki-net -lcontiki-lrplite -lclock


#use this to enable TSCH: MAKE_MAC = MAKE_MAC_TSCH
MAKE_MAC ?= MAKE_MAC_CSMA
MAKE_NET = MAKE_NET_NULLNET
include $(CONTIKI)/Makefile.include
