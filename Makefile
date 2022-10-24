CONFIG_DEBUG=y

CC = gcc
FLAGS = -g

DPDK_PATH = /data/users/deeptir/dpdk
INC = -I$(DPDK_PATH)/build/include -I$(DPDK_PATH)/lib/ethdev
FLAGS += $(INC) -mssse3

ifeq ($(CONFIG_DEBUG),y)
FLAGS += -O0 -ggdb
else
FLAGS += -O3
endif

DPDK_LIBS= -L$(DPDK_PATH)/build/lib
DPDK_LIBS += -Wl,-whole-archive -Wl,-no-whole-archive
DPDK_LIBS += -lrte_mempool
DPDK_LIBS += -lrte_ring
DPDK_LIBS += -lrte_eal
DPDK_LIBS += -lrte_kvargs

net_src = $(wildcard ice/*.c)
net_obj = $(net_src:.c=.o)

ice_netperf: ice_netperf.o $(net_obj)
	$(CC) $(FLAGS) -o ice_netperf ice_netperf.c $(net_src) $(DPDK_LIBS) -lpthread -lnuma -ldl

src = ice_netperf.c $(net_src)
obj = $(src:.c=.o)

%.o: %.c
	$(CC) $(FLAGS) -c $< -o $@

clean:
	rm ice_netperf $(obj)
