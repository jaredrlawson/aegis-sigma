CC ?= gcc
CXX ?= g++
CFLAGS ?= -O2 -Wall -Wextra -pthread
SRC := shield_soul.c model.c spiral.c groq_teacher.c
HEADERS := shield_soul.h model.h spiral.h groq_teacher.h
TARGET := aegis-shield-soul

# Optional LightGBM native C API support (requires liblightgbm-dev installed).
# Toggle with: make USE_LIGHTGBM=1
ifdef USE_LIGHTGBM
    CFLAGS  += -DAEGIS_USE_LIGHTGBM
    LDLIBS  += -llightgbm
    COMPILER := $(CXX)
else
    COMPILER := $(CC)
endif

LDLIBS += -lm -lcjson -lpthread

.PHONY: all clean install

all: $(TARGET)

$(TARGET): $(SRC) $(HEADERS)
	$(COMPILER) $(CFLAGS) -o $(TARGET) $(SRC) $(LDLIBS)

clean:
	rm -f $(TARGET)

# Build + system install under /usr/local (idempotent).
install: all
	install -d /usr/local/bin /var/lib/aegis-shield-soul
	install -m 0755 $(TARGET) /usr/local/bin/$(TARGET)
	@if [ -f models/shield.txt ]; then install -m 0644 models/shield.txt /var/lib/aegis-shield-soul/; fi
	@if [ -f models/soul.json ]; then install -m 0644 models/soul.json /var/lib/aegis-shield-soul/; fi
	@if [ -f models/metrics.json ]; then install -m 0644 models/metrics.json /var/lib/aegis-shield-soul/; fi
