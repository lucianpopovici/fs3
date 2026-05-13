# fs3 — Phase 2 build (llhttp + filesystem store + extended XML)
#
# Targets:
#   make              build ./fs3
#   make DEBUG=1      build with -O0 + ASan + UBSan
#   make clean        remove all build artifacts
#   make test         build and run all test binaries
#   make smoketest    runs ./fs3 briefly and probes with curl
#   make fetch-llhttp re-fetch llhttp sources (requires pip + network)

CC      ?= gcc
CFLAGS  := -std=c11 -O2 -g -Wall -Wextra -Wpedantic \
           -Wshadow -Wstrict-prototypes -Wmissing-prototypes \
           -Wno-unused-parameter \
           -D_GNU_SOURCE -fstack-protector-strong \
           -MMD -MP
LDFLAGS := -lcrypto

ifeq ($(DEBUG),1)
  CFLAGS  := $(filter-out -O2,$(CFLAGS)) -O0 \
             -fsanitize=address,undefined -fno-omit-frame-pointer
  LDFLAGS += -fsanitize=address,undefined
endif

# llhttp lives under third_party/llhttp/
LLHTTP_DIR := third_party/llhttp
XML_DIR    := third_party/xml
INCLUDES   := -Iinclude -I$(LLHTTP_DIR)/include -I$(XML_DIR)

# Server objects
SRV_SRCS := src/main.c src/server.c src/conn.c src/log.c src/store_fs.c \
            src/route.c src/response.c src/sigv4.c
SRV_OBJS := $(SRV_SRCS:.c=.o)

LLHTTP_OBJS := $(LLHTTP_DIR)/src/api.o $(LLHTTP_DIR)/src/http.o \
               $(LLHTTP_DIR)/src/llhttp.o
XML_OBJS    := $(XML_DIR)/xml_parser.o

OBJS := $(SRV_OBJS) $(LLHTTP_OBJS) $(XML_OBJS)

# llhttp's generated state machine has a few diagnostic noise warnings;
# build it with relaxed warnings while keeping our code strict.
LLHTTP_CFLAGS := -std=c11 -O2 -g -Wall -D_GNU_SOURCE -MMD -MP
ifeq ($(DEBUG),1)
  LLHTTP_CFLAGS := $(filter-out -O2,$(LLHTTP_CFLAGS)) -O0 \
                   -fsanitize=address,undefined -fno-omit-frame-pointer
endif

all: fs3

fs3: $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

# Our code: strict warnings
src/%.o: src/%.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Vendored llhttp: relaxed warnings
$(LLHTTP_DIR)/src/%.o: $(LLHTTP_DIR)/src/%.c
	$(CC) $(LLHTTP_CFLAGS) $(INCLUDES) -c $< -o $@

# XML library: same flags as our code
$(XML_DIR)/%.o: $(XML_DIR)/%.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# ----- Tests --------------------------------------------------------

TEST_BINS := tests/test_store tests/test_xml tests/test_xml_legacy tests/test_xml_fuzz tests/test_sigv4

test: $(TEST_BINS) fs3
	@echo "=== test_store ==="
	@./tests/test_store
	@echo "=== test_xml ==="
	@./tests/test_xml
	@echo "=== test_xml_legacy ==="
	@./tests/test_xml_legacy
	@echo "=== test_xml_fuzz (50000 iterations) ==="
	@./tests/test_xml_fuzz 50000
	@echo "=== test_sigv4 ==="
	@./tests/test_sigv4
	@echo "=== test_e2e (HTTP integration) ==="
	@./tests/test_e2e.sh
	@echo "=== test_e2e_auth (SigV4 integration) ==="
	@./tests/test_e2e_auth.sh
	@echo "=== test_e2e_mpu (multipart integration) ==="
	@./tests/test_e2e_mpu.sh
	@echo "=== test_e2e_phase9 (range / bulk-delete / bucket-subresources) ==="
	@./tests/test_e2e_phase9.sh
	@echo "=== test_e2e_phase10 (object copy / ?acl stub) ==="
	@./tests/test_e2e_phase10.sh

tests/test_store: tests/test_store.c src/store_fs.o src/log.o
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_store.c \
	    src/store_fs.o src/log.o $(LDFLAGS) -o $@

tests/test_xml: $(XML_DIR)/tests/test_xml.c $(XML_DIR)/xml_parser.o
	$(CC) $(CFLAGS) $(INCLUDES) $(XML_DIR)/tests/test_xml.c \
	    $(XML_DIR)/xml_parser.o $(LDFLAGS) -o $@

tests/test_xml_legacy: $(XML_DIR)/tests/test_legacy.c $(XML_DIR)/xml_parser.o
	$(CC) $(CFLAGS) $(INCLUDES) $(XML_DIR)/tests/test_legacy.c \
	    $(XML_DIR)/xml_parser.o $(LDFLAGS) -o $@

tests/test_xml_fuzz: $(XML_DIR)/tests/test_fuzz.c $(XML_DIR)/xml_parser.o
	$(CC) $(CFLAGS) $(INCLUDES) $(XML_DIR)/tests/test_fuzz.c \
	    $(XML_DIR)/xml_parser.o $(LDFLAGS) -o $@

# test_sigv4 needs the SIGV4_TESTING macro to expose internal helpers,
# so we recompile sigv4.c instead of using the cached .o from the
# server build.
tests/test_sigv4: tests/test_sigv4.c src/sigv4.c
	$(CC) $(CFLAGS) $(INCLUDES) -DSIGV4_TESTING tests/test_sigv4.c src/sigv4.c \
	    $(LDFLAGS) -o $@

clean:
	rm -f fs3 $(OBJS) $(OBJS:.o=.d) $(TEST_BINS) tests/*.d

# Auto-include compiler-generated dependency files so header changes
# correctly invalidate object files. Created via -MMD -MP above.
-include $(OBJS:.o=.d)

# Re-fetch llhttp from the httptools sdist on PyPI. The httptools project
# vendors a stable release of llhttp's generated C output, which is what
# we want — building llhttp from its own repo requires Node.js + a code
# generator. PyPI is a much simpler dependency.
fetch-llhttp:
	@set -e; \
	tmp=$$(mktemp -d); \
	echo "Downloading httptools sdist into $$tmp"; \
	(cd $$tmp && pip download --no-binary :all: --no-deps httptools >/dev/null); \
	tarball=$$(ls $$tmp/httptools-*.tar.gz); \
	echo "Extracting llhttp sources from $$tarball"; \
	tar -C $$tmp -xzf $$tarball; \
	srcdir=$$(ls -d $$tmp/httptools-*/vendor/llhttp); \
	mkdir -p $(LLHTTP_DIR)/include $(LLHTTP_DIR)/src; \
	cp $$srcdir/include/llhttp.h $(LLHTTP_DIR)/include/; \
	cp $$srcdir/src/api.c        $(LLHTTP_DIR)/src/; \
	cp $$srcdir/src/http.c       $(LLHTTP_DIR)/src/; \
	cp $$srcdir/src/llhttp.c     $(LLHTTP_DIR)/src/; \
	rm -rf $$tmp; \
	grep -E "VERSION_(MAJOR|MINOR|PATCH)" $(LLHTTP_DIR)/include/llhttp.h | head -3; \
	echo "OK"

smoketest: fs3
	@./fs3 -p 19000 -v & echo $$! > /tmp/fs3.pid; \
	sleep 0.3; \
	echo "--- GET /foo/bar ---"; \
	curl -sS -i http://127.0.0.1:19000/foo/bar?x=1 || true; \
	echo "--- PUT /b/k (32 bytes) ---"; \
	head -c 32 /dev/urandom | curl -sS -i -X PUT --data-binary @- \
	    http://127.0.0.1:19000/b/k || true; \
	kill `cat /tmp/fs3.pid` 2>/dev/null; rm -f /tmp/fs3.pid

.PHONY: all clean test smoketest fetch-llhttp
