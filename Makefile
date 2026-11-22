# fs3 build
#
# Targets:
#   make                  build fs3, fs3-lockd and fs3-dedup-estimate
#   make DEBUG=1          -O0 + ASan + UBSan (switching needs `make clean`)
#   make TLS=1            fs3 with native TLS (libssl); `make fs3-tls` for a separate binary
#   make *-static         static binaries for the Synology package
#   make test             unit, fuzz and e2e suites (checks test deps first)
#   make smoketest        run ./fs3 briefly and probe it with curl
#   make seccomp-profile  diff the syscalls the suites use against the allowlist
#   make clean            remove all build artifacts
#   make fetch-llhttp     re-fetch llhttp sources (requires pip + network)

CC      ?= gcc
CFLAGS  := -std=c11 -O2 -g -Wall -Wextra -Wpedantic \
           -Wshadow -Wstrict-prototypes -Wmissing-prototypes \
           -Wno-unused-parameter \
           -D_GNU_SOURCE -fstack-protector-strong -pthread \
           -fPIE -D_FORTIFY_SOURCE=2 \
           -MMD -MP
LDFLAGS := -lcrypto -pthread -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack

# make TLS=1: native TLS listener (links libssl). Switching TLS on/off
# needs `make clean`, like DEBUG.
ifeq ($(TLS),1)
  CFLAGS  += -DFS3_TLS
  LDFLAGS := -lssl $(LDFLAGS)
endif

ifeq ($(DEBUG),1)
  CFLAGS  := $(filter-out -O2 -D_FORTIFY_SOURCE=2,$(CFLAGS)) -O0 \
             -fsanitize=address,undefined -fno-omit-frame-pointer
  LDFLAGS += -fsanitize=address,undefined
endif

# llhttp lives under third_party/llhttp/
LLHTTP_DIR := third_party/llhttp
XML_DIR    := third_party/xml
INCLUDES   := -Iinclude -I$(LLHTTP_DIR)/include -I$(XML_DIR)

# Server objects
SRV_SRCS := src/main.c src/server.c src/conn.c src/log.c src/store_fs.c \
            src/route.c src/response.c src/sigv4.c src/metrics.c \
            src/iopool.c src/action.c src/checksum.c src/query.c src/cors.c src/lifecycle.c src/website.c src/json.c src/admin.c src/policy.c src/objlock.c src/tls.c src/audit.c src/objmeta.c src/scrub.c src/sandbox.c src/ssec.c src/lockc.c src/s3client.c
SRV_OBJS := $(SRV_SRCS:.c=.o)

LLHTTP_OBJS := $(LLHTTP_DIR)/src/api.o $(LLHTTP_DIR)/src/http.o \
               $(LLHTTP_DIR)/src/llhttp.o
XML_OBJS    := $(XML_DIR)/xml_parser.o

OBJS := $(SRV_OBJS) $(LLHTTP_OBJS) $(XML_OBJS)

# llhttp's generated state machine has a few diagnostic noise warnings;
# build it with relaxed warnings while keeping our code strict.
LLHTTP_CFLAGS := -std=c11 -O2 -g -Wall -D_GNU_SOURCE -fPIE -MMD -MP
ifeq ($(DEBUG),1)
  LLHTTP_CFLAGS := $(filter-out -O2,$(LLHTTP_CFLAGS)) -O0 \
                   -fsanitize=address,undefined -fno-omit-frame-pointer
endif

all: fs3 fs3-lockd fs3-dedup-estimate

fs3: $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

# Statically-linked-libcrypto build for portable deployment (e.g. the
# Synology SPK). glibc stays dynamic — DSM provides a recent glibc, and
# fully-static glibc has NSS/DNS pitfalls. Only libcrypto is pinned in,
# which is the one ABI that varies across DSM versions.
fs3-static: $(OBJS)
	$(CC) $(OBJS) -o $@ -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack \
	    -Wl,-Bstatic -l:libcrypto.a -Wl,-Bdynamic -lpthread -ldl
	strip $@

# TLS-enabled binary built in one compiler invocation (no .o reuse), so
# the TLS e2e suite never mixes FS3_TLS and non-TLS objects.
ALL_C_SRCS := $(SRV_SRCS) $(LLHTTP_OBJS:.o=.c) $(XML_OBJS:.o=.c)
comma := ,
TLS_SAN := $(if $(filter 1,$(DEBUG)),-O0 -fsanitize=address$(comma)undefined -fno-omit-frame-pointer,-O2)
fs3-tls: $(ALL_C_SRCS) $(wildcard include/*.h)
	$(CC) $(filter-out -MMD -MP,$(CFLAGS)) -DFS3_TLS $(INCLUDES) -fsyntax-only src/tls.c src/conn.c src/server.c
	$(CC) -std=c11 -g -D_GNU_SOURCE -DFS3_TLS -pthread $(TLS_SAN) $(INCLUDES) \
	    $(ALL_C_SRCS) -o $@ -lssl -lcrypto -pthread

# TLS binary for the Synology package / NAS testing: libssl + libcrypto
# linked statically (DSM's own libssl is a different version), glibc
# dynamic like fs3-static. Point C_INCLUDE_PATH / LIBRARY_PATH at a
# static OpenSSL build when the host has none (see
# docs/AGENT-BUILD-AND-DS1515-TEST.md).
fs3-tls-static: $(ALL_C_SRCS) $(wildcard include/*.h)
	$(CC) -std=c11 -O2 -g -D_GNU_SOURCE -DFS3_TLS -pthread -fPIE -fstack-protector-strong \
	    -D_FORTIFY_SOURCE=2 $(INCLUDES) $(ALL_C_SRCS) -o $@ -pie -Wl,-z,relro,-z,now \
	    -Wl,-z,noexecstack -Wl,-Bstatic -l:libssl.a -l:libcrypto.a -Wl,-Bdynamic -lpthread -ldl
	strip $@

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

TEST_BINS := tests/test_log tests/test_ssec tests/test_sandbox tests/test_objmeta tests/test_policy tests/test_json tests/test_config_fuzz tests/test_chunk_fuzz tests/test_checksum tests/test_store tests/test_conn tests/test_xml tests/test_xml_legacy tests/test_xml_fuzz tests/test_sigv4 tests/test_credfile

# Fail fast, with the install line, if a test dependency is missing —
# otherwise e.g. a missing awscrt shows up as checksum "server bugs".
check-test-deps:
	@python3 -c "import botocore, boto3, awscrt" 2>/dev/null || { \
	    echo "missing Python test deps: pip install -r tests/requirements.txt" >&2; exit 1; }
	@for t in aws curl openssl; do command -v $$t >/dev/null || { \
	    echo "missing tool '$$t' (aws: pip install -r tests/requirements.txt; curl/openssl: apt-get install curl openssl)" >&2; \
	    exit 1; }; done

test: check-test-deps $(TEST_BINS) fs3 fs3-lockd fs3-dedup-estimate
	@echo "=== test_policy (+50000 fuzz iterations) ==="
	@./tests/test_policy 50000
	@echo "=== test_json (+50000 fuzz iterations) ==="
	@./tests/test_json 50000
	@echo "=== test_config_fuzz (50000 iterations) ==="
	@./tests/test_config_fuzz 50000
	@echo "=== test_chunk_fuzz (50000 iterations) ==="
	@./tests/test_chunk_fuzz 50000
	@echo "=== test_ssec (+50000 fuzz iterations) ==="
	@./tests/test_ssec 50000
	@echo "=== test_sandbox (seccomp filter) ==="
	@./tests/test_sandbox
	@echo "=== test_log (rotated log files) ==="
	@./tests/test_log
	@echo "=== test_objmeta (+50000 fuzz iterations) ==="
	@./tests/test_objmeta 50000
	@echo "=== test_checksum ==="
	@./tests/test_checksum
	@echo "=== test_store ==="
	@./tests/test_store
	@echo "=== test_conn ==="
	@./tests/test_conn
	@echo "=== test_xml ==="
	@./tests/test_xml
	@echo "=== test_xml_legacy ==="
	@./tests/test_xml_legacy
	@echo "=== test_xml_fuzz (50000 iterations) ==="
	@./tests/test_xml_fuzz 50000
	@echo "=== test_sigv4 ==="
	@./tests/test_sigv4
	@echo "=== test_credfile ==="
	@./tests/test_credfile 50000
	@echo "=== test_e2e (HTTP integration) ==="
	@./tests/test_e2e.sh
	@echo "=== test_e2e_auth (SigV4 integration) ==="
	@./tests/test_e2e_auth.sh
	@echo "=== test_e2e_mpu (multipart integration) ==="
	@./tests/test_e2e_mpu.sh
	@echo "=== test_e2e_parts (round 2: part records, ListParts, UploadPartCopy) ==="
	@./tests/test_e2e_parts.sh
	@echo "=== test_e2e_metadata (round 2: user metadata, std headers, response-*) ==="
	@./tests/test_e2e_metadata.sh
	@echo "=== test_e2e_listing (round 2: ListObjectsV2 / ListMultipartUploads pagination) ==="
	@./tests/test_e2e_listing.sh
	@echo "=== test_e2e_quota (round 2: bucket/user quotas) ==="
	@./tests/test_e2e_quota.sh
	@echo "=== test_e2e_s3client (outbound S3 client for replication) ==="
	@./tests/test_e2e_s3client.sh
	@echo "=== test_e2e_logs (log file rotation) ==="
	@./tests/test_e2e_logs.sh
	@echo "=== test_e2e_dedup_estimate (fs3-dedup-estimate) ==="
	@./tests/test_e2e_dedup_estimate.sh
	@echo "=== test_e2e_scrub (round 2: integrity scrub) ==="
	@./tests/test_e2e_scrub.sh
	@echo "=== test_e2e_keys (round 2: key expiry / disable / read-only / last-used) ==="
	@./tests/test_e2e_keys.sh
	@echo "=== test_e2e_reflink (round 2: reflink fast paths; needs FS3_REFLINK_DIR) ==="
	@./tests/test_e2e_reflink.sh
	@echo "=== test_e2e_ssec (round 2: SSE-C over TLS) ==="
	@./tests/test_e2e_ssec.sh
	@echo "=== test_e2e_immutable (round 2: layout 2 + fs3-lockd; needs root) ==="
	@./tests/test_e2e_immutable.sh
	@echo "=== test_e2e_phase9 (range / bulk-delete / bucket-subresources) ==="
	@./tests/test_e2e_phase9.sh
	@echo "=== test_e2e_phase10 (object copy / ?acl stub) ==="
	@./tests/test_e2e_phase10.sh
	@echo "=== test_e2e_phase11 (health endpoint / credentials file / disk quota) ==="
	@./tests/test_e2e_phase11.sh
	@echo "=== test_e2e_phase12 (recovery / body cap / idle timeout / conn cap) ==="
	@./tests/test_e2e_phase12.sh
	@echo "=== test_e2e_isolation (per-user bucket ownership) ==="
	@./tests/test_e2e_isolation.sh
	@echo "=== test_e2e_subresources (S0: unimplemented subresources → 501) ==="
	@./tests/test_e2e_subresources.sh
	@echo "=== test_e2e_checksum (item 1: trailers + x-amz-checksum-*) ==="
	@./tests/test_e2e_checksum.sh
	@echo "=== test_e2e_audit (audit log + auth throttling) ==="
	@./tests/test_e2e_audit.sh
	@echo "=== test_e2e_tls (item 7: native TLS, fs3-tls build) ==="
	@./tests/test_e2e_tls.sh
	@echo "=== test_e2e_objlock (item 10: object lock) ==="
	@./tests/test_e2e_objlock.sh
	@echo "=== test_e2e_policy (item 9: bucket policies) ==="
	@./tests/test_e2e_policy.sh
	@echo "=== test_e2e_versioning (item 8: versioning) ==="
	@./tests/test_e2e_versioning.sh
	@echo "=== test_e2e_admin (item 11: admin API) ==="
	@./tests/test_e2e_admin.sh
	@echo "=== test_e2e_website (item 6: static websites) ==="
	@./tests/test_e2e_website.sh
	@echo "=== test_e2e_lifecycle (item 5: lifecycle) ==="
	@./tests/test_e2e_lifecycle.sh
	@echo "=== test_e2e_cors (item 4: CORS) ==="
	@./tests/test_e2e_cors.sh
	@echo "=== test_e2e_presign (item 2: presigned URLs) ==="
	@./tests/test_e2e_presign.sh
	@echo "=== test_ui_cgi (DSM tile admin console) ==="
	@./tests/test_ui_cgi.sh
	@echo "=== test_spk_scripts (package start script and watchdog) ==="
	@./tests/test_spk_scripts.sh

FUZZ_CFG_OBJS := src/cors.o src/lifecycle.o src/website.o src/store_fs.o src/ssec.o src/checksum.o src/log.o $(XML_OBJS)
tests/test_config_fuzz: tests/test_config_fuzz.c tests/fuzz_targets.h $(FUZZ_CFG_OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) -Itests tests/test_config_fuzz.c $(FUZZ_CFG_OBJS) \
	    $(LDFLAGS) -o $@

tests/test_policy: tests/test_policy.c src/policy.o src/json.o src/action.o
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_policy.c src/policy.o src/json.o src/action.o \
	    $(LDFLAGS) -o $@

tests/test_json: tests/test_json.c src/json.o
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_json.c src/json.o $(LDFLAGS) -o $@

tests/test_chunk_fuzz: tests/test_chunk_fuzz.c src/sigv4.o src/query.o src/log.o
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_chunk_fuzz.c src/sigv4.o \
	    src/query.o src/log.o $(LDFLAGS) -o $@

tests/test_ssec: tests/test_ssec.c src/ssec.o
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_ssec.c src/ssec.o $(LDFLAGS) -o $@

tests/test_log: tests/test_log.c src/log.o
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_log.c src/log.o $(LDFLAGS) -lpthread -o $@

tests/test_sandbox: tests/test_sandbox.c src/sandbox.o src/log.o
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_sandbox.c src/sandbox.o src/log.o $(LDFLAGS) -lpthread -o $@

tests/test_objmeta: tests/test_objmeta.c src/objmeta.o
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_objmeta.c src/objmeta.o $(LDFLAGS) -o $@

tests/test_checksum: tests/test_checksum.c src/checksum.o
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_checksum.c src/checksum.o \
	    $(LDFLAGS) -o $@

tests/test_store: tests/test_store.c src/store_fs.o src/ssec.o src/log.o src/checksum.o
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_store.c \
	    src/store_fs.o src/ssec.o src/log.o src/checksum.o $(LDFLAGS) -o $@

# Everything but main.o/server.o: conn.c pulls in routing, the store,
# SigV4, responses and metrics.
CONN_TEST_OBJS := $(filter-out src/main.o src/server.o,$(OBJS))
tests/test_conn: tests/test_conn.c $(CONN_TEST_OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) tests/test_conn.c \
	    $(CONN_TEST_OBJS) $(LDFLAGS) -o $@

tests/test_xml: $(XML_DIR)/tests/test_xml.c $(XML_DIR)/xml_parser.o
	$(CC) $(CFLAGS) $(INCLUDES) $(XML_DIR)/tests/test_xml.c \
	    $(XML_DIR)/xml_parser.o $(LDFLAGS) -o $@

tests/test_xml_legacy: $(XML_DIR)/tests/test_legacy.c $(XML_DIR)/xml_parser.o
	$(CC) $(CFLAGS) $(INCLUDES) $(XML_DIR)/tests/test_legacy.c \
	    $(XML_DIR)/xml_parser.o $(LDFLAGS) -o $@

tests/test_xml_fuzz: $(XML_DIR)/tests/test_fuzz.c $(XML_DIR)/xml_parser.o
	$(CC) $(CFLAGS) $(INCLUDES) $(XML_DIR)/tests/test_fuzz.c \
	    $(XML_DIR)/xml_parser.o $(LDFLAGS) -o $@

# Outbound S3 client driver (replication), plain and TLS builds.
S3C_SRCS := tests/s3c_cli.c src/s3client.c src/sigv4.c src/query.c
tests/s3c_cli: $(S3C_SRCS) include/s3client.h include/sigv4.h
	$(CC) $(filter-out -DFS3_TLS,$(CFLAGS)) $(INCLUDES) $(S3C_SRCS) $(filter-out -lssl,$(LDFLAGS)) -o $@
tests/s3c_cli_tls: $(S3C_SRCS) include/s3client.h include/sigv4.h
	$(CC) $(CFLAGS) -DFS3_TLS $(INCLUDES) $(S3C_SRCS) -lssl $(filter-out -lssl,$(LDFLAGS)) -o $@

# test_sigv4 needs the SIGV4_TESTING macro to expose internal helpers,
# so we recompile sigv4.c instead of using the cached .o from the
# server build.
tests/test_sigv4: tests/test_sigv4.c src/sigv4.c src/query.c
	$(CC) $(CFLAGS) $(INCLUDES) -DSIGV4_TESTING tests/test_sigv4.c src/sigv4.c src/query.c \
	    $(LDFLAGS) -o $@

# test_credfile needs the FS3_MAIN_TESTING macro to expose main.c's
# credentials-file parser and exclude main()/on_signal, so it can supply
# its own main() without pulling in server.c's dependency chain.
tests/test_credfile: tests/test_credfile.c src/main.c src/sigv4.c src/log.c src/query.c src/sandbox.c src/ssec.c src/lockc.c
	$(CC) $(CFLAGS) $(INCLUDES) -DFS3_MAIN_TESTING \
	    tests/test_credfile.c src/main.c src/sigv4.c src/log.c src/query.c src/sandbox.c \
	    $(LDFLAGS) -o $@

clean:
	rm -f fs3 fs3-tls fs3-static fs3-tls-static fs3-lockd fs3-dedup-estimate $(OBJS) $(OBJS:.o=.d) $(TEST_BINS) tests/s3c_cli tests/s3c_cli_tls tests/*.d

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

.PHONY: seccomp-profile all clean test check-test-deps smoketest fetch-llhttp

# Syscall evidence for src/sandbox.c (round 2, item 5): run the e2e
# suites under strace and diff against the compiled-in allowlist.
seccomp-profile: fs3 fs3-tls
	@./tests/tools/seccomp_profile.sh

# Root-run immutability helper (round 2, item 9); no store dependency.
fs3-lockd: src/lockd.c
	$(CC) $(CFLAGS) src/lockd.c -o $@

# Static helper for the Synology package (no libcrypto needed).
fs3-lockd-static: src/lockd.c
	$(CC) $(CFLAGS) -static src/lockd.c -o fs3-lockd

# Read-only block-dedup estimator; standalone, no libcrypto.
fs3-dedup-estimate: src/dedup_estimate.c
	$(CC) $(CFLAGS) src/dedup_estimate.c -o $@

fs3-dedup-estimate-static: src/dedup_estimate.c
	$(CC) $(CFLAGS) -static src/dedup_estimate.c -o fs3-dedup-estimate
