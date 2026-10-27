# Builds the QIP components with Odin. Each is a freestanding wasm32 module
# with fixed memory: its maximum is set here, and it never grows.

ODIN ?= odin
ODIN_FLAGS = -target:freestanding_wasm32 -no-entry-point -o:speed
SHARED = $(wildcard components/shared/*.odin)

COMPONENTS = opml-to-uri-list feed-to-entries feed-state atom-to-html
WASM = $(COMPONENTS:%=build/%.wasm)

# Memory per component: its buffers, rounded up.
MEM_opml-to-uri-list = 4194304
MEM_feed-to-entries = 67108864
MEM_feed-state = 2097152
MEM_atom-to-html = 16777216

all: $(WASM)

.SECONDEXPANSION:
build/%.wasm: $$(wildcard components/%/*.odin) $(SHARED)
	@mkdir -p build
	$(ODIN) build components/$* $(ODIN_FLAGS) \
		-extra-linker-flags:"-z stack-size=65536 --max-memory=$(MEM_$*)" -out:$@

test: all
	node --test

comply: all
	npx @qip.dev/qipx comply $(WASM)

clean:
	rm -rf build

.PHONY: all test comply clean
