# Mirror cvelistV5 into a featherd bucket.
#
#   make seed    store every record from today's midnight zip, once
#   make sync    apply the deltas since, once
#   make run     keep syncing every 15 minutes
#
# FEATHERD, BUCKET, AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are read from
# the environment by cve-sync, so pass them as usual:
#   FEATHERD=http://127.0.0.1:8333 make seed sync

GO ?= go
PARALLEL ?= 8
# Where the midnight zip is downloaded. It's about 650 MB, named by date,
# so a seed later the same day reuses it.
CACHE ?= cache
# Which release's midnight zip to seed from: latest, or a tag such as
# cve_2026-11-02_0100Z.
RELEASE ?= latest
# The cve-sync binary to run; deploy.conf points it at the deployed one.
SYNC ?= ./cve-sync

RELEASES_API = https://api.github.com/repos/CVEProject/cvelistV5/releases
RELEASE_API = $(if $(filter latest,$(RELEASE)),$(RELEASES_API)/latest,$(RELEASES_API)/tags/$(RELEASE))

cve-sync: $(wildcard *.go) go.mod
	$(GO) build -o $@ .

# One GitHub API request finds the asset; curl resumes a partial download.
# The zip is checked before cve-sync reads it.
seed: $(SYNC)
	@mkdir -p $(CACHE)
	@url=$$(curl -fsS $(RELEASE_API) | grep -o '"browser_download_url": *"[^"]*_all_CVEs_at_midnight[^"]*"' | grep -o 'https://[^"]*' | head -n 1); \
	if [ -z "$$url" ]; then echo "seed: no midnight zip in release $(RELEASE)" >&2; exit 1; fi; \
	zip="$(CACHE)/$${url##*/}"; \
	if [ ! -f "$$zip" ]; then \
		echo "seed: downloading $$url"; \
		curl -fL --retry 3 -C - -o "$$zip.part" "$$url" && unzip -tq "$$zip.part" >/dev/null && mv "$$zip.part" "$$zip" || exit 1; \
	fi; \
	$(SYNC) -seed "$$zip" -parallel $(PARALLEL)

sync: $(SYNC)
	$(SYNC) -once -parallel $(PARALLEL)

run: $(SYNC)
	$(SYNC) -parallel $(PARALLEL)

test:
	$(GO) test ./...

clean:
	rm -rf cve-sync $(CACHE)

.PHONY: seed sync run test clean
