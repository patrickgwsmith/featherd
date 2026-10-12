# Time zones

Serve the [IANA time zone database](https://www.iana.org/time-zones) from a
`tzdb` bucket: one object per zone holding its compiled rules, plus the
tables mapping countries to zones. It's about 600 small objects, under 1 MB,
and every macOS and Linux machine already has a copy in
`/usr/share/zoneinfo`, so there's nothing to download.

`tz.sh` needs only `curl` and `awk`.

## Layout

```
tzdb bucket  →  data/tzdb.sqlite3
├── <zone>          e.g. Europe/London: TZif rules (RFC 9636), application/tzif
├── zone.tab        country code, coordinates, zone and comment per line
├── zone1970.tab    the same, grouped by zone (if the source has it)
├── iso3166.tab     country code and name per line
└── VERSION         the release, e.g. 2026c (+VERSION in the source)
```

Aliases such as `US/Eastern` are separate objects with the same bytes as the
zone they point to, so every name a program might use can be fetched directly.

## Try it

```sh
go run . --dir data &

examples/tz/tz.sh put                # or: put path/to/zoneinfo
# stored 599 zones from /usr/share/zoneinfo

examples/tz/tz.sh version
# 2026c

examples/tz/tz.sh zones Pacific/A
# Pacific/Apia
# Pacific/Auckland
```

Look up a country's zones, with coordinates in decimal degrees:

```sh
examples/tz/tz.sh country nz
# NZ	New Zealand
# Pacific/Auckland                  -36.8667   174.7667  most of New Zealand
# Pacific/Chatham                   -43.9500  -176.5500  Chatham Islands
```

Ask what time it is. `now` downloads each zone and points `TZ` at the file,
so the rules come from featherd rather than the system:

```sh
examples/tz/tz.sh now Pacific/Chatham America/St_Johns Etc/GMT+5
# Pacific/Chatham                  2026-10-12 16:59:14 +1345 (+1345)
# America/St_Johns                 2026-10-12 00:44:14 NDT (-0230)
# Etc/GMT+5                        2026-10-11 22:14:14 -05 (-0500)
```

(`Etc/GMT+5` is five hours *behind* UTC; POSIX signs are the other way
round.)

Any HTTP client can read the zones. In Go:

```go
resp, err := http.Get("http://127.0.0.1:8333/tzdb/Pacific/Chatham")
if err != nil {
	return err
}
defer resp.Body.Close()
data, err := io.ReadAll(resp.Body)
if err != nil {
	return err
}
loc, err := time.LoadLocationFromTZData("Pacific/Chatham", data)
```

## Querying the bucket's database directly

featherd records each object's SHA-256 in the `content_meta` table, so
finding a zone's aliases is one query:

```sh
sqlite3 data/tzdb.sqlite3 "SELECT group_concat(name, ' = ') FROM content_meta
  WHERE sha256 = (SELECT sha256 FROM content_meta WHERE name = 'America/New_York')"
# America/New_York = EST5EDT = US/Eastern = posixrules

sqlite3 data/tzdb.sqlite3 "SELECT count(*), count(DISTINCT sha256) FROM content_meta
  WHERE content_type = 'application/tzif'"
# 599|341
```

## Notes

- `put` stores every file under the source that starts with the `TZif`
  magic, and skips the rest (`leapseconds`, `tzdata.zi`). Running it again
  overwrites the bucket's zones, so after a tzdata update it brings the
  bucket up to date; zones removed from the source stay until deleted.
- `put` creates the bucket if needed; a 409 `BucketAlreadyOwnedByYou` just
  means it already exists.
- Some systems ship `zone1970.tab` and others don't (macOS doesn't); `country`
  uses `zone.tab`, which every release has.
- `FEATHERD` (default `http://127.0.0.1:8333`) and `BUCKET` (default `tzdb`)
  choose the server and bucket. S3 bucket names need at least three
  characters, hence `tzdb` rather than `tz`.
