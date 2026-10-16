# Sign in with GitHub

Keep an OAuth 2.0 client's state in featherd: the single-use `state` record
of each sign-in, with its PKCE verifier, and a record per GitHub user that
links them to your own user. RFC 6749 calls the app the "client", so its
keys go under `oauth-client/`, and an authorization server of your own
would get its own prefix, `oauth-authz/`, so the two can't clash.

`github-login.sh` needs `curl`, `jq` and `openssl`, plus `sqlite3` for
`sweep`. Your web app calls it from its sign-in and callback handlers.

## Layout

```
app bucket  →  data/app.sqlite3
├── oauth-client/github.com/state/<state>     {"redirect_uri", "code_verifier", "browser", "created_at"}
├── oauth-client/github.com/users/<github-id> {"id", "login", "name", "email", "local_user",
│                                              "access_token", "scope", "refresh_token",
│                                              "token_expires_at", "created_at", "updated_at"}
└── users/<local-id>                          {"created_at", "github"}
```

The GitHub user is keyed by their numeric ID, not their login, since a login
can be renamed and then taken by someone else.

## Flow

1. **Start.** The app gives the browser a random cookie, the browser ID,
   and runs `start REDIRECT_URI BROWSER_ID`. It makes a 256-bit random
   `state` and a PKCE verifier, `PUT`s the state record with
   `If-None-Match: *`, and prints GitHub's authorize URL with the state and
   the verifier's S256 challenge. The app redirects the browser there. Only
   a SHA-256 of the browser ID is stored.
2. **Callback.** GitHub sends the browser back with `code` and `state`, and
   the app runs `callback STATE CODE BROWSER_ID`:
   1. **Consume the state.** `GET` the record and its ETag, then `DELETE` it
      with `If-Match: <etag>`. If the same callback arrives twice, only one
      gets 204; the other gets 412, or 404 if it came later. The state is used
      once, as RFC 6749 §10.12 requires.
   2. **Check it.** It must be younger than `STATE_TTL` and have been issued
      to the same browser ID. This is what stops someone else's code being
      sent to your browser (login CSRF). These checks come after the
      delete, so a state that fails them can't be tried again.
   3. **Exchange the code** with the client secret, the stored
      `redirect_uri` (exactly as sent in step 1) and the PKCE verifier, then
      `GET /user` with the token.
   4. **Link the user.** `GET oauth-client/github.com/users/<id>`. If it
      exists, keep its `local_user` and replace the profile and tokens with
      `If-Match: <etag>`. If not, make a new `users/<random>` and `PUT` the
      record with `If-None-Match: *`, so of two first sign-ins at the same
      time only one picks the local user. On 412 it reads the record again,
      up to 5 times. Then it `PUT`s `users/<local-id>` with
      `If-None-Match: *`. The link is written first, so a crash in between
      leaves a link that the next sign-in repairs, never a local user
      nothing points at.
   5. Print the local user ID. The app starts its own session for it.
3. **Sweep.** A user who never comes back from GitHub leaves a state
   record. featherd has no TTLs, so a cron job deletes old ones straight
   from the database. State records are written once, so sqlar's `mtime` is
   when the sign-in started:

   ```sql
   DELETE FROM sqlar WHERE name >= 'oauth-client/github.com/state/'
     AND name < 'oauth-client/github.com/state0' AND mtime < <cutoff>
   ```

   `0` is the character after `/`, so the range is exactly the state
   records and never reaches `users/`.

If GitHub sends the browser back with `error=access_denied` instead of a
code, the user said no; the app shows that and the state is swept later.

## Try it

Register an OAuth app at <https://github.com/settings/developers> with the
callback URL `http://localhost:3000/callback`, then:

```sh
FEATHERD_AUTH=none go run . --dir data &  # the scripts send unsigned requests
export GITHUB_CLIENT_ID=Ov23li… GITHUB_CLIENT_SECRET=…

examples/oauth-client/github-login.sh start http://localhost:3000/callback browser-1
# https://github.com/login/oauth/authorize?client_id=Ov23li…&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&scope=read%3Auser&state=acc57d35…&code_challenge=j5w3DfKg…&code_challenge_method=S256
```

Open the URL and approve. Nothing listens on port 3000, so the browser shows
an error, but its address bar has
`http://localhost:3000/callback?code=…&state=…`. Pass both on:

```sh
examples/oauth-client/github-login.sh callback acc57d35… 1f0e2d3c… browser-1
# users/e27295493701c72fafba7f9c63ad3e66
examples/oauth-client/github-login.sh callback acc57d35… 1f0e2d3c… browser-1
# github-login.sh: unknown or already used state

examples/oauth-client/github-login.sh user 583231
# {"id":583231,"login":"octocat","name":"The Octocat","email":null,"local_user":"users/e27295493701c72fafba7f9c63ad3e66","scope":"read:user","token_expires_at":null,"created_at":1791867218,"updated_at":1791867218}

examples/oauth-client/github-login.sh sweep
# deleted 0 sign-ins started more than 10 minutes ago
```

A callback with another browser ID fails with `state was issued to a
different browser`, and one more than `STATE_TTL` seconds after `start` with
`state expired`.

## Notes

- The bucket holds access tokens, so anyone who can read it can act as
  your users on GitHub. Keep featherd off untrusted networks, or turn on
  its SigV4 authentication (the script sends unsigned requests, so that
  means adding `--aws-sigv4` to its `curl` calls). If you only need
  sign-in, not API calls later, you can drop the token from the record.
- `user` prints the record without `access_token` and `refresh_token`.
- GitHub Apps with expiring tokens also return `refresh_token` and
  `expires_in`; the record keeps the refresh token and turns `expires_in`
  into `token_expires_at`. Refreshing isn't part of the example.
- `GITHUB_CLIENT_SECRET` and the code and verifier are sent from a file, so
  they don't show up in `ps`. The browser ID is an argument, so on a shared
  host pass a value that's useless on its own.
- `TestOAuthClient` in `oauthclient_test.go` tests the pattern: a second
  `DELETE` of a consumed state gets 412, only one of two first sign-ins
  links a local user, a stale `If-Match` update fails, and the sweep
  deletes only old state records.
- `FEATHERD` (default `http://127.0.0.1:8333`), `BUCKET` (default `app`)
  and `DATA` (default `data`) choose the server, the bucket and the
  directory holding its database. `SCOPE` (default `read:user`) is the
  scope asked for; add `user:email` to get private email addresses.
  `GITHUB` and `GITHUB_API` point at GitHub, or at a fake one for testing.
