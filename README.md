# WP REST API Key Authentication

Authenticate WordPress REST API requests with per-user API keys — no OAuth dance, no application passwords, no JWT plugin. Hand a key to a script, a Zapier zap, or a mobile app and it just works.

## Usage

```bash
curl -H "X-API-Key: rak_..." https://example.com/wp-json/wp/v2/posts
# or, when headers are awkward:
curl "https://example.com/wp-json/wp/v2/posts?api_key=rak_..."
```

## Features

- **Per-user keys** — a key authenticates *as* its owner, so normal WordPress capability checks apply. A key owned by an Editor can never do admin things.
- **Scopes** — `read` keys may only GET/HEAD; `write` keys (which imply read) may POST, PUT, PATCH and DELETE.
- **Hashed storage** — only an HMAC-SHA256 of the key is stored. The raw key is shown once at creation and can never be recovered — only revoked and re-created.
- **One-click revoke** — a revoked key gets a 401 immediately.
- **Last-used tracking** — updated at most once per 5 minutes, so a busy integration doesn't cause a database write on every request.
- **Invalid keys fail closed** — a request that supplies a bad or revoked key gets a 401, not a silent fall-through to anonymous access.

## Managing keys

**Users → API Keys**: create a key (label + owner + scopes), see the prefix, scopes, creation date and last use of every key, and revoke any key. Keys are created by administrators only.

## Hooks

```php
// Runs after a request was authenticated with an API key
add_action( 'wrak_authenticated', function( $key_row ) {
    error_log( 'API request with key: ' . $key_row->label );
} );
```

## Notes

- Keys are `rak_` + 48 hex characters from `random_bytes()`.
- `?api_key=` is convenient but puts the secret in server logs — prefer the `X-API-Key` header in production, and always use HTTPS.
- This plugin handles *authentication* only. For abuse protection, pair it with a rate limiter (see `wp-rest-api-rate-limit`).

## License

MIT — see [LICENSE](LICENSE).
