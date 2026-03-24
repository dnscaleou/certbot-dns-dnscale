# certbot-dns-dnscale

DNScale DNS Authenticator plugin for [certbot](https://certbot.eff.org/).

Automates Let's Encrypt DNS-01 challenges by creating and cleaning up TXT records via the [DNScale API](https://dnscale.eu).

## Installation

```bash
pip install certbot-dns-dnscale
```

Or install from source:

```bash
pip install git+https://github.com/dnscaleou/certbot-dns-dnscale.git
```

## Credentials

Create an API key at [dnscale.eu](https://dnscale.eu) with the following scopes:
- `zones:read`
- `records:read`
- `records:write`

Save it to a credentials file:

```ini
# /etc/letsencrypt/dnscale.ini
dns_dnscale_api_token = your-api-token-here
```

Restrict permissions:

```bash
chmod 600 /etc/letsencrypt/dnscale.ini
```

## Usage

### Obtain a certificate

```bash
certbot certonly \
  --authenticator dns-dnscale \
  --dns-dnscale-credentials /etc/letsencrypt/dnscale.ini \
  -d example.com \
  -d "*.example.com"
```

### Renew certificates

```bash
certbot renew
```

Certbot remembers the authenticator used for each certificate and will automatically use the DNScale plugin for renewal.

### Propagation delay

By default, the plugin waits 60 seconds for DNS propagation. Adjust if needed:

```bash
certbot certonly \
  --authenticator dns-dnscale \
  --dns-dnscale-credentials /etc/letsencrypt/dnscale.ini \
  --dns-dnscale-propagation-seconds 120 \
  -d example.com
```

## Docker

```bash
docker run --rm \
  -v /etc/letsencrypt:/etc/letsencrypt \
  certbot/certbot \
  pip install certbot-dns-dnscale && \
  certbot certonly \
    --authenticator dns-dnscale \
    --dns-dnscale-credentials /etc/letsencrypt/dnscale.ini \
    -d example.com
```

## Configuration

| Option | Description | Default |
|--------|-------------|---------|
| `--dns-dnscale-credentials` | Path to credentials INI file | Required |
| `--dns-dnscale-propagation-seconds` | Seconds to wait for DNS propagation | 60 |

### Credentials file options

| Key | Description | Required |
|-----|-------------|----------|
| `dns_dnscale_api_token` | DNScale API token | Yes |
| `dns_dnscale_api_url` | API base URL | No (default: `https://api.dnscale.eu`) |

## License

Apache License 2.0. See [LICENSE](LICENSE).
