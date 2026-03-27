# certbot-dns-nordname

Nordname DNS Authenticator plugin for Certbot.

## Usage

Create credentials file `/etc/letsencrypt/nordname/nordname.ini`:

```ini
dns_nordname_api_token = your_api_token_here
```

Set permissions:

```bash
chmod 600 /path/to/credentials.ini
```

## Virtualenv usage

Install project and dev dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Runtime

```bash
(venv) python -m pip install
```

### Development

```bash
(venv) python -m pip install -e ".[dev]"
```

Run tests:

```bash
(venv) python -m pytest -q
```

Run pylint:

```bash
(venv) python -m pylint certbot_dns_nordname
```

Then run Certbot:

```bash
certbot certonly \
  --authenticator dns-nordname \
  --dns-nordname-credentials /path/to/credentials.ini \
  -d example.com
```
