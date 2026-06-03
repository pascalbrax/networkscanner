# Check HTTP and HTTPS availability on a host
import json
import sys
import socket
import urllib.request
import urllib.error
import urllib.parse
import ssl
import re
import html

COLUMN_TITLE = 'HTTP/HTTPS'
TIMEOUT = 5
MAX_REDIRECTS = 5


def get_title() -> None:
    print(json.dumps({'title': COLUMN_TITLE}))


def extract_title(body: str) -> str:
    match = re.search(r'<title[^>]*>(.*?)</title>', body, re.IGNORECASE | re.DOTALL)
    if not match:
        return ''
    title = re.sub(r'\s+', ' ', match.group(1)).strip()
    return html.unescape(title)


def title_looks_redirect(title: str) -> bool:
    return bool(re.search(r'\b(moved|redirect(?:ed)?)\b', title or '', re.IGNORECASE))


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def probe(ip: str, port: int, scheme: str) -> dict:
    start_url = f'{scheme}://{ip}:{port}/'

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    opener = urllib.request.build_opener(NoRedirectHandler)

    current_url = start_url

    for _ in range(MAX_REDIRECTS):
        try:
            req = urllib.request.Request(
                current_url,
                headers={'User-Agent': 'NetworkScanner/1.0'}
            )

            with opener.open(
                req,
                timeout=TIMEOUT
            ) as resp:

                status = resp.status
                headers = dict(resp.headers)
                body_preview = resp.read(4096).decode(
                    'utf-8',
                    errors='replace'
                )

                title = extract_title(body_preview)

                result = {
                    'open': True,
                    'status': status,
                    'server': headers.get('Server', headers.get('server', '')),
                    'content_type': headers.get('Content-Type', headers.get('content-type', '')),
                    'body_preview': body_preview,
                    'title': title,
                    'url': current_url,
                }

                return result

        except urllib.error.HTTPError as e:
            headers = dict(e.headers) if e.headers else {}

            try:
                body_preview = e.read(4096).decode(
                    'utf-8',
                    errors='replace'
                )
            except Exception:
                body_preview = ''

            title = extract_title(body_preview)

            location = headers.get('Location')

            if location and title_looks_redirect(title):
                current_url = urllib.parse.urljoin(current_url, location)
                continue

            return {
                'open': True,
                'status': e.code,
                'server': headers.get('Server', headers.get('server', '')),
                'content_type': headers.get('Content-Type', headers.get('content-type', '')),
                'body_preview': body_preview,
                'title': title,
                'url': current_url,
            }

        except (urllib.error.URLError, socket.timeout, OSError):
            return {'open': False}

        except Exception as e:
            return {'open': False, 'error': str(e)}

    return {
        'open': True,
        'status': 'REDIRECT_LOOP',
        'server': '',
        'content_type': '',
        'body_preview': '',
        'title': '',
        'url': current_url,
    }


def choose_short_answer(http: dict, https: dict, fallback: str) -> str:
    # Prefer HTTP title if available.
    if http.get('open') and http.get('title'):
        return http['title']

    # Otherwise HTTPS title.
    if https.get('open') and https.get('title'):
        return https['title']

    # No title found; use web server banner.
    if http.get('open') and http.get('server'):
        return http['server']

    if https.get('open') and https.get('server'):
        return https['server']

    # Unknown web server: keep original output.
    return fallback


def scan(ip: str) -> None:
    http = probe(ip, 80, 'http')
    https = probe(ip, 443, 'https')

    parts = []
    long_lines = []

    if http['open']:
        code = http.get('status', '?')

        parts.append(f'HTTP:{code}')

        long_lines.append('[HTTP :80]')
        long_lines.append(f'  Status : {code}')

        if http.get('url'):
            long_lines.append(f'  URL    : {http["url"]}')

        if http.get('title'):
            long_lines.append(f'  Title  : {http["title"]}')

        if http.get('server'):
            long_lines.append(f'  Server : {http["server"]}')

        if http.get('content_type'):
            long_lines.append(f'  Type   : {http["content_type"]}')

        if http.get('body_preview'):
            preview = http['body_preview'].replace('\r', '').strip()[:200]
            long_lines.append(f'  Body   : {preview}')

    else:
        parts.append('')
        long_lines.append('[HTTP :80]  closed / filtered')

    long_lines.append('')

    if https['open']:
        code = https.get('status', '?')

        parts.append(f'HTTPS:{code}')

        long_lines.append('[HTTPS:443]')
        long_lines.append(f'  Status : {code}')

        if https.get('url'):
            long_lines.append(f'  URL    : {https["url"]}')

        if https.get('title'):
            long_lines.append(f'  Title  : {https["title"]}')

        if https.get('server'):
            long_lines.append(f'  Server : {https["server"]}')

        if https.get('content_type'):
            long_lines.append(f'  Type   : {https["content_type"]}')

    else:
        parts.append('')
        long_lines.append('[HTTPS:443]  closed / filtered')

    fallback_short = '  '.join(parts)
    short_answer = choose_short_answer(http, https, fallback_short)

    print(json.dumps({
        'short': short_answer,
        'long': '\n'.join(long_lines)
    }))


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--title':
        get_title()
        sys.exit(0)

    if len(sys.argv) < 2:
        print(json.dumps({
            'short': 'ERR',
            'long': 'Usage: http.py <ip>'
        }))
        sys.exit(1)

    try:
        scan(sys.argv[1])
    except Exception as exc:
        print(json.dumps({
            'short': 'ERR',
            'long': str(exc)
        }))
        sys.exit(1)