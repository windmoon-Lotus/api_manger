"""External AI HTTP client. Secrets are read only from the local environment."""
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request

SERVER_ERRORS = {
    'authentication_required', 'invalid_revoked_or_expired_key', 'credential_store_unavailable',
    'project_unavailable', 'storage_unavailable', 'internal_error', 'unknown_tool',
    'key_is_read_only', 'body_limit_64kb', 'expected_arguments_object',
    'project_scope_mismatch', 'unknown_arguments', 'valid_project_id_required',
    'invalid_arguments', 'idempotency_key_required_16_to_128_chars', 'idempotency_conflict',
    'invalid_parameters_or_execution_preconditions', 'invalid_plan_id',
    'plan_not_found_in_project', 'readiness_blocked', 'run_not_found_in_project',
    'tool_failed', 'receipt_not_found',
}

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class ClientError(Exception):
    def __init__(self, code, status=None, details=None):
        self.code, self.status = code, status
        self.details = details or {}
        super().__init__(code)


class Client:
    def __init__(self, base, key):
        base = base.rstrip('/')
        url = urllib.parse.urlsplit(base)
        if url.scheme not in {'http', 'https'} or not url.hostname or url.path or url.query or url.fragment or url.username or url.password:
            raise ClientError('invalid_platform_origin')
        if url.scheme == 'http' and url.hostname not in {'localhost', '127.0.0.1', '::1'}:
            raise ClientError('remote_platform_requires_https')
        if not key or '\r' in key or '\n' in key:
            raise ClientError('configure_API_MANAGER_ACCESS_KEY')
        self.base, self.key = base, key

    def request(self, path, body=None, idem=None, timeout=30):
        public = path == '/ai?format=markdown'
        decoded = urllib.parse.unquote(path)
        if (not public and not path.startswith('/api/ai/')) or any(c in decoded for c in ('\\', '#', '\r', '\n', '\x00')) or any(p in {'.', '..'} for p in decoded.split('/')):
            raise ClientError('invalid_api_path')
        headers = {'Accept': 'application/json'}
        if not public:
            headers['Authorization'] = 'Bearer ' + self.key
        if idem:
            headers['Idempotency-Key'] = idem
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers['Content-Type'] = 'application/json'
        try:
            req = urllib.request.Request(self.base + path, data=data, headers=headers)
            with urllib.request.build_opener(NoRedirect).open(req, timeout=timeout) as response:
                raw = response.read(4*1024*1024+1)
                if len(raw) > 4*1024*1024:
                    raise ClientError('response_too_large')
                if public:
                    if b'/api/ai/capabilities' not in raw:
                        raise ClientError('invalid_bootstrap')
                    return {'ok': True}
                result = json.loads(raw)
                if not isinstance(result, dict) or result.get('ok') is not True:
                    raise ClientError('invalid_api_response')
                return result
        except urllib.error.HTTPError as exc:
            # Do not print arbitrary proxy/server bodies, which may echo credentials.
            details = {}
            try:
                result = json.loads(exc.read(65536))
                code = result.get('error', 'http_error')
                if not isinstance(code, str) or code not in SERVER_ERRORS:
                    code = 'http_error'
                for name in ('request_id', 'state'):
                    value = result.get(name)
                    if isinstance(value, str) and ((name == 'request_id' and re.fullmatch(r'(?:[a-f0-9]{32}|[a-f0-9]{64})', value)) or (name == 'state' and value in {'pending', 'done', 'failed', 'unknown'})):
                        details[name] = value
            except (ValueError, AttributeError):
                code = 'http_error'
            raise ClientError(code, exc.code, details) from None
        except (urllib.error.URLError, TimeoutError):
            raise ClientError('connection_failed') from None
        except (ValueError, UnicodeError):
            raise ClientError('invalid_json_response') from None


def doctor(client):
    checks = []
    for name, path, body in [
        ('bootstrap', '/ai?format=markdown', None),
        ('capabilities', '/api/ai/capabilities', None),
        ('guide', '/api/ai/guide', None),
        ('tool_schema', '/api/ai/tools/project.list', None),
        ('real_read_call', '/api/ai/tools/project.list', {'arguments': {}}),
        ('call_readback', '/api/ai/calls', None),
    ]:
        started = time.monotonic()
        try:
            result = client.request(path, body)
            checks.append({'step': name, 'ok': True, 'elapsed_ms': round((time.monotonic()-started)*1000)})
            if name == 'real_read_call':
                receipt = result.get('request_id')
            if name == 'call_readback' and not any(c.get('request_id') == receipt for c in result.get('calls', [])):
                checks[-1].update(ok=False, error='call_receipt_missing')
                return {'ok': False, 'checks': checks}
        except ClientError as exc:
            checks.append({'step': name, 'ok': False, 'error': exc.code, 'status': exc.status})
            return {'ok': False, 'checks': checks}
    return {'ok': True, 'checks': checks, 'business_verification': 'not_performed'}



def call(client, name, arguments, idem=None, timeout=30):
    if not re.fullmatch(r"[a-zA-Z0-9_.]+", name):
        raise ClientError("invalid_tool_name")
    return client.request("/api/ai/tools/" + name, {"arguments": arguments}, idem, timeout=timeout)
