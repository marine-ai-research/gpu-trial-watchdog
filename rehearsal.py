"""GET-only account rehearsal. No production policy, Pod IDs or mutation tools."""
import json
import os
import re
import signal
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = 'https://api.runpod.io/v2'
CATEGORIES = {
    'pods': ('/pods', 'pods'),
    'queued': ('/queued-pods', 'queuedPods'),
    'network_volumes': ('/network-volumes', 'networkVolumes'),
    'global_volumes': ('/global-volumes', 'globalVolumes'),
    'serverless': ('/serverless', 'endpoints'),
    'clusters': ('/clusters', 'clusters'),
}
AUTHORIZATION = 'GET_ONLY_EMPTY_ACCOUNT_600S_V1'


class Stop(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise Stop()
            result[key] = value
        return result
    def bad(value):
        raise Stop()
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=bad)
    except Exception:
        raise Stop() from None


def get_collection(path, cursor, token, timeout):
    # No method argument, generic URL, individual-resource path or request body.
    if path not in {item[0] for item in CATEGORIES.values()}:
        raise Stop()
    if cursor is not None and (type(cursor) is not str or not 1 <= len(cursor) <= 256):
        raise Stop()
    if type(token) is not str or not token or len(token) > 4096 or any(ord(c) < 33 or ord(c) > 126 for c in token):
        raise Stop()
    if not 0 < timeout <= 15:
        raise Stop()
    url = BASE + path
    if cursor is not None:
        url += '?' + urllib.parse.urlencode({'cursor': cursor})
    req = urllib.request.Request(url, method='GET', headers={
        'Authorization': 'Bearer ' + token, 'Accept': 'application/json'})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(req, timeout=timeout) as response:
            if response.status != 200:
                raise Stop()
            raw = response.read(1048577)
            if len(raw) > 1048576:
                raise Stop()
            return strict_json(raw.decode('utf-8'))
    except Exception:
        # Never expose token, cursor, provider response, URL or exception text.
        raise Stop() from None


def verify_context(env):
    repo = env.get('CONTROLLER_REPOSITORY', '')
    pin = env.get('REVIEWED_REHEARSAL_COMMIT', '')
    if (not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repo)
            or not re.fullmatch('[a-f0-9]{40}', pin)
            or env.get('GITHUB_REPOSITORY') != repo
            or env.get('GITHUB_SHA') != pin
            or env.get('GITHUB_REF') != 'refs/heads/main'
            or env.get('GITHUB_EVENT_NAME') != 'workflow_dispatch'
            or env.get('REHEARSAL_AUTHORIZATION') != AUTHORIZATION):
        raise Stop()


def empty_inventory(token, deadline, transport=get_collection, mono=time.monotonic):
    for path, key in CATEGORIES.values():
        cursor = None
        seen = set()
        for _ in range(100):
            remaining = deadline - mono()
            if remaining <= 0:
                raise Stop()
            data = transport(path, cursor, token, min(15, remaining))
            if mono() > deadline:
                raise Stop()
            if type(data) is not dict or type(data.get(key)) is not list:
                raise Stop()
            # First observed item stops all further requests; no IDs are logged.
            if data[key]:
                raise Stop()
            pagination = data.get('pagination')
            if (type(pagination) is not dict
                    or type(pagination.get('hasNextPage')) is not bool
                    or 'nextCursor' not in pagination):
                raise Stop()
            cursor = pagination['nextCursor']
            if not pagination['hasNextPage']:
                if cursor not in (None, ''):
                    raise Stop()
                break
            if type(cursor) is not str or not 1 <= len(cursor) <= 256 or cursor in seen:
                raise Stop()
            seen.add(cursor)
        else:
            raise Stop()


def emit(event):
    if event not in {'READY_EMPTY_ACCOUNT', 'EMPTY_ACCOUNT_CHECK', 'EMPTY_OBSERVATION_COMPLETE', 'STOP'}:
        raise Stop()
    record = {'event': event}
    if event != 'STOP':
        record.update(counts=dict.fromkeys(CATEGORIES, 0), all_billable_resources_verified=False)
    print(json.dumps(record, sort_keys=True), flush=True)


def observe(token, transport=get_collection, mono=time.monotonic, sleep=time.sleep):
    # Initial 120s, at least 600s observation, bounded sweeps; 750s overall budget.
    initial = mono()
    empty_inventory(token, initial + 120, transport, mono)
    emit('READY_EMPTY_ACCOUNT')
    end = mono() + 600
    while mono() < end:
        sleep(min(15, max(0, end - mono())))
        if mono() >= end:
            break
        # A sweep started before the observation boundary keeps its 30s budget.
        # Crossing 600s is not an API failure; a fresh final sweep still follows.
        empty_inventory(token, min(initial + 750, mono() + 30), transport, mono)
        emit('EMPTY_ACCOUNT_CHECK')
    # A terminal full six-category readback is mandatory, not a stale cached result.
    empty_inventory(token, min(initial + 750, mono() + 30), transport, mono)
    emit('EMPTY_OBSERVATION_COMPLETE')


def main(env=None):
    try:
        if len(sys.argv) != 1:
            raise Stop()
        env = os.environ if env is None else env
        verify_context(env)
        token = env.get('REHEARSAL_RUNPOD_TOKEN')
        if not token:
            raise Stop()
        def interrupted(signum, frame):
            raise Stop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, interrupted)
        observe(token)
        return 0
    except BaseException:
        emit('STOP')
        return 1


if __name__ == '__main__':
    sys.exit(main())
