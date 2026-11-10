#!/usr/bin/env python3
"""Fetch VPN Gate public OpenVPN profiles and build a Mihomo YAML subscription.
Usage: pip install requests PyYAML
       python vpngate_to_mihomo.py --country JP --limit 20 --proto udp
       python vpngate_to_mihomo.py --file example.ovpn --output local.yaml
"""
import argparse
import base64
import csv
import io
import re
import sys
from pathlib import Path

import requests
import yaml

API = 'https://www.vpngate.net/api/iphone/'


def parse_ovpn(raw: str, name: str):
    blocks = {}
    opts = {}
    tag = None
    lines = []
    for original in raw.replace('\r', '').splitlines():
        line = original.strip()
        if tag:
            if line.lower() == f'</{tag}>':
                blocks[tag] = '\n'.join(lines).strip() + '\n'
                tag, lines = None, []
            else:
                lines.append(original)
            continue
        m = re.fullmatch(r'<(ca|cert|key|tls-auth|tls-crypt|tls-crypt-v2)>', line, re.I)
        if m:
            tag = m.group(1).lower()
            lines = []
            continue
        if not line or line.startswith(('#', ';')):
            continue
        parts = line.split()
        opts.setdefault(parts[0].lower(), []).append(parts[1:])
    if tag:
        raise ValueError('unclosed inline certificate/key block')

    def get(key, default=None):
        return opts.get(key, [[default]])[0][0] if opts.get(key) and opts[key][0] else default

    remote = opts.get('remote', [[]])[0]
    if len(remote) < 2 or not blocks.get('ca'):
        raise ValueError('missing remote or inline CA')
    if get('dev', 'tun') != 'tun':
        raise ValueError('only tun profiles supported')
    proto = (get('proto', remote[2] if len(remote) > 2 else 'udp')).lower()
    proto = 'tcp' if proto.startswith('tcp') else 'udp' if proto.startswith('udp') else None
    if proto is None:
        raise ValueError('unknown transport')

    # Fail closed for directives that require additional handling rather than silently ignoring them.
    unsupported = {'secret', 'pkcs12', 'plugin', 'http-proxy', 'socks-proxy',
                   'tls-verify', 'verify-x509-name', 'tls-remote', 'fragment',
                   'compress', 'comp-noadapt', 'auth-token'}
    present = unsupported.intersection(opts)
    if present:
        raise ValueError('unsupported directives: ' + ', '.join(sorted(present)))
    if 'auth-user-pass' in opts:
        raise ValueError('auth-user-pass requires credentials; not auto-converted')
    if not blocks.get('cert') or not blocks.get('key'):
        raise ValueError('inline client cert and key required')
    for k in ('ca', 'cert', 'key', 'tls-auth', 'tls-crypt', 'tls-crypt-v2'):
        if k in opts and k not in blocks:
            raise ValueError(f'external {k} file is not supported')

    node = {'name': name, 'type': 'openvpn', 'server': remote[0],
            'port': int(remote[1]), 'proto': proto, 'dev': 'tun', 'udp': True}
    for k in ('cipher', 'auth'):
        if get(k):
            node[k] = get(k)
    if get('data-ciphers'):
        node['data-ciphers'] = get('data-ciphers').split(':')
    if get('data-ciphers-fallback') or get('cipher'):
        node['data-ciphers-fallback'] = get('data-ciphers-fallback') or get('cipher')
    if get('tun-mtu'):
        node['mtu'] = int(get('tun-mtu'))
    for k in ('ca', 'cert', 'key', 'tls-auth', 'tls-crypt', 'tls-crypt-v2'):
        if k in blocks:
            node[k] = blocks[k]
    if 'tls-auth' in blocks and get('key-direction'):
        node['key-direction'] = int(get('key-direction'))
    return node


def fetch_nodes(country, proto, limit, timeout):
    response = requests.get(API, timeout=timeout, headers={'User-Agent': 'Mozilla/5.0'})
    response.raise_for_status()
    content = response.content.decode('utf-8-sig', errors='replace')
    header = None
    servers = []
    for row in csv.reader(io.StringIO(content)):
        if not row:
            continue
        if row[0].startswith('#HostName'):
            header = [c.lstrip('#') for c in row]
            continue
        if not header or row[0].startswith('*') or len(row) != len(header):
            continue
        servers.append(dict(zip(header, row)))
    if not header:
        raise ValueError('VPN Gate CSV header not found')
    servers = [s for s in servers if country == 'ALL' or s.get('CountryShort', '').upper() == country]
    servers.sort(key=lambda s: int(s.get('Speed') or 0), reverse=True)
    nodes, seen = [], set()
    for s in servers:
        if limit > 0 and len(nodes) >= limit:
            break
        try:
            raw = base64.b64decode(s['OpenVPN_ConfigData_Base64'], validate=True).decode('utf-8-sig')
            name = f"{s.get('CountryShort', 'XX')}-{s.get('HostName', 'unknown')}"
            node = parse_ovpn(raw, name)
            if proto != 'all' and node['proto'] != proto:
                continue
            identity = (node['server'], node['port'], node['proto'])
            if identity in seen:
                continue
            seen.add(identity)
            node['name'] = f"{name}-{node['proto']}-{node['port']}"
            nodes.append(node)
        except (KeyError, ValueError, UnicodeError, base64.binascii.Error) as exc:
            print(f"Skipped {s.get('HostName', '?')}: {exc}", file=sys.stderr)
    return nodes



def build_config(nodes, ruleset_base='https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite'):
    """Build a full standalone Mihomo configuration with editable policy groups."""
    names = [node['name'] for node in nodes]
    selector = lambda name, choices: {'name': name, 'type': 'select', 'proxies': choices}
    groups = [
        selector('🚀 节点选择', ['♻️ 自动选择', *names, 'DIRECT']),
        {'name': '♻️ 自动选择', 'type': 'url-test', 'url': 'https://www.gstatic.com/generate_204',
         'interval': 300, 'tolerance': 100, 'proxies': names},
        selector('🤖 AI服务', ['🚀 节点选择', '♻️ 自动选择', 'DIRECT']),
        selector('🎬 流媒体', ['🚀 节点选择', '♻️ 自动选择', 'DIRECT']),
        selector('💬 Telegram', ['🚀 节点选择', '♻️ 自动选择', 'DIRECT']),
        selector('🌍 国外网站', ['🚀 节点选择', '♻️ 自动选择', 'DIRECT']),
        selector('🇨🇳 国内网站', ['DIRECT', '🚀 节点选择']),
        selector('🛡️ 广告拦截', ['REJECT', 'DIRECT']),
        selector('🐟 漏网之鱼', ['🚀 节点选择', 'DIRECT']),
    ]
    # MetaCubeX meta-rules-dat publishes Mihomo-compatible .mrs geosite/geolocation files.
    rule_names = ['category-ads-all', 'openai', 'youtube', 'netflix', 'telegram',
                  'geolocation-cn', 'geolocation-!cn']
    providers = {
        name: {'type': 'http', 'behavior': 'domain', 'format': 'mrs',
               'url': f'{ruleset_base}/{name}.mrs', 'path': f'./ruleset/{name}.mrs',
               'interval': 86400}
        for name in rule_names
    }
    providers['cn-ip'] = {
        'type': 'http', 'behavior': 'ipcidr', 'format': 'mrs',
        'url': 'https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/cn.mrs',
        'path': './ruleset/cn-ip.mrs', 'interval': 86400
    }
    return {
        'mixed-port': 7890, 'allow-lan': False, 'mode': 'rule',
        'log-level': 'warning', 'ipv6': False,
        'proxies': nodes,
        'proxy-groups': groups,
        'rule-providers': providers,
        'rules': [
            'DOMAIN-SUFFIX,localhost,DIRECT',
            'IP-CIDR,127.0.0.0/8,DIRECT,no-resolve',
            'IP-CIDR,10.0.0.0/8,DIRECT,no-resolve',
            'IP-CIDR,172.16.0.0/12,DIRECT,no-resolve',
            'IP-CIDR,192.168.0.0/16,DIRECT,no-resolve',
            'IP-CIDR,169.254.0.0/16,DIRECT,no-resolve',
            'RULE-SET,category-ads-all,🛡️ 广告拦截',
            'RULE-SET,openai,🤖 AI服务',
            'RULE-SET,youtube,🎬 流媒体',
            'RULE-SET,netflix,🎬 流媒体',
            'RULE-SET,telegram,💬 Telegram',
            'RULE-SET,geolocation-cn,🇨🇳 国内网站',
            'RULE-SET,cn-ip,🇨🇳 国内网站,no-resolve',
            'RULE-SET,geolocation-!cn,🌍 国外网站',
            'MATCH,🐟 漏网之鱼',
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--country', default='ALL', help='JP, US, KR, ALL, etc.')
    parser.add_argument('--proto', choices=['all', 'udp', 'tcp'], default='all')
    parser.add_argument('--limit', type=int, default=0, help='0 means all compatible nodes')
    parser.add_argument('--timeout', type=int, default=20)
    parser.add_argument('--file', type=Path, help='Convert a local .ovpn instead of fetching VPN Gate')
    parser.add_argument('--output', type=Path, default=Path('vpngate.yaml'))
    args = parser.parse_args()
    if args.limit < 0:
        parser.error('--limit must be >= 0')
    try:
        if args.file:
            nodes = [parse_ovpn(args.file.read_text(encoding='utf-8-sig'), args.file.stem)]
        else:
            nodes = fetch_nodes(args.country.upper(), args.proto, args.limit, args.timeout)
        if not nodes:
            raise ValueError('No compatible nodes found; try another country/protocol')
        config = build_config(nodes)
        args.output.write_text(yaml.safe_dump(config, allow_unicode=True, sort_keys=False, width=120), encoding='utf-8')
        print(f'Wrote {len(nodes)} node(s) to {args.output}')
    except (requests.RequestException, ValueError, OSError) as exc:
        parser.exit(1, f'Error: {exc}\n')


if __name__ == '__main__':
    main()
