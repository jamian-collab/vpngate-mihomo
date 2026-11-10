# VPN Gate → Mihomo GitHub Actions

Every two hours, fetch all compatible public OpenVPN profiles from the VPN Gate iPhone CSV API, convert them to a standalone Mihomo YAML with routing groups and MRS rule providers, and publish via GitHub Pages.

## Deploy

1. Create a **public** GitHub repository, e.g. `vpngate-mihomo`.
2. Upload all files **including `.github/workflows/update.yml`** to the repository root.
3. Go to **Settings → Pages → Build and deployment → Source → GitHub Actions**.
4. Go to **Actions → Update VPN Gate Mihomo → Run workflow**.
5. After a successful run, subscribe to `https://USERNAME.github.io/REPOSITORY/vpngate.yaml` in Clash Verge Rev.

## Configuration

- `--country ALL --proto all --limit 0` collects every API-listed compatible OpenVPN profile. `0` means unlimited.
- Schedule: `13 */2 * * *` (every two hours, UTC; actual GitHub scheduling may be delayed).
- `workflow_dispatch` allows manual runs.
- Failed fetching or empty output causes the workflow to fail **before** deployment; the previously published Pages version remains intact.
- Generated configuration includes the original script's rules, groups, and remote `.mrs` rule providers. Mihomo must be able to download these rule providers, and Clash Verge Rev must run in Rule mode.
- Public GitHub Pages exposes the subscription and embedded VPN Gate public certificates. Do not add private credentials.

## Test locally

```bash
pip install -r requirements.txt
python vpngate_to_mihomo.py --file example.ovpn --output vpngate.yaml
python vpngate_to_mihomo.py --country ALL --proto all --limit 0 --output vpngate.yaml
```

Note: 'all' means all *currently listed and compatible* profiles returned by VPN Gate API, not all servers in existence. The API provides one embedded OpenVPN profile per listed row. Compatibility and connectivity are not guaranteed.
