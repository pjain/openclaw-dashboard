# OpenClaw Dashboard v2.0.0 - Release Notes

## 🔐 Authentication & Security Hardening

Major security release — the dashboard now requires authentication and includes enterprise-grade security features.

**Repository:** https://github.com/tugcantopaloglu/openclaw-dashboard

---

## 🆕 New Features

### 🔑 Username/Password Authentication
- First visit shows a registration screen to create your account
- Passwords hashed with PBKDF2 (100,000 iterations, SHA-512, random salt)
- Server-side session tokens — passwords never stored in browser
- "Remember me" option: 3-hour persistent session vs browser-session only
- Credentials stored in `data/credentials.json`

### 🛡️ Multi-Factor Authentication (TOTP)
- Optional MFA with any TOTP app (Google Authenticator, Authy, etc.)
- QR code scanning for easy setup
- 6-digit codes with ±1 window tolerance for clock drift
- TOTP verification required before MFA is activated
- Enable/disable from the Security page in dashboard

### 🔒 Password Recovery
- "Forgot password?" flow using recovery token (`DASHBOARD_TOKEN` env var)
- Change password from Security page (invalidates other sessions)
- Complete account reset via SSH if needed

### 🌐 HTTPS Enforcement
- HTTP blocked for non-localhost connections
- Localhost access allowed for local development
- `DASHBOARD_ALLOW_HTTP=true` env var to override
- Works seamlessly with Tailscale HTTPS proxy

## 🛡️ Security Hardening

### Critical Fixes
- **Timing-safe token comparison** — `crypto.timingSafeEqual` prevents timing attacks
- **IP spoofing protection** — only `req.socket.remoteAddress` used (no X-Forwarded-For trust)
- **No token leakage** — login response doesn't expose sensitive data

### Security Headers (all responses)
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- `Content-Security-Policy` with explicit directives
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `X-XSS-Protection: 1; mode=block`
- `Referrer-Policy: strict-origin-when-cross-origin`

### Rate Limiting
- Unified rate limiter for login attempts only
- 5 failed attempts → 15-minute soft lockout
- 20 failed attempts → 15-minute hard lockout
- Lockout calculated from last failed attempt

### Other
- **CORS** — same-origin only, no wildcard
- **OPTIONS preflight** handling (204 response)
- **Audit logging** — all auth events and destructive actions logged to `data/audit.log` (auto-rotates at 10MB)
- **Atomic log rotation** — uses tmp file + rename
- **Scoped tmux kill** — only kills claude-persistent session, not all tmux
- **CSP documented** — `unsafe-inline` explained as necessary for single-file architecture

## 🔧 Infrastructure

### Reverse Proxy Support
- Automatic API base path detection for subpath deployments (e.g., `/dashboard`)
- Works with Tailscale serve, nginx, and other reverse proxies

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DASHBOARD_PORT` | `7000` | Server port |
| `DASHBOARD_TOKEN` | Auto-generated | Recovery token for password reset |
| `WORKSPACE_DIR` | `~/clawd` | OpenClaw workspace path |
| `OPENCLAW_DIR` | `~/.openclaw` | OpenClaw config directory |
| `DASHBOARD_ALLOW_HTTP` | `false` | Allow HTTP from non-local IPs |

### install.sh Updates
- Token setup during installation (custom or auto-generated)
- Token saved to systemd service environment
- Displays login instructions after install

## 📝 Documentation
- Comprehensive README with MFA guide, password recovery, and troubleshooting
- Security features documented in detail
- API reference for authenticated vs unauthenticated endpoints

## ⬆️ Upgrade from v1.x

1. Pull latest: `git pull origin main`
2. Restart service: `systemctl restart agent-dashboard`
3. First visit will show registration screen — create your account
4. (Optional) Enable MFA from Security page
5. Share recovery token with yourself (check `journalctl -u agent-dashboard`)

**Breaking changes:**
- Authentication is now required for all API endpoints
- Old bookmarks to dashboard will show login screen
- `DASHBOARD_TOKEN` env var is now used as recovery key (not login token)

---

*Previous: [v1.0.0 — Initial Public Release](#v100)*

# OpenClaw Dashboard v1.0.0

Initial public release with session management, cost analysis, live feed, memory viewer, system health monitoring, and more. See git history for details.
