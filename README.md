# 🌍 EcoWatch — Pollution Response Network

> A deliberately vulnerable web application for demonstrating **Prototype Pollution (CWE-1321)** in a realistic environment.

[![Watch the video](https://img.shields.io/badge/YouTube-Watch%20Demo-red?style=for-the-badge&logo=youtube)](https://youtu.be/X3SvLLl3hXM?si=D9FnG6OiK3oLotRJ)

---

## What is this?

EcoWatch is a fictional environmental monitoring platform built as a security demo app. It simulates a real-world Node.js application with authentication, role-based access control, and a vulnerable profile update endpoint that can be exploited via prototype pollution to escalate privileges.

The app is intentionally vulnerable. Do not deploy it publicly.

---

## The Vulnerability

The `/api/profile/update` endpoint accepts a JSON payload and merges it into the user object using an unsafe recursive merge function:

```js
function vulnerableMerge(target, source) {
  for (const key in source) {
    if (typeof source[key] === 'object') {
      if (!target[key]) target[key] = {};
      vulnerableMerge(target[key], source[key]); // recurses into __proto__
    } else {
      target[key] = source[key];
    }
  }
}
```

Sending the following payload poisons `Object.prototype` and escalates a `volunteer` account to admin:

```json
{
  "bio": "Saving the planet",
  "__proto__": {
    "canManageUsers": true,
    "canDeleteReports": true
  }
}
```

---

## CVE Reference

This app also demonstrates **CVE-2019-10744** — prototype pollution in lodash `<=4.17.11` via `_.defaultsDeep()`. The `constructor.prototype` path is an alternative vector that bypasses naive `__proto__` filters:

```json
{ "constructor": { "prototype": { "isAdmin": true } } }
```

Patched in lodash **4.17.12** via the introduction of `safeGet()`.

---

## Demo Accounts

| Username    | Password      | Role        |
|-------------|---------------|-------------|
| `admin`     | ecowatch2026  | Administrator |
| `ranger`    | fieldwork!1   | Field Agent |
| `volunteer` | saveearth     | Volunteer   |

Log in as `volunteer` and use the Security Lab to escalate to admin without knowing the admin password.

---

## Running Locally

**Prerequisites:** Node.js 18+, Docker (optional)

### Without Docker

```bash
git clone https://github.com/INSERT_USERNAME/ecowatch
cd ecowatch
npm install
node server.js
```

App runs at `http://localhost:3000`

### With Docker Compose

```bash
docker compose up
```

---

## Project Structure

```
ecowatch/
├── server.js          # Express server — vulnerable endpoints live here
├── public/
│   └── index.html     # Frontend — single page app
├── docker-compose.yml
└── package.json
```

---

## Key Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/login` | Authenticate and receive JWT |
| POST | `/api/profile/update` | ❌ Vulnerable merge endpoint |
| POST | `/api/profile/update-safe` | ✅ Safe merge with key denylist |
| GET  | `/api/prototype-state` | Inspect current Object.prototype pollution |
| POST | `/api/prototype-reset` | Reset Object.prototype to clean state |
| GET  | `/api/admin/users` | Admin-only user list |

---

## Security Lab Features

- **Live prototype monitor** — shows injected keys on `Object.prototype` in real time
- **Side-by-side code** — vulnerable vs safe merge implementation
- **Attack flow diagram** — traces the payload from input to `Object.prototype`
- **Preset payloads** — one-click escalation to admin or field agent
- **Safe merge demo** — shows how a key denylist blocks the attack

---

## Remediation

```js
const BLOCKED = new Set(['__proto__', 'constructor', 'prototype']);

function safeMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (BLOCKED.has(key)) continue;
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = {};
      safeMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
}
```

Use `Object.keys()` instead of `for...in` to avoid inherited properties, and explicitly block dangerous keys before recursing.

---

## Disclaimer

This project is for **educational purposes only**. The vulnerabilities are intentional. Do not use any techniques demonstrated here against systems you do not own.
