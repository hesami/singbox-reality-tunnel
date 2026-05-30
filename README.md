# 🔒 sing-box Setup & Manager

**اسکریپت Bash تعاملی برای استقرار و مدیریت تونل‌های VLESS + REALITY و Hysteria2 با استفاده از [sing-box](https://github.com/SagerNet/sing-box)**

[![version](https://img.shields.io/badge/version-3.0.0-blue?style=flat-square)](https://github.com/hesami/singbox-reality-tunnel/releases)
[![platform](https://img.shields.io/badge/platform-Ubuntu%20%7C%20Debian-orange?style=flat-square)](https://github.com/hesami/singbox-reality-tunnel)
[![protocol](https://img.shields.io/badge/protocol-VLESS%20%2B%20REALITY%20%2B%20Hysteria2-purple?style=flat-square)](https://github.com/hesami/singbox-reality-tunnel)
[![license](https://img.shields.io/badge/license-MIT-green?style=flat-square)](https://github.com/hesami/singbox-reality-tunnel)

---

## 📋 فهرست مطالب

- [معرفی](#-معرفی)
- [معماری](#-معماری)
- [پیش‌نیازها](#-پیشنیازها)
- [راه‌اندازی سریع](#-راهاندازی-سریع)
- [ساختار ماژولار](#-ساختار-ماژولار)
- [منوی اصلی](#-منوی-اصلی)
  - [1. Setup Wizard](#1-setup-wizard)
  - [2. User Management](#2-user-management)
  - [3. Service Control](#3-service-control)
  - [4. SSL / Domain](#4-ssl--domain)
  - [5. Optimization](#5-optimization)
  - [6. Security](#6-security)
  - [7. Update Binaries](#7-update-binaries)
  - [8. Uninstall](#8-uninstall)
  - [9. View Logs](#9-view-logs)
- [ساختار فایل‌ها](#-ساختار-فایلها)
- [فرمت لینک VLESS](#-فرمت-لینک-vless)
- [نکات امنیتی](#-نکات-امنیتی)
- [عیب‌یابی](#-عیبیابی)
- [نویسنده](#-نویسنده)

---

## 🌐 معرفی

**sing-box Setup & Manager** یک اسکریپت Bash تعاملی است که تمام مراحل نصب، پیکربندی، مدیریت کاربران و بهینه‌سازی را برای تونل‌های VLESS + REALITY و Hysteria2 خودکار می‌کند.

در نسخه ۳.۰.۰ معماری اسکریپت به صورت **کاملاً ماژولار** بازنویسی شده — هر قابلیت در یک فایل مجزا قرار دارد و `manager.sh` نقطه ورودی اصلی است که تمام ماژول‌ها را بارگذاری می‌کند.

### ✨ قابلیت‌های کلیدی

- **پشتیبانی از دو پروتکل** — VLESS + REALITY و Hysteria2 روی یک سرور
- **ویزارد نصب یکپارچه** — نصب خودکار، تولید کلید، پیکربندی سرویس systemd، و باز کردن فایروال
- **مدیریت کاربر چندپروتکلی** — افزودن، حذف، فعال/غیرفعال، سهمیه ترافیک، و لینک اشتراک برای VLESS و Hysteria2
- **پشتیبانی از SSL/TLS با Let's Encrypt** — گواهینامه رایگان از طریق acme.sh
- **بهینه‌سازی سیستم** — BBR، بافرهای TCP، swappiness، اولویت CPU، OOM، و file descriptors
- **Fail2ban** — محافظت در برابر حملات brute-force
- **وضعیت real-time** — نمایش لحظه‌ای وضعیت سرویس‌های VLESS، Hysteria2، Auth/Sub، و Fail2ban در بالای منو
- **ایمن از طراحی** — `set -euo pipefail`، تأیید اجباری برای تمام عملیات مخرب

---

## 🏗 معماری

```
┌─────────────────────────────────────────────────────────────┐
│                      Client Device                          │
│              v2rayN / Hiddify / NekoBox                     │
└────────────────────────┬────────────────────────────────────┘
                         │  VLESS + REALITY (TLS 1.3)
                         │  Disguised as: www.speedtest.net
                         ▼
┌─────────────────────────────────────────────────────────────┐
│               Outbound Server  (e.g. Germany)               │
│                  sing-box  [inbound: VLESS]                  │
│               This script — Setup Wizard → Proxy            │
└─────────────────────────────────────────────────────────────┘

         ─ ─ ─ OR use two-hop relay architecture ─ ─ ─

┌────────────────────┐        ┌────────────────────────────────┐
│   Client Device    │        │     Iran Relay Server          │
│  Any SOCKS5 app    │──────▶ │  sing-box [inbound: SOCKS5]    │
└────────────────────┘        │  This script — Tunnel Mode     │
                              └──────────────┬─────────────────┘
                                             │  VLESS + REALITY
                                             ▼
                              ┌─────────────────────────────────┐
                              │   Outbound Server (Germany)     │
                              │  sing-box [inbound: VLESS]      │
                              └─────────────────────────────────┘
```

---

## 📦 پیش‌نیازها

| مؤلفه | الزام |
|---|---|
| **OS** | Ubuntu 20.04 / 22.04 / 24.04 یا Debian 11 / 12 |
| **معماری** | x86_64 (amd64) |
| **کاربر** | root یا sudo |
| **RAM** | حداقل ۵۱۲ مگابایت (۱ گیگابایت پیشنهادی) |
| **دیسک** | ۲ گیگابایت فضای آزاد |
| **شبکه** | دسترسی به GitHub برای دانلود باینری‌ها |
| **وابستگی‌ها** | `curl`، `python3` (در صورت نیاز خودکار نصب می‌شوند) |

> **اختیاری:** `qrencode` برای نمایش QR code در ترمینال، `speedtest-cli` برای تست سرعت — هر دو در صورت نیاز خودکار نصب می‌شوند.

---

## 🚀 راه‌اندازی سریع

```bash
# دانلود و اجرا به عنوان root
wget -O manager.sh https://raw.githubusercontent.com/hesami/singbox-reality-tunnel/main/manager.sh
chmod +x manager.sh
sudo bash manager.sh
```

یا اجرای مستقیم:

```bash
sudo bash <(curl -fsSL https://raw.githubusercontent.com/hesami/singbox-reality-tunnel/main/manager.sh)
```

> **نکته:** برای یک سرور جدید، پس از نصب گزینه **5 → Apply ALL Optimizations** را اجرا کنید.

---

## 🗂 ساختار ماژولار

در نسخه ۳.۰.۰، کد به صورت ماژولار سازمان‌یافته است. `manager.sh` تمام ماژول‌ها را در ابتدای اجرا بارگذاری می‌کند:

```
manager.sh              ← نقطه ورودی اصلی + منوی اصلی
│
├── core/
│   ├── common.sh       ← رنگ‌ها، توابع چاپ، menu_prompt
│   ├── system.sh       ← بررسی root، نصب وابستگی‌ها
│   └── db.sh           ← مدیریت پایگاه داده SQLite کاربران
│
├── protocols/
│   ├── vless.sh        ← نصب، به‌روزرسانی، حذف VLESS + REALITY
│   └── hysteria2.sh    ← نصب، به‌روزرسانی، حذف Hysteria2
│
├── features/
│   ├── ssl.sh          ← مدیریت گواهینامه SSL با acme.sh
│   ├── users.sh        ← مدیریت کاربران (VLESS + Hysteria2)
│   ├── optimization.sh ← BBR، TCP، swap، CPU، FD
│   └── security.sh     ← Fail2ban
│
└── wizard/
    ├── install.sh      ← ویزارد نصب تعاملی
    └── tunnel.sh       ← پیکربندی تونل relay
```

---

## 📖 منوی اصلی

در بالای هر منو، یک **نوار وضعیت real-time** نمایش داده می‌شود:

```
 Services : ● VLESS ○ Hysteria2 ● Auth/Sub ● Fail2ban
 Users    : 5  Domain: vpn.example.com
```

---

### 1. Setup Wizard

ویزارد تعاملی برای نصب اولیه. دو حالت را پوشش می‌دهد:

**حالت Proxy (سرور outbound):**
1. دانلود آخرین نسخه stable یا pre-release sing-box از GitHub
2. دریافت پارامترها از کاربر: UUID (خودکار یا دستی)، پورت (پیش‌فرض: `443`)، SNI (پیش‌فرض: `www.speedtest.net`)، Short ID
3. تولید keypair جدید REALITY
4. نوشتن `/etc/sing-box/config.json` و `/etc/sing-box/server.json`
5. ایجاد و فعال‌سازی سرویس systemd
6. باز کردن پورت در UFW / iptables
7. نمایش **لینک VLESS** کامل + **QR code**

**حالت Tunnel (relay):**
- استقرار sing-box به عنوان یک پروکسی SOCKS5 محلی که ترافیک را به سرور outbound هدایت می‌کند
- تست خودکار تونل پس از نصب
- سرویس systemd: `sing-box-client.service`

---

### 2. User Management

مدیریت کامل چرخه کاربران برای هر دو پروتکل:

```
┌──────────────────────────────────────────────────────────────────────────┐
│  No.  UUID / Username          Label     Quota        Used     Status    │
│  ────────────────────────────────────────────────────────────────────────│
│  1    550e8400...440000        default   Unlimited    0.0 MB   ON        │
│  2    alice                   Alice     50 GB        12.4 GB  ON        │
│  3    bob                     Bob       10 GB        9.8 GB   OFF       │
└──────────────────────────────────────────────────────────────────────────┘
```

| گزینه | توضیح |
|---|---|
| **افزودن کاربر** | تولید UUID/رمز، تنظیم label، سهمیه ترافیک، تاریخ انقضا — چاپ لینک + QR |
| **مشاهده جزئیات** | نمایش اطلاعات کامل + لینک اشتراک + QR code |
| **ویرایش سهمیه** | تغییر لحظه‌ای سهمیه ترافیک (۰ = نامحدود) |
| **فعال / غیرفعال** | تغییر وضعیت بدون نیاز به ری‌استارت سرویس |
| **تنظیم انقضا** | غیرفعال‌سازی خودکار کاربر در تاریخ مشخص |
| **ریست ترافیک** | صفر کردن شمارنده مصرف کاربر |
| **حذف کاربر** | حذف دائمی از پایگاه داده و پیکربندی |

**ذخیره‌سازی:** داده کاربران در `/etc/sing-box/users.json` (VLESS) و SQLite در `/etc/hysteria/users.db` (Hysteria2) نگه‌داری می‌شود.

---

### 3. Service Control

کنترل تمام سرویس‌ها از یک منو:

| سرویس | توضیح |
|---|---|
| `sing-box` | سرور VLESS + REALITY |
| `sing-box-client` | کلاینت تونل relay |
| `hysteria-server` | سرور Hysteria2 |
| `hysteria-auth` | سرویس Auth + Subscription API |

برای هر سرویس: **Start، Stop، Restart، مشاهده live log** (Ctrl+C برای خروج)

همچنین گزینه **Restart ALL** برای ری‌استارت یکجای تمام سرویس‌های فعال.

---

### 4. SSL / Domain

مدیریت گواهینامه SSL رایگان از طریق **acme.sh** و Let's Encrypt:

- صدور گواهینامه برای دامنه دلخواه
- تمدید خودکار با cron
- تنظیم hook برای ری‌لود سرویس‌ها پس از تمدید
- حذف و ابطال گواهینامه

پس از تنظیم دامنه، نام دامنه در نوار وضعیت بالای منو نمایش داده می‌شود.

---

### 5. Optimization

یک مجموعه بهینه‌سازی سه‌سطحی برای سرورهای VPS با منابع محدود:

#### 5.1 — شبکه: BBR و TCP

| گزینه | عملکرد |
|---|---|
| **Enable BBR + FQ** | تنظیم `tcp_congestion_control=bbr` و `default_qdisc=fq` |
| **Disable BBR** | بازگشت به `cubic` |
| **TCP buffer & keepalive** | افزایش `rmem_max`/`wmem_max` به ۱۲۸ MB؛ فعال‌سازی `tcp_fastopen`، `tcp_mtu_probing`، keepalive با تنظیمات بهینه |
| **Show values** | نمایش مقادیر فعلی sysctl |

#### 5.2 — سیستم: حافظه و اولویت CPU

| گزینه | عملکرد |
|---|---|
| **Optimize swap** | `vm.swappiness=10`، `vm.vfs_cache_pressure=50` |
| **CPU priority** | تنظیم `Nice=-5` برای sing-box در systemd |
| **OOM protection** | `OOMScoreAdjust=-500` — کرنل sing-box را kill نمی‌کند |
| **Apply all** | هر سه گزینه با یک دستور |

#### 5.3 — ذخیره‌سازی: لاگ و File Descriptors

| گزینه | عملکرد |
|---|---|
| **Limit journald** | محدودیت ۵۰ MB برای journal؛ vacuum فوری |
| **File descriptors** | افزایش `fs.file-max` به ۱،۰۴۸،۵۷۶ |

#### 5.4 — Apply ALL Optimizations ⭐

اجرای ۶ مرحله به ترتیب با نشانگر پیشرفت. **پیشنهاد: بلافاصله بعد از نصب اجرا شود.**

```
── 1/6  BBR + FQ ──────────────────
── 2/6  TCP Buffers & Keepalive ───
── 3/6  Swap & Cache ──────────────
── 4/6  CPU & OOM Priority ────────
── 5/6  File Descriptors ──────────
── 6/6  Journald Size ─────────────
```

#### 5.5 — Reset ALL to Defaults

حذف کامل تمام بهینه‌سازی‌های اعمال‌شده و بازگشت به وضعیت اولیه سیستم.

---

### 6. Security

محافظت در برابر حملات brute-force با **Fail2ban**:

تشخیص خودکار backend لاگ (journal systemd یا فایل `/var/log/sing-box/sing-box.log`).

| گزینه | توضیح |
|---|---|
| **Install & configure** | نصب fail2ban + rsyslog، تنظیم فیلتر و jail |
| **Show banned IPs** | لیست تمام IPهای مسدود شده |
| **Unban an IP** | رفع مسدودیت یک IP خاص |
| **Change ban settings** | تغییر `maxretry`، `findtime`، `bantime` |
| **Start / Stop** | کنترل سرویس fail2ban |
| **Show live log** | نمایش `tail -f /var/log/fail2ban.log` |
| **Uninstall** | حذف کامل fail2ban و تمام فایل‌های پیکربندی |

**تنظیمات پیش‌فرض:**

```
maxretry = 5 تلاش
findtime = 60 ثانیه
bantime  = 3600 ثانیه (۱ ساعت)
action   = iptables-allports (مسدود کردن تمام پورت‌ها)
```

---

### 7. Update Binaries

به‌روزرسانی باینری‌ها بدون از دست دادن پیکربندی:

```
 sing-box  : 1.10.2
 hysteria2 : 2.6.0
```

| گزینه | توضیح |
|---|---|
| **Update sing-box** | دانلود آخرین نسخه از GitHub، جایگزینی باینری |
| **Update Hysteria2** | به‌روزرسانی باینری Hysteria2 |
| **Update both** | هر دو با یک دستور |
| **Update this manager** | دانلود آخرین نسخه تمام ماژول‌ها از GitHub با بکاپ خودکار |

**Self-Update:** فایل‌های بکاپ با timestamp ذخیره می‌شوند. در صورت شکست بیش از ۳ فایل، عملیات لغو می‌شود.

---

### 8. Uninstall

حذف انتخابی یا کامل:

| گزینه | توضیح |
|---|---|
| **Remove VLESS + Reality** | حذف sing-box و پیکربندی آن |
| **Remove Hysteria2** | حذف hysteria-server و پیکربندی |
| **Remove EVERYTHING** | ریست کامل — تمام باینری‌ها، پیکربندی‌ها، کاربران، SSL، cron، sysctl، fail2ban |

> ⚠️ عملیات **برگشت‌ناپذیر** است. اسکریپت قبل از اجرا تأیید صریح می‌خواهد.

---

### 9. View Logs

| گزینه | توضیح |
|---|---|
| **VLESS server log** | `journalctl -u sing-box -f` |
| **Hysteria2 server log** | `journalctl -u hysteria-server -f` |
| **Auth + Sub API log** | `journalctl -u hysteria-auth -f` |
| **Traffic sync log** | آخرین ۵۰ خط از لاگ sync ترافیک |
| **Manager log** | لاگ داخلی manager |
| **Fail2ban log** | `journalctl -u fail2ban -f` |

---

## 📁 ساختار فایل‌ها

```
/usr/local/bin/
├── sing-box                         # باینری sing-box
└── hysteria                         # باینری Hysteria2

/etc/sing-box/
├── config.json                      # پیکربندی VLESS (inbound/outbound)
├── server.json                      # هویت سرور (keypair، SNI، پورت)
└── users.json                       # پایگاه داده کاربران VLESS

/etc/hysteria/
├── config.yaml                      # پیکربندی Hysteria2
├── server.json                      # هویت سرور Hysteria2
├── users.db                         # SQLite: اعتبارنامه، سهمیه، انقضا
├── auth_api.py                      # Flask auth + subscription (پورت 18989)
└── sync_traffic.py                  # sync ترافیک (هر ۲ دقیقه یک‌بار)

/etc/singbox-manager/
├── domain.conf                      # تنظیمات دامنه و SSL
└── ssl_reload_hook.sh               # hook تمدید خودکار SSL

/etc/systemd/system/
├── sing-box.service                 # سرویس VLESS
├── sing-box-client.service          # سرویس کلاینت تونل
├── hysteria-server.service          # سرویس Hysteria2
├── hysteria-auth.service            # سرویس Auth/Sub API
└── sing-box.service.d/
    └── priority.conf                # drop-in CPU/OOM/FD

/var/log/singbox-manager/
├── hy2_sync.log                     # لاگ sync ترافیک Hysteria2
└── vless_sync.log                   # لاگ sync ترافیک VLESS

/etc/fail2ban/
├── jail.local                       # پیکربندی jail
└── filter.d/singbox.conf            # فیلتر لاگ REALITY/Hysteria2
```

---

## 🔗 فرمت لینک VLESS

لینک‌های تولیدشده با **v2rayN**، **Hiddify**، **NekoBox**، **v2rayNG** و سایر کلاینت‌های VLESS استاندارد سازگار هستند:

```
vless://<UUID>@<SERVER_IP>:<PORT>
  ?encryption=none
  &flow=xtls-rprx-vision
  &security=reality
  &sni=<SNI>
  &fp=chrome
  &pbk=<PUBLIC_KEY>
  &sid=<SHORT_ID>
  &type=tcp
  &headerType=none
  #<LABEL>
```

| پارامتر | توضیح |
|---|---|
| `flow` | `xtls-rprx-vision` — الزامی برای REALITY |
| `security` | `reality` — TLS 1.3 با handshake REALITY |
| `sni` | دامنه camouflage (مثلاً `www.speedtest.net`) |
| `fp` | اثر انگشت TLS — `chrome` |
| `pbk` | کلید عمومی REALITY سرور |
| `sid` | Short ID برای تأیید handshake |

---

## 🔐 نکات امنیتی

- **کلید خصوصی REALITY** فقط در سرور در `/etc/sing-box/server.json` ذخیره می‌شود. هرگز آن را به اشتراک نگذارید.
- **UUID** به عنوان credential کاربر عمل می‌کند — مثل رمز عبور با آن رفتار کنید.
- اسکریپت از `set -euo pipefail` استفاده می‌کند — در صورت بروز هر خطای غیرمنتظره بلافاصله متوقف می‌شود.
- تمام عملیات مخرب (حذف کاربر، uninstall، ریست کامل) نیاز به تأیید صریح `y/n` دارند.
- `iptables-allports` در Fail2ban تمام پورت‌ها را برای IP مسدود مسدود می‌کند.
- تنظیم OOM score به `-500` تضمین می‌کند که کرنل sing-box را به دلیل فشار حافظه kill نمی‌کند.

---

## 🛠 عیب‌یابی

**سرویس بعد از نصب راه‌اندازی نمی‌شود:**
```bash
journalctl -u sing-box --no-pager -n 30
```

**بررسی اشغال بودن پورت:**
```bash
ss -tlnp | grep :443
```

**تست اتصال VLESS به صورت دستی:**
```bash
curl -v --connect-timeout 5 https://<SERVER_IP>
# باید یک اتصال TLS برگرداند (شبیه‌سازی سایت SNI)
```

**Fail2ban راه‌اندازی نمی‌شود:**
```bash
journalctl -u fail2ban --no-pager -n 30
fail2ban-client --test
```

**پینگ بالا یا packet loss:**
```bash
# بررسی CPU steal time (steal بالا = همسایه نویزی در VPS)
top   # به ستون 'st' در خط CPU توجه کنید

# تأیید فعال بودن BBR
sysctl net.ipv4.tcp_congestion_control

# بررسی فشار حافظه
free -m
```

---

## 👤 نویسنده

**Mehdi Hesami**

- نسخه اسکریپت: `3.0.0`
- پروتکل‌ها: VLESS + REALITY و Hysteria2
- تست‌شده روی: Ubuntu 22.04 LTS

---

اگر این پروژه برایتان مفید بود، با دادن ⭐ در GitHub حمایت کنید.
