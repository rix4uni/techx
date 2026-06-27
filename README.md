## techfinder

A high-performance technology detection tool built with Go with **inlined wappalyzergo fingerprinting engine** — no external dependencies. Detects web technologies and frameworks including dynamically loaded JS frameworks like **React, Next.js, Vue, Svelte, Framer Motion** via headless browser support with reusable browser pool for massive speed improvements on bulk scans.

## 🚀 Features

- **🧠 Headless Detection (default)**: Uses real headless Chrome with **browser pool** (~30x faster for bulk scans)
- **⚡ Fast Static Mode**: High-speed HTTP-only detection for large-scale scans
- **🔧 Multi-threaded**: Concurrent processing with configurable browser pool size
- **📄 Multiple Output Formats**: Plain text, JSON, and CSV support
- **🎯 Tech Matching**: Filter & alert on specific technologies
- **💬 Discord Integration**: Send detections directly to Discord
- **♻️ Crash-Safe Resume**: Default-on resume with `resume.cfg`; use `--no-resume` to start fresh
- **📦 Auto-Download**: Automatically downloads fingerprint data files on first run

## 📦 Installation

### Using Go Install
```
go install github.com/rix4uni/techfinder@latest
```

### Download Prebuilt Binaries
```
wget https://github.com/rix4uni/techfinder/releases/download/v0.1.0/techfinder-linux-amd64-0.1.0.tgz
tar -xvzf techfinder-linux-amd64-0.1.0.tgz
rm -rf techfinder-linux-amd64-0.1.0.tgz
mv techfinder ~/go/bin/techfinder
```

Or download [binary release](https://github.com/rix4uni/techfinder/releases) for your platform.

### Compile from Source
```
git clone --depth 1 https://github.com/rix4uni/techfinder.git
cd techfinder; go install
```

## 🔧 Usage
```console
A high-performance technology detection tool built with Go, leveraging the rix4uni wappalyzergo library to identify web technologies and frameworks.

Usage:
  techfinder [flags]

Flags:
OUTPUT:
   -o, -output string  File to save output (default is stdout)
   -json               Output in JSON format
   -csv                Output in CSV format

RATE-LIMIT:
   -t, -threads int  Number of threads to use (default 50)

CONFIGURATIONS:
   -H, -user-agent string        Custom User-Agent header for HTTP requests (default "Mozilla/5.0 ...")
   -discord                      Send Matched tech to Discord
   -id string                    Discord id to send the notification (default "alivesubdomain")
   -pc, -provider-config string  provider config path (default "/root/.config/notify/provider-config.yaml")
   -no-resume                    Disable resume functionality and start scanning fresh

MATCHERS:
   -mt, -match-tech string  Send matched tech output to Discord (comma-separated, file) (default "/root/.config/techfinder/technologies.txt")

DEBUG:
   -verbose  Enable verbose output for debugging purposes
   -version  Print the version of the tool and exit
   -silent   silent mode

OPTIMIZATIONS:
   -retries int            Number of retry attempts for failed HTTP requests (default 1)
   -timeout int            HTTP request timeout in seconds (default 15)
   -headless-timeout int   Headless browser timeout in seconds (browser launch + navigation + JS execution) (default 30)
   -rd, -retriesDelay int  Delay in seconds between retry attempts
   -i, -insecure           Disable TLS verification
   -delay value            duration between each http request (eg: 200ms, 1s) (default -1ns)
   -rate int               Maximum requests per second (0 = unlimited)
   -mode string            Detection mode: 'best' uses headless browser for JS/DOM fingerprinting (default), 'fast' uses static HTTP only (default "best")
   -browser-pool-size int  Number of headless browsers to keep in pool (only for 'best' mode, max 20) (default 5)
```

## 🧠 Detection Modes

techfinder supports two detection modes controlled by the `-mode` flag:

### `-mode best` (Default — Headless Browser with Pool)

Uses **reusable browser pool** (default 5 browsers) for massive speedup on bulk scans. Each browser executes page JavaScript and evaluates:
- **JS globals** (e.g. `window.React.version`, `window.__NEXT_DATA__`)
- **DOM selectors** (e.g. `.swiper`, `[data-framer]`)
- Fully rendered HTML after JS hydration

This catches technologies invisible to static HTTP requests.

**Browser Pool Benefits:**
- **~30x faster** for bulk scanning (50k subdomains: ~41h → ~1.4h)
- Pre-initialized browsers eliminate per-URL launch overhead (~3s → ~0.5s)
- Configurable pool size: `-browser-pool-size 10`

```console
echo "https://www.cetus.zone" | techfinder -mode best -silent

URL: https://www.cetus.zone
Count: 17
Technologies: [Amazon CloudFront, Amazon Web Services, Framer Motion, HSTS, LottieFiles, Netlify, Next.js App Router, Next.js:14.2.16, Node.js, Open Graph, Priority Hints, React, Svelte, SvelteKit, Swiper, Vite, Webpack]
```

### `-mode fast` (Static HTTP Only)

Uses plain HTTP GET requests only — no browser, no JS execution. Best for large-scale scanning where speed matters more than completeness.

```console
echo "https://www.cetus.zone" | techfinder -mode fast -silent

URL: https://www.cetus.zone
Count: 4
Technologies: [Amazon CloudFront, Amazon Web Services, HSTS, Netlify]
```

> **Note:** In `best` mode, if headless Chrome fails for a URL (e.g. network timeout, browser not installed), techfinder reports the error and skips the URL. The browser pool automatically recycles browser instances. If pool fails to initialize, falls back to creating new browser per URL.

## 📊 Output Examples

Single URL:
```console
echo "https://hackerone.com" | techfinder
```

Multiple URLs:
```console
cat urls.txt | techfinder
```

Start fresh without resuming:
```console
cat urls.txt | techfinder --no-resume
```

## Plain text
```console
cat urls.txt | techfinder -mode fast
URL: https://hackerone.com
Count: 14
Technologies: [Cloudflare, Drupal:10, Fastly, Google Tag Manager, HSTS, MariaDB, Marketo Forms:2, Nginx, Optimizely, PHP, Pantheon, TrustArc, Varnish, YouTube]

URL: https://bugcrowd.com
Count: 16
Technologies: [Bootstrap, Fastly, HSTS, MariaDB, Marketo Forms:2, MySQL, Nginx, OneTrust, PHP, Pantheon, Slick, Varnish, WordPress, Yoast SEO:22.8, jQuery, jQuery UI]

URL: https://www.intigriti.com
Count: 4
Technologies: [CookieYes, DatoCMS, HSTS, Vercel]
```

## JSON format
```console
cat urls.txt | techfinder -json
{
  "host": "https://hackerone.com",
  "count": 14,
  "tech": [
    "Cloudflare",
    "Drupal:10",
    "Fastly",
    "Google Tag Manager",
    "HSTS",
    "MariaDB",
    "Marketo Forms:2",
    "Nginx",
    "Optimizely",
    "PHP",
    "Pantheon",
    "TrustArc",
    "Varnish",
    "YouTube"
  ]
}
```

## CSV format
```console
cat urls.txt | techfinder -csv
host,count,tech
https://bugcrowd.com,16,"Bootstrap, Fastly, HSTS, MariaDB, Marketo Forms:2, MySQL, Nginx, OneTrust, PHP, Pantheon, Slick, Varnish, WordPress, Yoast SEO:22.8, jQuery, jQuery UI"
https://www.intigriti.com,4,"CookieYes, DatoCMS, HSTS, Vercel"
https://hackerone.com,14,"Cloudflare, Drupal:10, Fastly, Google Tag Manager, HSTS, MariaDB, Marketo Forms:2, Nginx, Optimizely, PHP, Pantheon, TrustArc, Varnish, YouTube"
```

## ⚙️ Configuration Flags

### Output Options
| Flag | Description | Default |
|------|-------------|---------|
| `-o, -output` | Save output to file | stdout |
| `-json` | Output in JSON format | false |
| `-csv` | Output in CSV format | false |

### Rate Limiting
| Flag | Description | Default |
|------|-------------|---------|
| `-t, -threads` | Number of concurrent threads | 50 |
| `-delay` | Delay between HTTP requests (e.g., 200ms, 1s) | -1ns |
| `-retries` | Retry attempts for failed requests | 1 |
| `-rd, -retriesDelay` | Delay between retries (seconds) | 0 |
| `-rate` | Maximum requests per second (0 = unlimited) | 0 |

### HTTP Configuration
| Flag | Description | Default |
|------|-------------|---------|
| `-H, -user-agent` | Custom User-Agent string | Mozilla/5.0 (Windows NT 10.0...) |
| `-timeout` | HTTP request timeout in seconds | 15 |
| `-headless-timeout` | Headless browser timeout (launch + navigation + JS) | 30 |
| `-i, -insecure` | Disable TLS verification | false |
| `--no-resume` | Disable resume; start fresh | false |

### Detection Mode
| Flag | Description | Default |
|------|-------------|---------|
| `-mode` | `best` = headless browser (JS/DOM), `fast` = static HTTP only | `best` |
| `-headless-timeout` | Timeout for headless browser operations (seconds) | 30 |
| `-browser-pool-size` | Number of browsers in pool (1-20, best mode only) | 5 |

### Matchers & Notifications
| Flag | Description | Default |
|------|-------------|---------|
| `-mt, -match-tech` | Match specific technologies (file or comma-separated) | - |
| `-discord` | Send results to Discord | false |
| `-id` | Discord channel ID for notifications | alivesubdomain |
| `-pc, -provider-config` | Notify provider config path | ~/.config/notify/provider-config.yaml |

### Debug & Info
| Flag | Description |
|------|-------------|
| `-verbose` | Enable verbose debugging output |
| `-silent` | Enable silent mode |
| `-version` | Show version information |

## 🔍 Advanced Usage

### Technology Matching
```console
# Match specific technologies
echo "https://example.com" | techfinder -mt "wordpress,php,nginx,react,nextjs"

# Use match file
echo "https://example.com" | techfinder -mt technologies.txt
```

### Discord Integration
```console
# Send results to Discord
cat urls.txt | techfinder -discord -id "tech-scans"
```

### Save Results to File
```console
# JSON output to file
cat urls.txt | techfinder -json -o results.json

# CSV output to file
cat urls.txt | techfinder -csv -o results.csv
```

## 🛠️ Performance Tuning

For large-scale scans where speed is critical, use `-mode fast` to skip headless Chrome:
```console
# Fast static mode — no browser overhead
cat large_targets.txt | techfinder -mode fast -t 200 -timeout 10 -retries 2 -rate 500
```

For accuracy-focused scans on a smaller set of targets, use the default headless mode with browser pool:
```console
# Best accuracy with browser pool (default 5 browsers)
cat targets.txt | techfinder -mode best -t 20 -timeout 15 -headless-timeout 45

# Larger pool for faster bulk scanning (use with sufficient RAM)
cat targets.txt | techfinder -mode best -browser-pool-size 10 -t 50
```

## ♻️ Resume & Interrupt Handling

- Default-on resume saves progress to a `resume.cfg` in the current directory:

```console
scanned=300000
```

- Re-run the same command in the same directory to resume; the scanner skips the first `scanned` items and continues.
- Use `--no-resume` to start from scratch.
- On successful completion, `resume.cfg` is deleted automatically.
- On CTRL+C, pending tasks are cancelled gracefully and progress is saved before exiting with a helpful resume hint.

## 🗂️ Fingerprint Data Files

techfinder automatically downloads required fingerprint data files on first run:
- `fingerprints_data.json` (~3.7MB) — Technology fingerprints
- `categories_data.json` — Category mappings

Files are stored in `~/.config/techfinder/` and auto-downloaded from GitHub if missing.

**Manual Setup (optional):**
```console
mkdir -p ~/.config/techfinder
cd ~/.config/techfinder
wget https://raw.githubusercontent.com/projectdiscovery/wappalyzergo/refs/heads/main/fingerprints_data.json
wget https://raw.githubusercontent.com/projectdiscovery/wappalyzergo/refs/heads/main/categories_data.json
```

## 🏗️ Architecture

techfinder now has **inlined wappalyzergo** — all fingerprinting logic is embedded directly in `techfinder.go`:
- No external `wappalyzergo` dependency
- Direct control over all fingerprinting code
- Runtime-loaded JSON data (not embedded, keeps binary smaller)
- Reusable browser pool for headless mode performance
