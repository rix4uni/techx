## techfinder

Detects web technologies and frameworks like React, Next.js, Vue, Svelte, and Framer Motion with headless browser support for fast bulk scanning.

## 📦 Installation

### Using Go Install
```
go install github.com/rix4uni/techfinder@latest
```

### Download Prebuilt Binaries
```
wget https://github.com/rix4uni/techfinder/releases/download/v2.0.0/techfinder-linux-amd64-2.0.0.tgz
tar -xvzf techfinder-linux-amd64-2.0.0.tgz
rm -rf techfinder-linux-amd64-2.0.0.tgz
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
Detects web technologies and frameworks like React, Next.js, Vue, Svelte, and Framer Motion with headless browser support for fast bulk scanning.

Usage:
  techfinder [flags]

Flags:
OUTPUT:
   -o, -output string  File to save output (default is stdout)
   -json               Output in JSON format
   -csv                Output in CSV format
   -nc, -no-color      Disable color in output

RATE-LIMIT:
   -t, -threads int  Number of threads to use (default 50)

CONFIGURATIONS:
   -H, -user-agent string        Custom User-Agent header for HTTP requests (default "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36")
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
   -timeout int            HTTP request timeout in seconds for fingerprinting and initial protocol probing (default 15)
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

## 📊 Output Examples

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
