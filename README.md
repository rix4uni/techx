# techx

# Installation
```
go install github.com/rix4uni/techx@latest
```

##### via clone command
```
git clone https://github.com/rix4uni/techx.git && cd techx && go build techx.go && mv techx ~/go/bin/techx && cd .. && rm -rf techx
```

##### via binary
```
wget https://github.com/rix4uni/techx/releases/download/v0.0.1/techx-linux-amd64-0.0.1.tgz && tar -xvzf techx-linux-amd64-0.0.1.tgz && rm -rf techx-linux-amd64-0.0.1.tgz && mv techx ~/go/bin/techx
```

##### Usage
```console
techx is a technologies detector tool using the projectdiscovery wappalyzergo library.

Usage:
  ./techx [flags]

Flags:
OUTPUT:
   -o, -output string  File to save output (default is stdout)
   -json               Output in JSON format
   -csv                Output in CSV format

RATE-LIMIT:
   -t, -threads int  Number of threads to use (default 50)

CONFIGURATIONS:
   -ua string                    Custom User-Agent header for HTTP requests (default "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36")
   -discord                      Send Matched tech to Discord, Very useful with gungnir because gungnir is gives real-time stdout
   -id string                    Discord id to send the notification (default "general")
   -pc, -provider-config string  provider config path (default "/root/.config/notify/provider-config.yaml")

MATCHERS:
   -mt, -match-tech string  File containing match values (.txt file) or comma-separated list of match values

DEBUG:
   -v, -verbose  Enable verbose output for debugging purposes
   -V, -version  Print the version of the tool and exit
   -sl, -silent  silent mode

OPTIMIZATIONS:
   -retries int            Number of retry attempts for failed HTTP requests (default 1)
   -timeout int            Delay in seconds between retry attempts (default 10)
   -rd, -retriesDelay int  Delay in seconds between retry attempts
   -i, -insecure           Disable TLS verification
   -delay value            duration between each http request (eg: 200ms, 1s) (default -1ns)
```

# Output Examples

Single URL:
```
echo "https://hackerone.com" | techx
```

Multiple URLs:
```
cat urls.txt | techx
```

# Plain text
```
cat urls.txt | techx
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

# JSON format
```
cat urls.txt | techx -json
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
{
  "host": "https://www.intigriti.com",
  "count": 4,
  "tech": [
    "CookieYes",
    "DatoCMS",
    "HSTS",
    "Vercel"
  ]
}
{
  "host": "https://bugcrowd.com",
  "count": 16,
  "tech": [
    "Bootstrap",
    "Fastly",
    "HSTS",
    "MariaDB",
    "Marketo Forms:2",
    "MySQL",
    "Nginx",
    "OneTrust",
    "PHP",
    "Pantheon",
    "Slick",
    "Varnish",
    "WordPress",
    "Yoast SEO:22.8",
    "jQuery",
    "jQuery UI"
  ]
}
```

# CSV format
```
cat urls.txt | techx -csv
host,count,tech
https://bugcrowd.com,16,"Bootstrap, Fastly, HSTS, MariaDB, Marketo Forms:2, MySQL, Nginx, OneTrust, PHP, Pantheon, Slick, Varnish, WordPress, Yoast SEO:22.8, jQuery, jQuery UI"
https://www.intigriti.com,4,"CookieYes, DatoCMS, HSTS, Vercel"
https://hackerone.com,14,"Cloudflare, Drupal:10, Fastly, Google Tag Manager, HSTS, MariaDB, Marketo Forms:2, Nginx, Optimizely, PHP, Pantheon, TrustArc, Varnish, YouTube"
```

# TODO
- tls improvement needed
- without -discord flag user also can run 
