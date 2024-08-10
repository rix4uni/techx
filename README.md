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
```
Usage of techx:
  -H string
        Custom User-Agent header for HTTP requests. (default "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36")
  -csv
        Output in CSV format
  -insecure
        Disable TLS verification.
  -json
        Output in JSON format
  -o string
        File to save output (default is stdout)
  -retries int
        Number of retry attempts for failed HTTP requests. (default 1)
  -retriesdelay int
        Delay in seconds between retry attempts.
  -t int
        Number of threads to utilize. (default 8)
  -timeout int
        Maximum time to crawl each URL from stdin, in seconds. (default 15)
  -verbose
        Enable verbose output for debugging purposes.
  -version
        Print the version of the tool and exit.
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
