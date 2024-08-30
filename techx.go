package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

const version = "0.0.1"

func printVersion() {
	fmt.Printf("techx version %s\n", version)
}

// Result structure for JSON output
type Result struct {
	Host  string   `json:"host"`
	Count int      `json:"count"`
	Tech  []string `json:"tech"`
}

func probeDomain(domain string, timeout int, userAgent string, client *http.Client) (string, string) {
	// Attempt HTTPS first
	url := "https://" + domain
	if isReachable(url, timeout, userAgent, client) {
		return url, "https://"
	}

	// Fallback to HTTP
	url = "http://" + domain
	if isReachable(url, timeout, userAgent, client) {
		return url, "http://"
	}

	// Return empty values if both attempts fail
	return "", ""
}

func isReachable(url string, timeout int, userAgent string, client *http.Client) bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode >= 200 && resp.StatusCode < 400 // Consider status codes 200-399 as reachable
}

func main() {
	// Define the flags
	jsonOutput := flag.Bool("json", false, "Output in JSON format")
	csvOutput := flag.Bool("csv", false, "Output in CSV format")
	outputFile := flag.String("o", "", "File to save output (default is stdout)")
	versionFlag := flag.Bool("version", false, "Print the version of the tool and exit.")
	timeout := flag.Int("timeout", 15, "Maximum time to crawl each URL from stdin, in seconds.")
	insecure := flag.Bool("insecure", false, "Disable TLS verification.")
	userAgent := flag.String("H", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36", "Custom User-Agent header for HTTP requests.")
	verbose := flag.Bool("verbose", false, "Enable verbose output for debugging purposes.")
	retries := flag.Int("retries", 1, "Number of retry attempts for failed HTTP requests.")
	retriesDelay := flag.Int("retriesdelay", 0, "Delay in seconds between retry attempts.")
	threads := flag.Int("t", 50, "Number of threads to utilize.")
	// probe := flag.Bool("probe", false, "Probe domain to determine if http:// or https:// should be used")
	flag.Parse()

	// Print version and exit if --version flag is provided
	if *versionFlag {
		printVersion()
		return
	}

	// Initialize Wappalyzer client
	wappalyzerClient, err := wappalyzer.New()
	if err != nil {
		if *verbose {
			fmt.Printf("Error initializing Wappalyzer client: %v\n", err)
		}
		os.Exit(1)
	}

	// Initialize HTTP client with optional TLS verification
	var httpClient *http.Client
	if *insecure {
		httpClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
	} else {
		httpClient = &http.Client{}
	}

	// Initialize writers
	var writers []io.Writer
	if *outputFile != "" {
		file, err := os.Create(*outputFile)
		if err != nil {
			if *verbose {
				fmt.Printf("Failed to create file %s: %v\n", *outputFile, err)
			}
			os.Exit(1)
		}
		defer file.Close()
		writers = append(writers, file)
	}
	// Always append stdout (terminal) to writers
	writers = append(writers, os.Stdout)

	// Use MultiWriter to write to multiple destinations
	writer := io.MultiWriter(writers...)

	// Create a CSV writer if the -csv flag is used
	var csvWriter *csv.Writer
	if *csvOutput {
		csvWriter = csv.NewWriter(writer)
		// Write CSV headers
		if err := csvWriter.Write([]string{"host", "count", "tech"}); err != nil {
			if *verbose {
				fmt.Printf("Error writing header to CSV: %v\n", err)
			}
			os.Exit(1)
		}
	}

	// Create a channel for URLs and a wait group
	urlChan := make(chan string)
	var wg sync.WaitGroup
	sem := make(chan struct{}, *threads) // Semaphore to limit the number of concurrent threads
	var mu sync.Mutex // Mutex for synchronized output

	// Worker function to process URLs
	worker := func() {
		for url := range urlChan {
			if *verbose {
				mu.Lock()
				fmt.Printf("Processing URL: %s\n", url)
				mu.Unlock()
			}

			var resp *http.Response
			var fetchErr error

			// Retry logic
			for i := 0; i < *retries; i++ {
				// Set up HTTP request with timeout
				ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*timeout)*time.Second)
				defer cancel()

				req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
				if err != nil {
					if *verbose {
						mu.Lock()
						fmt.Printf("Failed to create request for %s: %v\n", url, err)
						mu.Unlock()
					}
					continue
				}

				// Set the custom User-Agent header
				req.Header.Set("User-Agent", *userAgent)

				resp, fetchErr = httpClient.Do(req)
				if fetchErr == nil {
					break // Exit retry loop if request is successful
				}

				if *verbose {
					mu.Lock()
					fmt.Printf("Retrying %s (%d/%d): %v\n", url, i+1, *retries, fetchErr)
					mu.Unlock()
				}

				if *retriesDelay > 0 {
					time.Sleep(time.Duration(*retriesDelay) * time.Second) // Delay before retry
				}
			}

			if fetchErr != nil {
				if *verbose {
					mu.Lock()
					fmt.Printf("Failed to fetch %s after %d retries: %v\n", url, *retries, fetchErr)
					mu.Unlock()
				}
				continue
			}
			data, _ := io.ReadAll(resp.Body)
			resp.Body.Close() // Close the body after reading

			// Fingerprint the URL
			fingerprints := wappalyzerClient.Fingerprint(resp.Header, data)

			// Convert fingerprints to a slice of strings and sort
			var tech []string
			for name := range fingerprints {
				tech = append(tech, name)
			}
			sort.Strings(tech) // Sort the technologies alphabetically
			count := len(tech)  // Count the number of detected technologies

			if *verbose {
				mu.Lock()
				fmt.Printf("Detected technologies for %s: %v\n", url, tech)
				mu.Unlock()
			}

			// Output the result based on the flags
			if *jsonOutput {
				result := Result{
					Host:  url,
					Count: count,
					Tech:  tech,
				}
				jsonData, _ := json.MarshalIndent(result, "", "  ")
				mu.Lock()
				fmt.Fprintln(writer, string(jsonData))
				mu.Unlock()
			} else if *csvOutput {
				// Write CSV output
				record := []string{url, fmt.Sprintf("%d", count), strings.Join(tech, ", ")}
				mu.Lock()
				if err := csvWriter.Write(record); err != nil {
					fmt.Printf("Error writing record to CSV: %v\n", err)
					os.Exit(1)
				}
				csvWriter.Flush()
				mu.Unlock()
			} else {
				mu.Lock()
				fmt.Fprintf(writer, "URL: %s\nCount: %d\nTechnologies: [%s]\n\n", url, count, strings.Join(tech, ", "))
				mu.Unlock()
			}

			// Release the semaphore
			<-sem
		}
	}

	// Start worker goroutines
	for i := 0; i < *threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			worker()
		}()
	}

	// Reading URLs from stdin and sending them to the channel
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		url := scanner.Text()

		// Probe logic: Check if the domain needs probing
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			// Probe the domain to determine the correct scheme
			probedURL, scheme := probeDomain(url, *timeout, *userAgent, httpClient)
			
			// If probing fails (i.e., both https:// and http:// fail), skip this URL
			if probedURL == "" {
				if *verbose {
					mu.Lock()
					fmt.Printf("Skipping %s: both http:// and https:// failed\n", url)
					mu.Unlock()
				}
				continue // Move to the next URL
			}

			// Update the URL to the probed URL
			url = probedURL

			// Print the successfully probed scheme
			if *verbose {
				mu.Lock()
				fmt.Printf("Probed: %s\n", scheme)
				mu.Unlock()
			}
		}

		sem <- struct{}{} // Acquire a semaphore slot
		urlChan <- url
	}

	// Close the URL channel and wait for all workers to finish
	close(urlChan)
	wg.Wait()

	// Handle scanner errors
	if err := scanner.Err(); err != nil {
		if *verbose {
			mu.Lock()
			fmt.Printf("Error reading from stdin: %v\n", err)
			mu.Unlock()
		}
		os.Exit(1)
	}
}
