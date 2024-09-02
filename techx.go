package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"bytes"
	"path/filepath"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
	"github.com/projectdiscovery/goflags"
)

const version = "v0.0.2"

func printVersion() {
	fmt.Printf("Current techx version %s\n", version)
}

func printBanner() {
	banner := `
 ____  ____  ___  _   _  _  _ 
(_  _)( ___)/ __)( )_( )( \/ )
  )(   )__)( (__  ) _ (  )  ( 
 (__) (____)\___)(_) (_)(_/\_)`
fmt.Printf("%s\n%40s\n\n", banner, "Current techx version "+version)

}

func printFlags() {
	options := ParseOptions()
    fmt.Println("-------------------------------------------")
    fmt.Printf("%-18s: %v\n", ":: Output", options.Output)
    fmt.Printf("%-18s: %v\n", ":: JSONOutput", options.JSONOutput)
    fmt.Printf("%-18s: %v\n", ":: CSVOutput", options.CSVOutput)
    fmt.Printf("%-18s: %v\n", ":: Threads", options.Threads)
    fmt.Printf("%-18s: %v\n", ":: UserAgent", options.UserAgent)
    fmt.Printf("%-18s: %v\n", ":: SendToDiscord", options.SendToDiscord)
    fmt.Printf("%-18s: %v\n", ":: DiscordId", options.DiscordId)
    fmt.Printf("%-18s: %v\n", ":: ProviderConfig", options.ProviderConfig)
    fmt.Printf("%-18s: %v\n", ":: MatchTech", options.MatchTech)
    fmt.Printf("%-18s: %v\n", ":: Verbose", options.Verbose)
    fmt.Printf("%-18s: %v\n", ":: Version", options.Version)
    fmt.Printf("%-18s: %v\n", ":: Silent", options.Silent)
    fmt.Printf("%-18s: %v\n", ":: Delay", options.Delay)
    fmt.Printf("%-18s: %v\n", ":: Retries", options.Retries)
    fmt.Printf("%-18s: %v\n", ":: Timeout", options.Timeout)
    fmt.Printf("%-18s: %v\n", ":: RetriesDelay", options.RetriesDelay)
    fmt.Printf("%-18s: %v\n", ":: Insecure", options.Insecure)
    fmt.Println("-------------------------------------------")
}

// Result structure for JSON output
type Result struct {
	Host  string   `json:"host"`
	Count int      `json:"count"`
	Tech  []string `json:"tech"`
}

// Attempts to probe the domain to determine which protocol (http or https) to use
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

// Checks if a URL is reachable
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
	return resp.StatusCode >= 100 && resp.StatusCode < 599 // Consider status codes 100-599 as reachable
}

type Options struct {
	Output      	string
	JSONOutput      bool
	CSVOutput		bool
	Threads         int
	UserAgent       string
	SendToDiscord   bool
	DiscordId  		string
	ProviderConfig  string
	MatchTech		string
	Verbose         bool
	Version     	bool
	Silent          bool
	Delay           time.Duration
	Retries         int
	Timeout         int
	RetriesDelay    int
	Insecure        bool
}

// Define the flags
func ParseOptions() *Options {
	// Get the user's home directory
    homeDir, err := os.UserHomeDir()
    if err != nil {
        fmt.Printf("Error fetching home directory: %v\n", err)
        os.Exit(1)
    }

	// Define the default config path using the expanded home directory
    defaultConfigPath := filepath.Join(homeDir, ".config", "notify", "provider-config.yaml")

	options := &Options{}
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`techx is a technologies detector tool using the projectdiscovery wappalyzergo library.`)

	createGroup(flagSet, "output", "Output",
		flagSet.StringVarP(&options.Output, "output", "o", "", "File to save output (default is stdout)"),
		flagSet.BoolVar(&options.JSONOutput, "json", false, "Output in JSON format"),
		flagSet.BoolVar(&options.CSVOutput, "csv", false, "Output in CSV format"),
	)

	createGroup(flagSet, "rate-limit", "RATE-LIMIT",
		flagSet.IntVarP(&options.Threads, "threads", "t", 50, "Number of threads to use"),
	)

	createGroup(flagSet, "configurations", "Configurations",
		flagSet.StringVar(&options.UserAgent, "ua", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36", "Custom User-Agent header for HTTP requests"),
		flagSet.BoolVar(&options.SendToDiscord, "discord", false, "Send Matched tech to Discord, Very useful with gungnir because gungnir is gives real-time stdout"),
		flagSet.StringVar(&options.DiscordId, "id", "general", "Discord id to send the notification"),
		flagSet.StringVarP(&options.ProviderConfig, "provider-config", "pc", defaultConfigPath, "provider config path"),
	)

	createGroup(flagSet, "matchers", "Matchers",
		flagSet.StringVarP(&options.MatchTech, "match-tech", "mt", "", "File containing match values (.txt file) or comma-separated list of match values"),
	)

	createGroup(flagSet, "debug", "Debug",
		flagSet.BoolVarP(&options.Verbose, "verbose", "v", false, "Enable verbose output for debugging purposes"),
		flagSet.BoolVarP(&options.Version, "version", "V", false, "Print the version of the tool and exit"),
		flagSet.BoolVarP(&options.Silent, "silent", "sl", false, "silent mode"),
	)

	createGroup(flagSet, "optimizations", "OPTIMIZATIONS",
		flagSet.IntVar(&options.Retries, "retries", 1, "Number of retry attempts for failed HTTP requests"),
		flagSet.IntVar(&options.Timeout, "timeout", 10, "Delay in seconds between retry attempts"),
		flagSet.IntVarP(&options.RetriesDelay, "retriesDelay", "rd", 0, "Delay in seconds between retry attempts"),
		flagSet.BoolVarP(&options.Insecure, "insecure", "i", false, "Disable TLS verification"),
		flagSet.DurationVar(&options.Delay, "delay", -1, "duration between each http request (eg: 200ms, 1s)"),
	)

	_ = flagSet.Parse()

	return options
}

func createGroup(flagSet *goflags.FlagSet, groupName, description string, flags ...*goflags.FlagData) {
	flagSet.SetGroup(groupName, description)
	for _, currentFlag := range flags {
		currentFlag.Group(groupName)
	}
}

// Config structure to hold the YAML data
type Config struct {
	Discord []DiscordConfig `yaml:"discord"`
}

// DiscordConfig holds individual Discord settings
type DiscordConfig struct {
	ID                string `yaml:"id"`
	DiscordChannel    string `yaml:"discord_channel"`
	DiscordUsername   string `yaml:"discord_username"`
	DiscordFormat     string `yaml:"discord_format"`
	DiscordWebhookURL string `yaml:"discord_webhook_url"`
}

// Function to load the configuration from a YAML file
func loadConfig(configFile string) (*Config, error) {
	config := &Config{}

	// Read the YAML file
	file, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, err
	}

	// Unmarshal the YAML data into the Config struct
	err = yaml.Unmarshal(file, config)
	if err != nil {
		return nil, err
	}

	return config, nil
}

// Function to find the Discord configuration by ID
func getDiscordConfigByID(config *Config, id string) *DiscordConfig {
	for _, discordConfig := range config.Discord {
		if discordConfig.ID == id {
			return &discordConfig
		}
	}
	return nil
}

// Function to send a message to Discord
func discord(webhookURL, messageContent string) {
	// Create a map to hold the JSON payload
	payload := map[string]string{
		"content": messageContent,
	}

	// Marshal the payload to JSON
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		fmt.Println("Error marshaling payload:", err)
		return
	}

	// Create a new POST request with the payload
	req, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	// Set the Content-Type header to application/json
	req.Header.Set("Content-Type", "application/json")

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	// Check if the request was successful
	if resp.StatusCode == http.StatusNoContent {
		fmt.Println("Matched tech Message sent to Discord successfully!")
	} else {
		fmt.Printf("Failed to send message. Status code: %d\n", resp.StatusCode)
	}
}

func readMatchesFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var matches []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		match := strings.TrimSpace(scanner.Text())
		if match != "" {
			matches = append(matches, match)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return matches, nil
}

func parseMatches(matchesStr string) []string {
	var matches []string
	for _, match := range strings.Split(matchesStr, ",") {
		trimmed := strings.TrimSpace(match)
		if trimmed != "" {
			matches = append(matches, trimmed)
		}
	}
	return matches
}

func main() {
	options := ParseOptions()

	// Print version and exit if -version flag is provided
	if options.Version {
		printVersion()
		return
	}

	if !options.Silent {
		printBanner()
		printFlags()
	}

	// Check if -discord flag not provided then exit the program
	if (options.SendToDiscord && options.ProviderConfig == "") || (!options.SendToDiscord && options.ProviderConfig != "") {
		fmt.Println("Error: -discord must be provided, it's temporary i will fix soon.")
		os.Exit(1)
	}

	var config *Config
	var err error // Declare err here

	// Only load the configuration if -pc is provided
	if options.SendToDiscord && options.ProviderConfig != "" {
		config, err = loadConfig(options.ProviderConfig)
		if err != nil {
			fmt.Println("Error loading config:", err)
			os.Exit(1)
		}
	}

	// Determine the match criteria
	var matches []string
	if strings.HasSuffix(options.MatchTech, ".txt") {
		// Treat as a file path
		var err error
		matches, err = readMatchesFromFile(options.MatchTech)
		if err != nil {
			fmt.Printf("Error reading match file: %v\n", err)
			return
		} 
	} else {
		// Treat as a comma-separated list or single value
		matches = parseMatches(options.MatchTech)
	}

	// Initialize Wappalyzer client
	wappalyzerClient, err := wappalyzer.New()
	if err != nil {
		if options.Verbose {
			fmt.Printf("Error initializing Wappalyzer client: %v\n", err)
		}
		os.Exit(1)
	}

	// Use a hardcoded ID to find the corresponding webhook URL
	hardcodedID := options.DiscordId // replace with your desired hardcoded ID
	discordConfig := getDiscordConfigByID(config, hardcodedID)
	if discordConfig == nil {
		fmt.Printf("Discord config with ID '%s' not found\n", hardcodedID)
		return
	}

	// Initialize HTTP client with optional TLS verification
	var httpClient *http.Client
	if options.Insecure {
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
	if options.Output != "" {
		file, err := os.Create(options.Output)
		if err != nil {
			if options.Verbose {
				fmt.Printf("Failed to create file %s: %v\n", options.Output, err)
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
	if options.CSVOutput {
		csvWriter = csv.NewWriter(writer)
		// Write CSV headers
		if err := csvWriter.Write([]string{"host", "count", "tech"}); err != nil {
			if options.Verbose {
				fmt.Printf("Error writing header to CSV: %v\n", err)
			}
			os.Exit(1)
		}
	}

	// Create a channel for URLs and a wait group
	urlChan := make(chan string)
	var wg sync.WaitGroup
	sem := make(chan struct{}, options.Threads) // Semaphore to limit the number of concurrent threads
	var mu sync.Mutex // Mutex for synchronized output

	// Worker function to process URLs
	worker := func() {
		for url := range urlChan {
			if options.Verbose {
				mu.Lock()
				fmt.Printf("Processing URL: %s\n", url)
				mu.Unlock()
			}

			var resp *http.Response
			var fetchErr error

			// Retry logic
			for i := 0; i < options.Retries; i++ {
				// Set up HTTP request with timeout
				ctx, cancel := context.WithTimeout(context.Background(), time.Duration(options.Timeout)*time.Second)
				defer cancel()

				req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
				if err != nil {
					if options.Verbose {
						mu.Lock()
						fmt.Printf("Failed to create request for %s: %v\n", url, err)
						mu.Unlock()
					}
					continue
				}

				// Set the custom User-Agent header
				req.Header.Set("User-Agent", options.UserAgent)

				resp, fetchErr = httpClient.Do(req)
				if fetchErr == nil {
					break // Exit retry loop if request is successful
				}

				if options.Verbose {
					mu.Lock()
					fmt.Printf("Retrying %s (%d/%d): %v\n", url, i+1, options.Retries, fetchErr)
					mu.Unlock()
				}

				if options.RetriesDelay > 0 {
					time.Sleep(time.Duration(options.RetriesDelay) * time.Second) // Delay before retry
				}
			}

			if fetchErr != nil {
				if options.Verbose {
					mu.Lock()
					fmt.Printf("Failed to fetch %s after %d retries: %v\n", url, options.Retries, fetchErr)
					mu.Unlock()
				}
				continue
			}
			data, _ := io.ReadAll(resp.Body)
			resp.Body.Close() // Close the body after reading

			// Fingerprint the URL
			fingerprints := wappalyzerClient.Fingerprint(resp.Header, data)

			// Hardcoded matches
			// matches := []string{"IIS", "Jenkins", "JAVA"}
			var matched []string


			// Convert fingerprints to a slice of strings and sort
			var tech []string
			for name := range fingerprints {
				tech = append(tech, name)

				// match tech with case-sensitive
				lowerName := strings.ToLower(name)
				for _, match := range matches {
					if strings.Contains(lowerName, strings.ToLower(match)) {
						matched = append(matched, name)
					}
				}

			}
			sort.Strings(tech) // Sort the technologies alphabetically
			count := len(tech)  // Count the number of detected technologies

			if options.Verbose {
				mu.Lock()
				fmt.Printf("Detected technologies for %s: [%s]\n", url, strings.Join(tech, ", "))
				mu.Unlock()
			}

			// Output the result based on the flags
			if options.JSONOutput {
				result := Result{
					Host:  url,
					Count: count,
					Tech:  tech,
				}
				jsonData, _ := json.MarshalIndent(result, "", "  ")
				mu.Lock()
				fmt.Fprintln(writer, string(jsonData))
				mu.Unlock()
			} else if options.CSVOutput {
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

			// Consolidate matched technologies into a single message
			if len(matched) > 0 {
			    // Create a single message with all matched technologies
			    matchedTechs := strings.Join(matched, ", ")
			    messageContent := fmt.Sprintf("```URL: %s\nMatched Tech: %v```\n", url, matchedTechs)

			    // Send consolidated message to Discord
			    if options.SendToDiscord && config != nil {
			        discord(discordConfig.DiscordWebhookURL, messageContent)
			    }
			}

			// Delay between requests if delay is set
	        if options.Delay > 0 {
	            time.Sleep(options.Delay)
	        }

			// Release the semaphore
			<-sem
		}
	}

	// Start worker goroutines
	for i := 0; i < options.Threads; i++ {
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
			probedURL, scheme := probeDomain(url, options.Timeout, options.UserAgent, httpClient)
			
			// If probing fails (i.e., both https:// and http:// fail), skip this URL
			if probedURL == "" {
				if options.Verbose {
					mu.Lock()
					fmt.Printf("Skipping %s: both http:// and https:// failed\n", url)
					mu.Unlock()
				}
				continue // Move to the next URL
			}

			// Update the URL to the probed URL
			url = probedURL

			// Print the successfully probed scheme
			if options.Verbose {
				mu.Lock()
				fmt.Printf("Probed Scheme: %s\n", scheme)
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
		if options.Verbose {
			mu.Lock()
			fmt.Printf("Error reading from stdin: %v\n", err)
			mu.Unlock()
		}
		os.Exit(1)
	}
}
