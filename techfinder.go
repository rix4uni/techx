package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/projectdiscovery/goflags"
	"github.com/rix4uni/techfinder/banner"
	"golang.org/x/net/html"
	"gopkg.in/yaml.v2"
)

// ==================== WAPPALYZERGO INTEGRATION ====================

// Fingerprints contains a map of fingerprints for tech detection
type Fingerprints struct {
	Apps map[string]*Fingerprint `json:"apps"`
}

// Fingerprint is a single piece of information about a tech validated and normalized
type Fingerprint struct {
	Cats        []int                             `json:"cats"`
	CSS         []string                          `json:"css"`
	Cookies     map[string]string                 `json:"cookies"`
	Dom         map[string]map[string]interface{} `json:"dom"`
	JS          map[string]string                 `json:"js"`
	Headers     map[string]string                 `json:"headers"`
	HTML        []string                          `json:"html"`
	Script      []string                          `json:"scripts"`
	ScriptSrc   []string                          `json:"scriptSrc"`
	Meta        map[string][]string               `json:"meta"`
	Implies     []string                          `json:"implies"`
	Description string                            `json:"description"`
	Website     string                            `json:"website"`
	CPE         string                            `json:"cpe"`
	Icon        string                            `json:"icon"`
}

// CompiledFingerprints contains a map of fingerprints for tech detection
type CompiledFingerprints struct {
	Apps map[string]*CompiledFingerprint
}

// CompiledFingerprint contains the compiled fingerprints from the tech json
type CompiledFingerprint struct {
	cats        []int
	implies     []string
	description string
	website     string
	icon        string
	cookies     map[string]*ParsedPattern
	js          map[string]*ParsedPattern
	dom         map[string]map[string]*ParsedPattern
	headers     map[string]*ParsedPattern
	html        []*ParsedPattern
	script      []*ParsedPattern
	scriptSrc   []*ParsedPattern
	meta        map[string][]*ParsedPattern
	cpe         string
}

func (f *CompiledFingerprint) GetJSRules() map[string]*ParsedPattern {
	return f.js
}

func (f *CompiledFingerprint) GetDOMRules() map[string]map[string]*ParsedPattern {
	return f.dom
}

// AppInfo contains basic information about an App.
type AppInfo struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Description string   `json:"description"`
	Website     string   `json:"website"`
	CPE         string   `json:"cpe"`
	Icon        string   `json:"icon"`
	Categories  []string `json:"categories"`
}

// CatsInfo contains basic information about an App.
type CatsInfo struct {
	Cats []int `json:"cats"`
}

// ParsedPattern encapsulates a regular expression with additional metadata
type ParsedPattern struct {
	regex      *regexp.Regexp
	Confidence int
	Version    string
	SkipRegex  bool
}

// Wappalyze is a client for working with tech detection
type Wappalyze struct {
	original     *Fingerprints
	fingerprints *CompiledFingerprints
}

// UniqueFingerprints deduplication helper
type UniqueFingerprints struct {
	values map[string]uniqueFingerprintMetadata
}

type uniqueFingerprintMetadata struct {
	confidence int
	version    string
}

type matchPartResult struct {
	application string
	confidence  int
	version     string
}

type categoryItem struct {
	Name     string `json:"name"`
	Priority int    `json:"priority"`
}

// Global categories mapping loaded at runtime
var categoriesMapping = make(map[int]categoryItem)

// loadCategories loads the categories data from JSON file
func loadCategories() error {
	var data []byte
	var err error

	// Search paths: current dir, then $HOME/.config/techfinder/
	paths := []string{
		"categories_data.json",
	}

	homeDir, _ := os.UserHomeDir()
	if homeDir != "" {
		paths = append(paths, filepath.Join(homeDir, ".config", "techfinder", "categories_data.json"))
	}

	for _, path := range paths {
		data, err = os.ReadFile(path)
		if err == nil {
			break
		}
	}

	if data == nil {
		// Categories are optional, just return without error
		return nil
	}

	var categoriesMap map[string]categoryItem
	err = json.Unmarshal(data, &categoriesMap)
	if err != nil {
		return err
	}

	// Convert string keys to int
	for k, v := range categoriesMap {
		if id, err := strconv.Atoi(k); err == nil {
			categoriesMapping[id] = v
		}
	}
	return nil
}

// BrowserPool manages a pool of reusable browser instances
type BrowserPool struct {
	allocators []context.Context
	size       int
	mu         sync.Mutex
	cancelFuncs []context.CancelFunc
	sem         chan struct{} // semaphore to bound concurrent headless requests
}

// NewBrowserPool creates a new browser pool with the specified size
func NewBrowserPool(size int) *BrowserPool {
	return &BrowserPool{
		allocators:  make([]context.Context, 0, size),
		size:        size,
		cancelFuncs: make([]context.CancelFunc, 0, size),
		sem:         make(chan struct{}, size),
	}
}

// Initialize creates the browser instances in the pool
func (p *BrowserPool) Initialize() error {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("disable-web-security", true),
		chromedp.Flag("disable-features", "VizDisplayCompositor"),
	)

	for i := 0; i < p.size; i++ {
		allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
		p.allocators = append(p.allocators, allocCtx)
		p.cancelFuncs = append(p.cancelFuncs, cancel)
		p.sem <- struct{}{} // pre-fill semaphore slots
	}
	return nil
}

// Acquire acquires a semaphore slot and returns an allocator context from the pool (round-robin)
func (p *BrowserPool) Acquire() context.Context {
	<-p.sem // block until a slot is free
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.allocators) == 0 {
		return nil
	}
	// Simple round-robin
	ctx := p.allocators[0]
	p.allocators = append(p.allocators[1:], ctx)
	return ctx
}

// Release returns a semaphore slot back to the pool after headless work is done
func (p *BrowserPool) Release() {
	p.sem <- struct{}{}
}

// Close shuts down all browser instances in the pool
func (p *BrowserPool) Close() {
	for _, cancel := range p.cancelFuncs {
		cancel()
	}
	p.allocators = nil
	p.cancelFuncs = nil
}

// part is the part of the fingerprint to match
type part int

const (
	cookiesPart part = iota + 1
	jsPart
	headersPart
	htmlPart
	scriptPart
	metaPart
)

const versionSeparator = ":"
const keyValuePairLength = 2

// Pattern parsing constants
const (
	verCap1        = `(\d+(?:\.\d+)+)`
	verCap1Fill    = "__verCap1__"
	verCap1Limited = `(\d{1,20}(?:\.\d{1,20}){1,20})`
	verCap2        = `((?:\d+\.)+\d+)`
	verCap2Fill    = "__verCap2__"
	verCap2Limited = `((?:\d{1,20}\.){1,20}\d{1,20})`
)

// ==================== VERSION FUNCTIONS ====================

func isMoreSpecific(a, b string) bool {
	aParts := splitParts(a)
	bParts := splitParts(b)
	if len(aParts) != len(bParts) {
		return len(aParts) > len(bParts)
	}
	return versionLess(b, a)
}

func versionLess(a, b string) bool {
	aParts := splitParts(a)
	bParts := splitParts(b)
	maxLen := len(aParts)
	if len(bParts) > maxLen {
		maxLen = len(bParts)
	}
	for i := 0; i < maxLen; i++ {
		ai := 0
		bi := 0
		if i < len(aParts) {
			ai = aParts[i]
		}
		if i < len(bParts) {
			bi = bParts[i]
		}
		if ai < bi {
			return true
		}
		if ai > bi {
			return false
		}
	}
	return false
}

func splitParts(v string) []int {
	fields := strings.FieldsFunc(v, func(r rune) bool {
		return r == '.'
	})
	parts := make([]int, len(fields))
	for i, f := range fields {
		if n, err := strconv.Atoi(f); err == nil {
			parts[i] = n
		}
	}
	return parts
}

// ==================== PATTERN FUNCTIONS ====================

func ParsePattern(pattern string) (*ParsedPattern, error) {
	parts := strings.Split(pattern, "\\;")
	p := &ParsedPattern{Confidence: 100}

	if parts[0] == "" {
		p.SkipRegex = true
	}
	for i, part := range parts {
		if i == 0 {
			if p.SkipRegex {
				continue
			}
			regexPattern := part

			regexPattern = strings.ReplaceAll(regexPattern, verCap1, verCap1Fill)
			regexPattern = strings.ReplaceAll(regexPattern, verCap2, verCap2Fill)
			regexPattern = strings.ReplaceAll(regexPattern, "\\+", "__escapedPlus__")
			regexPattern = strings.ReplaceAll(regexPattern, "+", "{1,250}")
			regexPattern = strings.ReplaceAll(regexPattern, "*", "{0,250}")
			regexPattern = strings.ReplaceAll(regexPattern, "__escapedPlus__", "\\+")
			regexPattern = strings.ReplaceAll(regexPattern, verCap1Fill, verCap1Limited)
			regexPattern = strings.ReplaceAll(regexPattern, verCap2Fill, verCap2Limited)

			var err error
			p.regex, err = regexp.Compile("(?i)" + regexPattern)
			if err != nil {
				return nil, err
			}
		} else {
			keyValue := strings.SplitN(part, ":", 2)
			if len(keyValue) < 2 {
				continue
			}
			switch keyValue[0] {
			case "confidence":
				conf, err := strconv.Atoi(keyValue[1])
				if err != nil {
					p.Confidence = 100
				} else {
					p.Confidence = conf
				}
			case "version":
				p.Version = keyValue[1]
			}
		}
	}
	return p, nil
}

func (p *ParsedPattern) Evaluate(target string) (bool, string) {
	if p.SkipRegex {
		return true, ""
	}
	if p.regex == nil {
		return false, ""
	}
	submatches := p.regex.FindStringSubmatch(target)
	if len(submatches) == 0 {
		return false, ""
	}
	extractedVersion, _ := p.extractVersion(submatches)
	return true, extractedVersion
}

func (p *ParsedPattern) extractVersion(submatches []string) (string, error) {
	if len(submatches) == 0 {
		return "", nil
	}
	result := p.Version
	for i, match := range submatches[1:] {
		placeholder := fmt.Sprintf("\\%d", i+1)
		result = strings.ReplaceAll(result, placeholder, match)
	}
	result, err := evaluateVersionExpression(result, submatches[1:])
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(result), nil
}

func evaluateVersionExpression(expression string, submatches []string) (string, error) {
	if strings.Contains(expression, "?") {
		parts := strings.Split(expression, "?")
		if len(parts) != 2 {
			return "", fmt.Errorf("invalid ternary expression: %s", expression)
		}
		trueFalseParts := strings.Split(parts[1], ":")
		if len(trueFalseParts) != 2 {
			return "", fmt.Errorf("invalid true/false parts in ternary expression: %s", expression)
		}
		if trueFalseParts[0] != "" {
			if len(submatches) == 0 {
				return trueFalseParts[1], nil
			}
			return trueFalseParts[0], nil
		}
		if trueFalseParts[1] == "" {
			if len(submatches) == 0 {
				return "", nil
			}
			return trueFalseParts[0], nil
		}
		return trueFalseParts[1], nil
	}
	return expression, nil
}

// ==================== FINGERPRINT COMPILATION ====================

func compileFingerprint(fingerprint *Fingerprint) *CompiledFingerprint {
	compiled := &CompiledFingerprint{
		cats:        fingerprint.Cats,
		implies:     fingerprint.Implies,
		description: fingerprint.Description,
		website:     fingerprint.Website,
		icon:        fingerprint.Icon,
		dom:         make(map[string]map[string]*ParsedPattern),
		cookies:     make(map[string]*ParsedPattern),
		js:          make(map[string]*ParsedPattern),
		headers:     make(map[string]*ParsedPattern),
		html:        make([]*ParsedPattern, 0, len(fingerprint.HTML)),
		script:      make([]*ParsedPattern, 0, len(fingerprint.Script)),
		scriptSrc:   make([]*ParsedPattern, 0, len(fingerprint.ScriptSrc)),
		meta:        make(map[string][]*ParsedPattern),
		cpe:         fingerprint.CPE,
	}

	for dom, patterns := range fingerprint.Dom {
		compiled.dom[dom] = make(map[string]*ParsedPattern)
		for attr, value := range patterns {
			switch attr {
			case "exists", "text":
				pattern, err := ParsePattern(value.(string))
				if err != nil {
					continue
				}
				compiled.dom[dom]["main"] = pattern
			case "attributes":
				attrMap, ok := value.(map[string]interface{})
				if !ok {
					continue
				}
				compiled.dom[dom] = make(map[string]*ParsedPattern)
				for attrName, val := range attrMap {
					pattern, err := ParsePattern(val.(string))
					if err != nil {
						continue
					}
					compiled.dom[dom][attrName] = pattern
				}
			}
		}
	}

	for header, pattern := range fingerprint.Cookies {
		fp, err := ParsePattern(pattern)
		if err != nil {
			continue
		}
		compiled.cookies[header] = fp
	}

	for k, pattern := range fingerprint.JS {
		fp, err := ParsePattern(pattern)
		if err != nil {
			continue
		}
		compiled.js[k] = fp
	}

	for header, pattern := range fingerprint.Headers {
		fp, err := ParsePattern(pattern)
		if err != nil {
			continue
		}
		compiled.headers[header] = fp
	}

	for _, pattern := range fingerprint.HTML {
		fp, err := ParsePattern(pattern)
		if err != nil {
			continue
		}
		compiled.html = append(compiled.html, fp)
	}

	for _, pattern := range fingerprint.Script {
		fp, err := ParsePattern(pattern)
		if err != nil {
			continue
		}
		compiled.script = append(compiled.script, fp)
	}

	for _, pattern := range fingerprint.ScriptSrc {
		fp, err := ParsePattern(pattern)
		if err != nil {
			continue
		}
		compiled.scriptSrc = append(compiled.scriptSrc, fp)
	}

	for meta, patterns := range fingerprint.Meta {
		var compiledList []*ParsedPattern
		for _, pattern := range patterns {
			fp, err := ParsePattern(pattern)
			if err != nil {
				continue
			}
			compiledList = append(compiledList, fp)
		}
		compiled.meta[meta] = compiledList
	}
	return compiled
}

// ==================== COMPILED FINGERPRINTS MATCHING ====================

func (f *CompiledFingerprints) matchString(data string, part part) []matchPartResult {
	var matched bool
	var technologies []matchPartResult

	for app, fingerprint := range f.Apps {
		var version string
		var confidence int

		switch part {
		case jsPart:
			for _, pattern := range fingerprint.js {
				if valid, versionString := pattern.Evaluate(data); valid {
					matched = true
					if pattern.Confidence > confidence {
						confidence = pattern.Confidence
					}
					if versionString != "" && (version == "" || isMoreSpecific(versionString, version)) {
						version = versionString
					}
				}
			}
		case scriptPart:
			for _, pattern := range fingerprint.scriptSrc {
				if valid, versionString := pattern.Evaluate(data); valid {
					matched = true
					if pattern.Confidence > confidence {
						confidence = pattern.Confidence
					}
					if versionString != "" && (version == "" || isMoreSpecific(versionString, version)) {
						version = versionString
					}
				}
			}
		case htmlPart:
			for _, pattern := range fingerprint.html {
				if valid, versionString := pattern.Evaluate(data); valid {
					matched = true
					if pattern.Confidence > confidence {
						confidence = pattern.Confidence
					}
					if versionString != "" && (version == "" || isMoreSpecific(versionString, version)) {
						version = versionString
					}
				}
			}
		}

		if !matched {
			continue
		}

		technologies = append(technologies, matchPartResult{
			application: app,
			version:     version,
			confidence:  confidence,
		})
		if len(fingerprint.implies) > 0 {
			for _, implies := range fingerprint.implies {
				technologies = append(technologies, matchPartResult{
					application: implies,
					confidence:  confidence,
				})
			}
		}
		matched = false
	}
	return technologies
}

func (f *CompiledFingerprints) matchKeyValueString(key, value string, part part) []matchPartResult {
	var matched bool
	var technologies []matchPartResult

	for app, fingerprint := range f.Apps {
		var version string
		var confidence int

		switch part {
		case cookiesPart:
			for data, pattern := range fingerprint.cookies {
				if data != key {
					continue
				}
				if valid, versionString := pattern.Evaluate(value); valid {
					matched = true
					if pattern.Confidence > confidence {
						confidence = pattern.Confidence
					}
					if versionString != "" && (version == "" || isMoreSpecific(versionString, version)) {
						version = versionString
					}
				}
			}
		case headersPart:
			for data, pattern := range fingerprint.headers {
				if data != key {
					continue
				}
				if valid, versionString := pattern.Evaluate(value); valid {
					matched = true
					if pattern.Confidence > confidence {
						confidence = pattern.Confidence
					}
					if versionString != "" && (version == "" || isMoreSpecific(versionString, version)) {
						version = versionString
					}
				}
			}
		case metaPart:
			for data, patterns := range fingerprint.meta {
				if data != key {
					continue
				}
				for _, pattern := range patterns {
					if valid, versionString := pattern.Evaluate(value); valid {
						matched = true
						if pattern.Confidence > confidence {
							confidence = pattern.Confidence
						}
						if versionString != "" && (version == "" || isMoreSpecific(versionString, version)) {
							version = versionString
						}
					}
				}
			}
		}

		if !matched {
			continue
		}

		technologies = append(technologies, matchPartResult{
			application: app,
			version:     version,
			confidence:  confidence,
		})
		if len(fingerprint.implies) > 0 {
			for _, implies := range fingerprint.implies {
				technologies = append(technologies, matchPartResult{
					application: implies,
					confidence:  confidence,
				})
			}
		}
		matched = false
	}
	return technologies
}

func (f *CompiledFingerprints) matchMapString(keyValue map[string]string, part part) []matchPartResult {
	var matched bool
	var technologies []matchPartResult

	for app, fingerprint := range f.Apps {
		var version string
		var confidence int

		switch part {
		case cookiesPart:
			for data, pattern := range fingerprint.cookies {
				value, ok := keyValue[data]
				if !ok {
					continue
				}
				if pattern == nil {
					matched = true
					continue
				}
				if valid, versionString := pattern.Evaluate(value); valid {
					matched = true
					if pattern.Confidence > confidence {
						confidence = pattern.Confidence
					}
					if versionString != "" && (version == "" || isMoreSpecific(versionString, version)) {
						version = versionString
					}
				}
			}
		case headersPart:
			for data, pattern := range fingerprint.headers {
				value, ok := keyValue[data]
				if !ok {
					continue
				}
				if valid, versionString := pattern.Evaluate(value); valid {
					matched = true
					if pattern.Confidence > confidence {
						confidence = pattern.Confidence
					}
					if versionString != "" && (version == "" || isMoreSpecific(versionString, version)) {
						version = versionString
					}
				}
			}
		case metaPart:
			for data, patterns := range fingerprint.meta {
				value, ok := keyValue[data]
				if !ok {
					continue
				}
				for _, pattern := range patterns {
					if valid, versionString := pattern.Evaluate(value); valid {
						matched = true
						if pattern.Confidence > confidence {
							confidence = pattern.Confidence
						}
						if versionString != "" && (version == "" || isMoreSpecific(versionString, version)) {
							version = versionString
						}
					}
				}
			}
		}

		if !matched {
			continue
		}

		technologies = append(technologies, matchPartResult{
			application: app,
			version:     version,
			confidence:  confidence,
		})
		if len(fingerprint.implies) > 0 {
			for _, implies := range fingerprint.implies {
				technologies = append(technologies, matchPartResult{
					application: implies,
					confidence:  confidence,
				})
			}
		}
		matched = false
	}
	return technologies
}

func (f *CompiledFingerprints) matchJSGlobals(globals map[string]string) []matchPartResult {
	var matched bool
	var technologies []matchPartResult

	for app, fingerprint := range f.Apps {
		var version string
		var confidence int

		for data, pattern := range fingerprint.js {
			value, ok := globals[data]
			if !ok {
				continue
			}
			if valid, versionString := pattern.Evaluate(value); valid {
				matched = true
				if pattern.Confidence > confidence {
					confidence = pattern.Confidence
				}
				if versionString != "" && (version == "" || isMoreSpecific(versionString, version)) {
					version = versionString
				}
			}
		}

		if !matched {
			continue
		}

		technologies = append(technologies, matchPartResult{
			application: app,
			version:     version,
			confidence:  confidence,
		})
		if len(fingerprint.implies) > 0 {
			for _, implies := range fingerprint.implies {
				technologies = append(technologies, matchPartResult{
					application: implies,
					confidence:  confidence,
				})
			}
		}
		matched = false
	}
	return technologies
}

func (f *CompiledFingerprints) matchDOMSelectors(domAttributes map[string]map[string]string) []matchPartResult {
	var matched bool
	var technologies []matchPartResult

	for app, fingerprint := range f.Apps {
		var version string
		var confidence int

		for selector, attrPatterns := range fingerprint.dom {
			extractedAttributes, ok := domAttributes[selector]
			if !ok || extractedAttributes == nil {
				continue
			}

			var domMatched bool
			for attr, pattern := range attrPatterns {
				var attrValue string
				if attr == "main" {
					if val, textOk := extractedAttributes["text"]; textOk {
						attrValue = val
					} else if val, existsOk := extractedAttributes["exists"]; existsOk {
						attrValue = val
					} else {
						attrValue = ""
					}
				} else {
					attrValue = extractedAttributes[attr]
				}

				if valid, versionString := pattern.Evaluate(attrValue); valid {
					domMatched = true
					if pattern.Confidence > confidence {
						confidence = pattern.Confidence
					}
					if versionString != "" && (version == "" || isMoreSpecific(versionString, version)) {
						version = versionString
					}
				}
			}

			if domMatched {
				matched = true
			}
		}

		if !matched {
			continue
		}

		technologies = append(technologies, matchPartResult{
			application: app,
			version:     version,
			confidence:  confidence,
		})
		if len(fingerprint.implies) > 0 {
			for _, implies := range fingerprint.implies {
				technologies = append(technologies, matchPartResult{
					application: implies,
					confidence:  confidence,
				})
			}
		}
		matched = false
	}
	return technologies
}

func FormatAppVersion(app, version string) string {
	if version == "" {
		return app
	}
	return fmt.Sprintf("%s:%s", app, version)
}

// ParseAppVersion parses an app string that may contain version info
func ParseAppVersion(app string) (string, string) {
	parts := strings.SplitN(app, versionSeparator, 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return app, ""
}

// Result structure for JSON output
type Result struct {
	Host  string   `json:"host"`
	Count int      `json:"count"`
	Tech  []string `json:"tech"`
}

// ==================== WAPPALYZE METHODS ====================

// New creates a new tech detection instance
func NewWappalyzer() (*Wappalyze, error) {
	wappalyze := &Wappalyze{
		fingerprints: &CompiledFingerprints{
			Apps: make(map[string]*CompiledFingerprint),
		},
	}

	err := wappalyze.loadFingerprints()
	if err != nil {
		return nil, err
	}

	// Load categories (optional, for enrichment)
	_ = loadCategories()

	return wappalyze, nil
}

// loadFingerprints loads the fingerprints and compiles them
func (s *Wappalyze) loadFingerprints() error {
	// Try to load from multiple locations
	var data []byte
	var err error

	// Search paths: current dir, then $HOME/.config/techfinder/
	paths := []string{
		"fingerprints_data.json",
	}

	homeDir, _ := os.UserHomeDir()
	if homeDir != "" {
		paths = append(paths, filepath.Join(homeDir, ".config", "techfinder", "fingerprints_data.json"))
	}

	for _, path := range paths {
		data, err = os.ReadFile(path)
		if err == nil {
			break
		}
	}

	if data == nil {
		return fmt.Errorf("could not find fingerprints_data.json in any search path")
	}

	var fingerprintsStruct Fingerprints
	err = json.Unmarshal(data, &fingerprintsStruct)
	if err != nil {
		return err
	}

	s.original = &fingerprintsStruct
	for i, fingerprint := range fingerprintsStruct.Apps {
		s.fingerprints.Apps[i] = compileFingerprint(fingerprint)
	}
	return nil
}

// Fingerprint identifies technologies on a target based on headers and body
func (s *Wappalyze) Fingerprint(headers map[string][]string, body []byte) map[string]struct{} {
	uniqueFingerprints := NewUniqueFingerprints()

	normalizedBody := bytes.ToLower(body)
	normalizedHeaders := s.normalizeHeaders(headers)

	for _, app := range s.checkHeaders(normalizedHeaders) {
		uniqueFingerprints.SetIfNotExists(app.application, app.version, app.confidence)
	}

	cookies := s.findSetCookie(normalizedHeaders)
	if len(cookies) > 0 {
		for _, app := range s.checkCookies(cookies) {
			uniqueFingerprints.SetIfNotExists(app.application, app.version, app.confidence)
		}
	}

	bodyTech := s.checkBody(normalizedBody)
	for _, app := range bodyTech {
		uniqueFingerprints.SetIfNotExists(app.application, app.version, app.confidence)
	}
	return uniqueFingerprints.GetValues()
}

// FingerprintWithTitle identifies technologies and returns the title
func (s *Wappalyze) FingerprintWithTitle(headers map[string][]string, body []byte) (map[string]struct{}, string) {
	uniqueFingerprints := NewUniqueFingerprints()

	normalizedBody := bytes.ToLower(body)
	normalizedHeaders := s.normalizeHeaders(headers)

	for _, app := range s.checkHeaders(normalizedHeaders) {
		uniqueFingerprints.SetIfNotExists(app.application, app.version, app.confidence)
	}

	cookies := s.findSetCookie(normalizedHeaders)
	if len(cookies) > 0 {
		for _, app := range s.checkCookies(cookies) {
			uniqueFingerprints.SetIfNotExists(app.application, app.version, app.confidence)
		}
	}

	if strings.Contains(normalizedHeaders["content-type"], "text/html") {
		bodyTech := s.checkBody(normalizedBody)
		for _, app := range bodyTech {
			uniqueFingerprints.SetIfNotExists(app.application, app.version, app.confidence)
		}
		title := s.getTitle(body)
		return uniqueFingerprints.GetValues(), title
	}
	return uniqueFingerprints.GetValues(), ""
}

// FingerprintWithInfo identifies technologies and returns AppInfo with metadata
func (s *Wappalyze) FingerprintWithInfo(headers map[string][]string, body []byte) map[string]AppInfo {
	apps := s.Fingerprint(headers, body)
	return s.EnrichWithInfo(apps)
}

// FingerprintWithCats identifies technologies and returns category information
func (s *Wappalyze) FingerprintWithCats(headers map[string][]string, body []byte) map[string]CatsInfo {
	apps := s.Fingerprint(headers, body)
	return s.EnrichWithCats(apps)
}

// EnrichWithInfo adds metadata (categories, CPE) to fingerprint results
func (s *Wappalyze) EnrichWithInfo(apps map[string]struct{}) map[string]AppInfo {
	results := make(map[string]AppInfo, len(apps))
	for app := range apps {
		appName, version := ParseAppVersion(app)
		if compiled, ok := s.fingerprints.Apps[appName]; ok {
			categories := make([]string, 0, len(compiled.cats))
			for _, catID := range compiled.cats {
				if cat, ok := categoriesMapping[catID]; ok {
					categories = append(categories, cat.Name)
				}
			}
			results[app] = AppInfo{
				Name:       appName,
				Version:    version,
				CPE:        compiled.cpe,
				Categories: categories,
			}
		} else {
			results[app] = AppInfo{Name: appName, Version: version}
		}
	}
	return results
}

// EnrichWithCats adds category IDs to fingerprint results
func (s *Wappalyze) EnrichWithCats(apps map[string]struct{}) map[string]CatsInfo {
	results := make(map[string]CatsInfo, len(apps))
	for app := range apps {
		appName, _ := ParseAppVersion(app)
		if compiled, ok := s.fingerprints.Apps[appName]; ok {
			results[app] = CatsInfo{Cats: compiled.cats}
		} else {
			results[app] = CatsInfo{}
		}
	}
	return results
}

// GetFingerprints returns the original fingerprints
func (s *Wappalyze) GetFingerprints() *Fingerprints {
	return s.original
}

// GetCompiledFingerprints returns the compiled fingerprints
func (s *Wappalyze) GetCompiledFingerprints() *CompiledFingerprints {
	return s.fingerprints
}

// FingerprintURL checks the URL using headless browser for deep JS & DOM fingerprinting
func (s *Wappalyze) FingerprintURL(ctx context.Context, url string) (map[string]struct{}, error) {
	headers, body, jsGlobals, domMatches, err := s.headlessFetch(ctx, url)
	if err != nil {
		return nil, err
	}

	uniqueFingerprints := NewUniqueFingerprints()

	normalizedHeaders := s.normalizeHeaders(headers)
	for _, app := range s.checkHeaders(normalizedHeaders) {
		uniqueFingerprints.SetIfNotExists(app.application, app.version, app.confidence)
	}

	cookies := s.findSetCookie(normalizedHeaders)
	if len(cookies) > 0 {
		for _, app := range s.checkCookies(cookies) {
			uniqueFingerprints.SetIfNotExists(app.application, app.version, app.confidence)
		}
	}

	normalizedBody := []byte(strings.ToLower(body))
	for _, app := range s.checkBody(normalizedBody) {
		uniqueFingerprints.SetIfNotExists(app.application, app.version, app.confidence)
	}

	for _, app := range s.fingerprints.matchJSGlobals(jsGlobals) {
		uniqueFingerprints.SetIfNotExists(app.application, app.version, app.confidence)
	}

	for _, app := range s.fingerprints.matchDOMSelectors(domMatches) {
		uniqueFingerprints.SetIfNotExists(app.application, app.version, app.confidence)
	}

	return uniqueFingerprints.GetValues(), nil
}

// FingerprintURLWithPool checks the URL using a browser from the pool
func (s *Wappalyze) FingerprintURLWithPool(pool *BrowserPool, url string, timeout time.Duration) (map[string]struct{}, error) {
	allocCtx := pool.Acquire() // blocks until a browser slot is free
	if allocCtx == nil {
		return nil, fmt.Errorf("browser pool not initialized")
	}
	defer pool.Release() // always release the slot when done

	// Create a per-URL timeout context derived from the allocCtx so that a
	// timed-out or cancelled tab context does NOT poison the pool allocator.
	// We wrap allocCtx with a timeout but each call gets its own independent
	// child context via chromedp.NewContext inside headlessFetch.
	ctx, cancel := context.WithTimeout(allocCtx, timeout)
	defer cancel()

	return s.FingerprintURL(ctx, url)
}

// headlessFetch connects to a browser and extracts data
func (s *Wappalyze) headlessFetch(ctx context.Context, url string) (
	headers map[string][]string,
	body string,
	jsGlobals map[string]string,
	domMatches map[string]map[string]string,
	err error,
) {
	headers = make(map[string][]string)
	jsGlobals = make(map[string]string)
	domMatches = make(map[string]map[string]string)

	c, cancel := chromedp.NewContext(ctx)
	defer cancel()

	chromedp.ListenTarget(c, func(ev interface{}) {
		if ev, ok := ev.(*network.EventResponseReceived); ok {
			if ev.Type == network.ResourceTypeDocument || ev.Response.URL == url {
				for k, v := range ev.Response.Headers {
					if val, ok := v.(string); ok {
						headers[k] = []string{val}
					}
				}
			}
		}
	})

	var jsToEvaluate []string
	for _, fingerprint := range s.fingerprints.Apps {
		for jsProp := range fingerprint.js {
			jsToEvaluate = append(jsToEvaluate, jsProp)
		}
	}

	jsPayload := `(() => {
		const result = {};
		const extract = (path) => {
			try {
				let obj = window;
				for (let part of path.split('.')) {
					if (!obj || typeof obj !== 'object') return undefined;
					obj = obj[part];
				}
				if (typeof obj === 'string' || typeof obj === 'number' || typeof obj === 'boolean') {
					return String(obj);
				}
				return typeof obj !== 'undefined' ? "true" : undefined;
			} catch (e) {
				return undefined;
			}
		};
		const props = ` + toJSON(jsToEvaluate) + `;
		for (let prop of props) {
			let val = extract(prop);
			if (val !== undefined) result[prop] = val;
		}
		return JSON.stringify(result);
	})()`

	type domPayloadItem struct {
		Selector   string   `json:"s"`
		Attributes []string `json:"a"`
	}

	var domToEvaluate []domPayloadItem
	for _, fingerprint := range s.fingerprints.Apps {
		for selector, attrMap := range fingerprint.dom {
			item := domPayloadItem{Selector: selector, Attributes: []string{}}
			for attr := range attrMap {
				item.Attributes = append(item.Attributes, attr)
			}
			domToEvaluate = append(domToEvaluate, item)
		}
	}

	domPayload := `(() => {
		const result = {};
		const rules = ` + toJSON(domToEvaluate) + `;
		for (let rule of rules) {
			try {
				const els = document.querySelectorAll(rule.s);
				if (els.length === 0) continue;
				result[rule.s] = {};
				const el = els[0];
				for (let attr of rule.a) {
					if (attr === "text") {
						result[rule.s]["text"] = el.textContent || "";
					} else if (attr === "exists" || attr === "main") {
						result[rule.s]["exists"] = "true";
					} else {
						if (el.hasAttribute(attr)) {
							result[rule.s][attr] = el.getAttribute(attr) || "";
						}
					}
				}
			} catch (e) {}
		}
		return JSON.stringify(result);
	})()`

	var globalsJSON string
	var domJSON string

	err = chromedp.Run(c,
		network.Enable(),
		chromedp.Navigate(url),
		chromedp.WaitReady("body"),
		chromedp.Sleep(500*time.Millisecond),
		chromedp.OuterHTML("html", &body),
		chromedp.Evaluate(jsPayload, &globalsJSON),
		chromedp.Evaluate(domPayload, &domJSON),
	)

	if err != nil {
		return nil, "", nil, nil, err
	}

	if globalsJSON != "" {
		_ = json.Unmarshal([]byte(globalsJSON), &jsGlobals)
	}
	if domJSON != "" {
		_ = json.Unmarshal([]byte(domJSON), &domMatches)
	}

	return headers, body, jsGlobals, domMatches, nil
}

func toJSON(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// UniqueFingerprints helpers
func NewUniqueFingerprints() UniqueFingerprints {
	return UniqueFingerprints{
		values: make(map[string]uniqueFingerprintMetadata),
	}
}

func (u UniqueFingerprints) GetValues() map[string]struct{} {
	values := make(map[string]struct{}, len(u.values))
	for k, v := range u.values {
		if v.confidence == 0 {
			continue
		}
		values[FormatAppVersion(k, v.version)] = struct{}{}
	}
	return values
}

func (u UniqueFingerprints) SetIfNotExists(value, version string, confidence int) {
	if _, ok := u.values[value]; ok {
		new := u.values[value]
		updatedConfidence := new.confidence + confidence
		if updatedConfidence > 100 {
			updatedConfidence = 100
		}
		new.confidence = updatedConfidence
		if new.version == "" && version != "" {
			new.version = version
		}
		u.values[value] = new
		return
	}
	u.values[value] = uniqueFingerprintMetadata{
		confidence: confidence,
		version:    version,
	}
}

// Header fingerprinting
func (s *Wappalyze) checkHeaders(headers map[string]string) []matchPartResult {
	return s.fingerprints.matchMapString(headers, headersPart)
}

func (s *Wappalyze) normalizeHeaders(headers map[string][]string) map[string]string {
	normalized := make(map[string]string, len(headers))
	data := getHeadersMap(headers)
	for header, value := range data {
		normalized[strings.ToLower(header)] = strings.ToLower(value)
	}
	return normalized
}

func getHeadersMap(headersArray map[string][]string) map[string]string {
	headers := make(map[string]string, len(headersArray))
	builder := &strings.Builder{}
	for key, value := range headersArray {
		for i, v := range value {
			builder.WriteString(v)
			if i != len(value)-1 {
				builder.WriteString(", ")
			}
		}
		headers[key] = builder.String()
		builder.Reset()
	}
	return headers
}

// Cookie fingerprinting
func (s *Wappalyze) checkCookies(cookies []string) []matchPartResult {
	normalized := s.normalizeCookies(cookies)
	return s.fingerprints.matchMapString(normalized, cookiesPart)
}

func (s *Wappalyze) normalizeCookies(cookies []string) map[string]string {
	normalized := make(map[string]string)
	for _, part := range cookies {
		parts := strings.SplitN(strings.Trim(part, " "), "=", keyValuePairLength)
		if len(parts) < keyValuePairLength {
			continue
		}
		normalized[parts[0]] = parts[1]
	}
	return normalized
}

func (s *Wappalyze) findSetCookie(headers map[string]string) []string {
	value, ok := headers["set-cookie"]
	if !ok {
		return nil
	}
	var values []string
	for _, v := range strings.Split(value, " ") {
		if v == "" {
			continue
		}
		if strings.Contains(v, ",") {
			values = append(values, strings.Split(v, ",")...)
		} else if strings.Contains(v, ";") {
			values = append(values, strings.Split(v, ";")...)
		} else {
			values = append(values, v)
		}
	}
	return values
}

// Body fingerprinting
func (s *Wappalyze) checkBody(body []byte) []matchPartResult {
	var technologies []matchPartResult
	bodyString := unsafeToString(body)
	technologies = append(technologies, s.fingerprints.matchString(bodyString, htmlPart)...)

	tokenizer := html.NewTokenizer(bytes.NewReader(body))
	for {
		tt := tokenizer.Next()
		switch tt {
		case html.ErrorToken:
			return technologies
		case html.StartTagToken:
			token := tokenizer.Token()
			switch token.Data {
			case "script":
				source, found := getScriptSource(token)
				if found {
					technologies = append(technologies, s.fingerprints.matchString(source, scriptPart)...)
					continue
				}
			case "meta":
				name, content, found := getMetaNameAndContent(token)
				if !found {
					continue
				}
				technologies = append(technologies, s.fingerprints.matchKeyValueString(name, content, metaPart)...)
			}
		case html.SelfClosingTagToken:
			token := tokenizer.Token()
			if token.Data != "meta" {
				continue
			}
			name, content, found := getMetaNameAndContent(token)
			if !found {
				continue
			}
			technologies = append(technologies, s.fingerprints.matchKeyValueString(name, content, metaPart)...)
		}
	}
}

func (s *Wappalyze) getTitle(body []byte) string {
	var title string
	tokenizer := html.NewTokenizer(bytes.NewReader(body))
	for {
		tt := tokenizer.Next()
		switch tt {
		case html.ErrorToken:
			return title
		case html.StartTagToken:
			token := tokenizer.Token()
			switch token.Data {
			case "title":
				if tokenType := tokenizer.Next(); tokenType != html.TextToken {
					continue
				}
				title = tokenizer.Token().Data
			}
		}
	}
}

func getMetaNameAndContent(token html.Token) (string, string, bool) {
	if len(token.Attr) < keyValuePairLength {
		return "", "", false
	}
	var name, content string
	for _, attr := range token.Attr {
		switch attr.Key {
		case "name":
			name = attr.Val
		case "content":
			content = attr.Val
		}
	}
	return name, content, true
}

func getScriptSource(token html.Token) (string, bool) {
	if len(token.Attr) < 1 {
		return "", false
	}
	var source string
	for _, attr := range token.Attr {
		switch attr.Key {
		case "src":
			source = attr.Val
		}
	}
	return source, true
}

func unsafeToString(data []byte) string {
	return *(*string)(unsafe.Pointer(&data))
}

// probeDomainConcurrent probes both HTTP and HTTPS concurrently and returns the first successful URL
func probeDomainConcurrent(domain string, probeTimeout int, userAgent string, client *http.Client) (string, string) {
	type result struct {
		url    string
		scheme string
	}

	resultChan := make(chan result, 1)

	// Try HTTPS concurrently
	go func() {
		if isReachable("https://"+domain, probeTimeout, userAgent, client) {
			select {
			case resultChan <- result{url: "https://" + domain, scheme: "https://"}:
			default:
			}
		}
	}()

	// Try HTTP concurrently
	go func() {
		if isReachable("http://"+domain, probeTimeout, userAgent, client) {
			select {
			case resultChan <- result{url: "http://" + domain, scheme: "http://"}:
			default:
			}
		}
	}()

	// Wait for first success or timeout
	select {
	case res := <-resultChan:
		return res.url, res.scheme
	case <-time.After(time.Duration(probeTimeout) * time.Second):
		return "", ""
	}
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

// Options holds all configuration flags
type Options struct {
	Output          string
	JSONOutput      bool
	CSVOutput       bool
	Threads         int
	UserAgent       string
	SendToDiscord   bool
	DiscordId       string
	ProviderConfig  string
	MatchTech       string
	Verbose         bool
	Version         bool
	Silent          bool
	Delay           time.Duration
	Retries         int
	Timeout         int
	HeadlessTimeout int
	RetriesDelay    int
	Insecure        bool
	RateLimit       int
	NoResume        bool
	Mode            string // "best" = headless (default), "fast" = static HTTP only
	BrowserPoolSize int    // Number of browsers to keep in pool for headless mode
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
	defaulttechfinderConfigPath := filepath.Join(homeDir, ".config", "techfinder", "technologies.txt")

	options := &Options{}
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`A high-performance technology detection tool built with Go, leveraging the projectdiscovery wappalyzergo library to identify web technologies and frameworks.`)

	createGroup(flagSet, "output", "Output",
		flagSet.StringVarP(&options.Output, "output", "o", "", "File to save output (default is stdout)"),
		flagSet.BoolVar(&options.JSONOutput, "json", false, "Output in JSON format"),
		flagSet.BoolVar(&options.CSVOutput, "csv", false, "Output in CSV format"),
	)

	createGroup(flagSet, "rate-limit", "RATE-LIMIT",
		flagSet.IntVarP(&options.Threads, "threads", "t", 50, "Number of threads to use"),
	)

	createGroup(flagSet, "configurations", "Configurations",
		flagSet.StringVarP(&options.UserAgent, "user-agent", "H", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36", "Custom User-Agent header for HTTP requests"),
		flagSet.BoolVar(&options.SendToDiscord, "discord", false, "Send Matched tech to Discord"),
		flagSet.StringVar(&options.DiscordId, "id", "alivesubdomain", "Discord id to send the notification"),
		flagSet.StringVarP(&options.ProviderConfig, "provider-config", "pc", defaultConfigPath, "provider config path"),
		flagSet.BoolVar(&options.NoResume, "no-resume", false, "Disable resume functionality and start scanning fresh"),
	)

	createGroup(flagSet, "matchers", "Matchers",
		flagSet.StringVarP(&options.MatchTech, "match-tech", "mt", defaulttechfinderConfigPath, "Send matched tech output to Discord (comma-separated, file)"),
	)

	createGroup(flagSet, "debug", "Debug",
		flagSet.BoolVar(&options.Verbose, "verbose", false, "Enable verbose output for debugging purposes"),
		flagSet.BoolVar(&options.Version, "version", false, "Print the version of the tool and exit"),
		flagSet.BoolVar(&options.Silent, "silent", false, "silent mode"),
	)

	createGroup(flagSet, "optimizations", "OPTIMIZATIONS",
		flagSet.IntVar(&options.Retries, "retries", 1, "Number of retry attempts for failed HTTP requests"),
		flagSet.IntVar(&options.Timeout, "timeout", 15, "HTTP request timeout in seconds for fingerprinting and initial protocol probing"),
		flagSet.IntVar(&options.HeadlessTimeout, "headless-timeout", 30, "Headless browser timeout in seconds (browser launch + navigation + JS execution)"),
		flagSet.IntVarP(&options.RetriesDelay, "retriesDelay", "rd", 0, "Delay in seconds between retry attempts"),
		flagSet.BoolVarP(&options.Insecure, "insecure", "i", false, "Disable TLS verification"),
		flagSet.DurationVar(&options.Delay, "delay", -1, "duration between each http request (eg: 200ms, 1s)"),
		flagSet.IntVar(&options.RateLimit, "rate", 0, "Maximum requests per second (0 = unlimited)"),
		flagSet.StringVar(&options.Mode, "mode", "best", "Detection mode: 'best' uses headless browser for JS/DOM fingerprinting (default), 'fast' uses static HTTP only"),
		flagSet.IntVar(&options.BrowserPoolSize, "browser-pool-size", 5, "Number of headless browsers to keep in pool (only for 'best' mode, max 20)"),
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
	file, err := os.ReadFile(configFile)
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

	options := ParseOptions()
	// Check if the request was successful
	if options.Verbose {
		if resp.StatusCode == http.StatusNoContent {
			fmt.Println("Matched tech Message sent to Discord successfully!")
		} else {
			fmt.Printf("Failed to send message. Status code: %d\n", resp.StatusCode)
		}
	}
}

// ensureTechnologiesFile checks if the technologies.txt file exists in the config directory
// If it doesn't exist, downloads it from the GitHub repository
func ensureTechnologiesFile(techFilePath string, verbose bool) error {
	// Check if file already exists
	if _, err := os.Stat(techFilePath); err == nil {
		if verbose {
			fmt.Printf("Technologies file already exists at: %s\n", techFilePath)
		}
		return nil
	}

	if verbose {
		fmt.Printf("Technologies file not found. Downloading to: %s\n", techFilePath)
	}

	// Create the directory if it doesn't exist
	techDir := filepath.Dir(techFilePath)
	if err := os.MkdirAll(techDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %v", err)
	}

	// Download the file from GitHub
	url := "https://raw.githubusercontent.com/rix4uni/techfinder/main/technologies.txt"

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("failed to download technologies file: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download technologies file: HTTP %d", resp.StatusCode)
	}

	// Create the file
	file, err := os.Create(techFilePath)
	if err != nil {
		return fmt.Errorf("failed to create technologies file: %v", err)
	}
	defer file.Close()

	// Write the downloaded content to the file
	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to write technologies file: %v", err)
	}

	if verbose {
		fmt.Printf("Successfully downloaded technologies file to: %s\n", techFilePath)
	}

	return nil
}

// ensureFingerprintsFiles checks if fingerprint JSON files exist in the config directory
// If they don't exist, downloads them from the GitHub repository
func ensureFingerprintsFiles(configDir string, verbose bool) error {
	files := map[string]string{
		"fingerprints_data.json": "https://raw.githubusercontent.com/projectdiscovery/wappalyzergo/refs/heads/main/fingerprints_data.json",
		"categories_data.json":   "https://raw.githubusercontent.com/projectdiscovery/wappalyzergo/refs/heads/main/categories_data.json",
	}

	for filename, url := range files {
		filePath := filepath.Join(configDir, filename)

		// Check if file already exists
		if _, err := os.Stat(filePath); err == nil {
			if verbose {
				fmt.Printf("Fingerprint file already exists at: %s\n", filePath)
			}
			continue
		}

		if verbose {
			fmt.Printf("Downloading %s to: %s\n", filename, filePath)
		}

		client := &http.Client{
			Timeout: 120 * time.Second, // Larger file needs more time
		}

		resp, err := client.Get(url)
		if err != nil {
			return fmt.Errorf("failed to download %s: %v", filename, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("failed to download %s: HTTP %d", filename, resp.StatusCode)
		}

		file, err := os.Create(filePath)
		if err != nil {
			return fmt.Errorf("failed to create %s: %v", filename, err)
		}
		defer file.Close()

		_, err = io.Copy(file, resp.Body)
		if err != nil {
			return fmt.Errorf("failed to write %s: %v", filename, err)
		}

		if verbose {
			fmt.Printf("Successfully downloaded %s\n", filename)
		}
	}

	return nil
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
		banner.PrintBanner()
		banner.PrintVersion()
		return
	}

	if !options.Silent {
		banner.PrintBanner()
	}

	// Check if -discord flag is provided without -pc
	if options.SendToDiscord && options.ProviderConfig == "" {
		fmt.Println("Error: -pc flag is required when using -discord.")
		os.Exit(1)
	}
	var config *Config
	var err error // Declare err here
	// Only load the configuration if -discord and -pc is provided
	if options.SendToDiscord && options.ProviderConfig != "" {
		config, err = loadConfig(options.ProviderConfig)
		if err != nil {
			fmt.Println("Error loading config:", err)
			os.Exit(1)
		}
	}

	// Ensure technologies.txt file exists (download if needed)
	if strings.HasSuffix(options.MatchTech, ".txt") {
		if err := ensureTechnologiesFile(options.MatchTech, options.Verbose); err != nil {
			fmt.Printf("Error ensuring technologies file: %v\n", err)
			os.Exit(1)
		}
	}

	// Ensure fingerprint JSON files exist (download if needed)
	userHomeDir, _ := os.UserHomeDir()
	techfinderConfigDir := filepath.Join(userHomeDir, ".config", "techfinder")
	if err := ensureFingerprintsFiles(techfinderConfigDir, options.Verbose); err != nil {
		if options.Verbose {
			fmt.Printf("Warning: could not ensure fingerprint files: %v\n", err)
		}
		// Don't exit - files might exist in current directory
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
	wappalyzerClient, err := NewWappalyzer()
	if err != nil {
		if options.Verbose {
			fmt.Printf("Error initializing Wappalyzer client: %v\n", err)
		}
		os.Exit(1)
	}

	// Initialize browser pool for headless mode
	var browserPool *BrowserPool
	if options.Mode == "best" && options.BrowserPoolSize > 0 {
		poolSize := options.BrowserPoolSize
		if poolSize > 20 {
			poolSize = 20 // Max limit
		}
		if options.Verbose {
			fmt.Printf("Initializing browser pool with %d browsers...\n", poolSize)
		}
		browserPool = NewBrowserPool(poolSize)
		if err := browserPool.Initialize(); err != nil {
			if options.Verbose {
				fmt.Printf("Warning: could not initialize browser pool: %v\n", err)
			}
			browserPool = nil // Fall back to creating new browser per URL
		} else {
			defer browserPool.Close()
		}
	}

	// Initialize Discord config only if SendToDiscord is enabled
	var discordConfig *DiscordConfig
	if options.SendToDiscord {
		// Use a hardcoded ID to find the corresponding webhook URL
		hardcodedID := options.DiscordId // replace with your desired hardcoded ID
		discordConfig = getDiscordConfigByID(config, hardcodedID)
		if discordConfig == nil {
			fmt.Printf("Discord config with ID '%s' not found in %s\n", hardcodedID, options.ProviderConfig)
			os.Exit(1)
		}
	}
	// Initialize HTTP client with improved TLS and transport settings
	tr := &http.Transport{
		MaxIdleConns:          5000,
		MaxIdleConnsPerHost:   100,
		MaxConnsPerHost:       100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		Proxy:                 http.ProxyFromEnvironment,
		ForceAttemptHTTP2:     true,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}
	if options.Insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	httpClient := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(options.Timeout) * time.Second,
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

	// Resume setup
	cwd, _ := os.Getwd()
	resumePath := filepath.Join(cwd, "resume.cfg")
	start := 0
	if options.NoResume {
		_ = deleteResume(resumePath)
		if !options.Silent {
			fmt.Fprintln(os.Stderr, "Starting fresh; resume disabled (--no-resume)")
		}
	} else {
		if s, err := loadResume(resumePath); err == nil {
			start = s
			if start > 0 && !options.Silent {
				fmt.Fprintf(os.Stderr, "Resuming from scanned=%d (skipping %d items)\n", start, start)
			}
		}
	}

	// Global context + interrupt handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)
	interrupted := false
	go func() {
		<-sigCh
		interrupted = true
		fmt.Fprintln(os.Stderr, "\nInterrupt received. Cancelling pending tasks and saving progress...")
		cancel()
	}()

	if !options.NoResume {
		_ = saveResume(resumePath, start)
	}

	// Create a channel for URLs and a wait group
	type workItem struct{ index int; value string }
	workChan := make(chan workItem)
	var wg sync.WaitGroup
	sem := make(chan struct{}, options.Threads) // Semaphore to limit the number of concurrent threads
	var mu sync.Mutex                           // Mutex for synchronized output

	// Rate limiter (optional)
	var rateLimiter <-chan time.Time
	if options.RateLimit > 0 {
		rateLimiter = time.Tick(time.Second / time.Duration(options.RateLimit))
	}

	// Worker function to process URLs
	doneCh := make(chan int, options.Threads*2)

	// Progress collector
	nextLocal := start
	pending := make(map[int]struct{})
	collectorDone := make(chan struct{})
	go func() {
		defer close(collectorDone)
		for idx := range doneCh {
			pending[idx] = struct{}{}
			for {
				if _, ok := pending[nextLocal]; ok {
					delete(pending, nextLocal)
					nextLocal++
					_ = saveResume(resumePath, nextLocal)
				} else {
					break
				}
			}
		}
	}()

	worker := func() {
		for wi := range workChan {
			// Acquire semaphore slot
			sem <- struct{}{}

			// Rate limiting
			if options.RateLimit > 0 {
				<-rateLimiter
			}

			// Probe if needed (domain without protocol)
			domain := wi.value
			url := domain
			if !strings.HasPrefix(domain, "http://") && !strings.HasPrefix(domain, "https://") {
				probedURL, scheme := probeDomainConcurrent(domain, options.Timeout, options.UserAgent, httpClient)
				if probedURL == "" {
					if options.Verbose {
						mu.Lock()
						fmt.Printf("Skipping %s: both http:// and https:// failed\n", domain)
						mu.Unlock()
					}
					<-sem // Release semaphore before continue
					continue
				}
				url = probedURL
				if options.Verbose {
					mu.Lock()
					fmt.Printf("Probed Scheme: %s for %s\n", scheme, domain)
					mu.Unlock()
				}
			}

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
				reqCtx, reqCancel := context.WithTimeout(ctx, time.Duration(options.Timeout)*time.Second)

				req, err := http.NewRequestWithContext(reqCtx, "GET", url, nil)
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

				// If global ctx cancelled, abort quickly
				if ctx.Err() != nil {
					reqCancel()
					fetchErr = fmt.Errorf("cancelled")
				} else {
					resp, fetchErr = httpClient.Do(req)
				}
				reqCancel() // Always cancel per-request context after use
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
				// Do not mark completion if cancelled
				<-sem
				if ctx.Err() != nil {
					continue
				}
				// Mark completion for resume progress
				select {
				case doneCh <- wi.index:
				case <-ctx.Done():
				}
				continue
			}
			data, _ := io.ReadAll(resp.Body)
			resp.Body.Close() // Close the body after reading

			// Fingerprint the URL — mode determines static vs headless
			var fingerprints map[string]struct{}
			if options.Mode == "best" {
				var headlessErr error
				if browserPool != nil {
					// Use browser pool for faster headless scanning
					fingerprints, headlessErr = wappalyzerClient.FingerprintURLWithPool(browserPool, url, time.Duration(options.HeadlessTimeout)*time.Second)
				} else {
					// Fallback: create new browser context per URL
					headlessCtx, headlessCancel := context.WithTimeout(ctx, time.Duration(options.HeadlessTimeout)*time.Second)
					fingerprints, headlessErr = wappalyzerClient.FingerprintURL(headlessCtx, url)
					headlessCancel()
				}
				if headlessErr != nil {
					if options.Verbose {
						mu.Lock()
						fmt.Fprintf(os.Stderr, "Headless failed for %s: %v\n", url, headlessErr)
						mu.Unlock()
					}
					<-sem
					select {
					case doneCh <- wi.index:
					case <-ctx.Done():
					}
					continue
				}
			} else {
				// Fast mode: use static HTTP response only
				fingerprints = wappalyzerClient.Fingerprint(resp.Header, data)
			}

			// Matches
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
			count := len(tech) // Count the number of detected technologies

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
				if options.SendToDiscord && config != nil && discordConfig != nil {
					discord(discordConfig.DiscordWebhookURL, messageContent)
				}
			}

			// Delay between requests if delay is set
			if options.Delay > 0 {
				time.Sleep(options.Delay)
			}

			// Release the semaphore
			<-sem
			// Mark completion for resume progress (only if not cancelled)
			if ctx.Err() == nil {
				select {
				case doneCh <- wi.index:
				case <-ctx.Done():
				}
			}
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

	// Reading URLs from stdin and sending them to the channel with resume offset
	scanner := bufio.NewScanner(os.Stdin)
	total := 0
	for scanner.Scan() {
		line := scanner.Text()
		// We count non-empty lines as items
		if strings.TrimSpace(line) == "" {
			continue
		}
		if total >= start {
			workChan <- workItem{index: total, value: line}
		}
		total++
	}

	// Early exit if everything already scanned
	if !options.NoResume && start >= total {
		if !options.Silent {
			fmt.Fprintln(os.Stderr, "Nothing to do; all items already scanned. Use --no-resume to start over.")
		}
		close(workChan)
		close(doneCh)
		<-collectorDone
		_ = deleteResume(resumePath)
		return
	}

	// Close the work channel and wait for all workers to finish
	close(workChan)
	wg.Wait()
	close(doneCh)
	<-collectorDone

	// Handle scanner errors
	if err := scanner.Err(); err != nil {
		if options.Verbose {
			mu.Lock()
			fmt.Printf("Error reading from stdin: %v\n", err)
			mu.Unlock()
		}
		os.Exit(1)
	}

	// Cleanup resume file and print hint if interrupted
	if nextLocal >= total && !interrupted {
		_ = deleteResume(resumePath)
	}
	if interrupted {
		fmt.Fprintln(os.Stderr, "Progress saved to resume.cfg. Re-run the same command to resume, or use --no-resume to start over.")
	}
}

// Resume helpers
func loadResume(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "scanned=") {
			val := strings.TrimPrefix(line, "scanned=")
			n, err := strconv.Atoi(strings.TrimSpace(val))
			if err == nil && n >= 0 {
				return n, nil
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, err
	}
	return 0, nil
}

func saveResume(path string, scanned int) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	data := []byte(fmt.Sprintf("scanned=%d\n", scanned))
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		_ = os.Remove(path)
	}
	return os.Rename(tmp, path)
}

func deleteResume(path string) error {
	if _, err := os.Stat(path); err == nil {
		return os.Remove(path)
	}
	return nil
}
