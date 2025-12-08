package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// ScrapeResult holds the data found during scraping
type ScrapeResult struct {
	URL            string   `json:"url"`
	RobotsTxt      string   `json:"robots_txt,omitempty"`
	DevFiles       []string `json:"dev_files,omitempty"`
	JavaScriptFiles []string `json:"javascript_files,omitempty"`
	NewSubdomains  []string `json:"new_subdomains,omitempty"`
	Error          string   `json:"error,omitempty"`
}

var (
	// Global rate limiter for this web scraper instance (5 requests per second)
	limiter = rate.NewLimiter(rate.Limit(5), 1)
	// Use the local proxy
	proxyURL, _ = url.Parse("http://127.0.0.1:8080")
	httpClient  = &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}
)

// performRequest waits for the rate limiter and then executes an HTTP request.
func performRequest(req *http.Request) (*http.Response, error) {
	ctx := context.Background()
	err := limiter.Wait(ctx) // Blocks until a token is available
	if err != nil {
		return nil, fmt.Errorf("rate limiter wait failed: %w", err)
	}
	log.Printf("[WebScraper] Making request to: %s", req.URL.String())
	return httpClient.Do(req)
}

// WebScraper performs multi-threaded web scraping
func WebScraper(targetURL string) (*ScrapeResult, error) {
	result := &ScrapeResult{URL: targetURL}
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		result.Error = fmt.Sprintf("Failed to parse URL: %v", err)
		return result, err
	}

	var wg sync.WaitGroup

	// Task 1: Fetch robots.txt
	wg.Add(1)
	go func() {
		defer wg.Done()
		robotsURL := fmt.Sprintf("%s://%s/robots.txt", parsedURL.Scheme, parsedURL.Host)
		req, _ := http.NewRequest("GET", robotsURL, nil)
		resp, err := performRequest(req)
		if err != nil {
			log.Printf("[WebScraper] Error fetching robots.txt for %s: %v", parsedURL.Host, err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			body, _ := ioutil.ReadAll(resp.Body)
			result.RobotsTxt = string(body)
			log.Printf("[WebScraper] Discovered robots.txt for %s", parsedURL.Host)
		}
	}()

	// Task 2: Find common dev files
	devFilePaths := []string{".env", "/.git/config", "/swagger.json", "/api-docs"} // More can be added
	for _, path := range devFilePaths {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			devURL := fmt.Sprintf("%s://%s%s", parsedURL.Scheme, parsedURL.Host, p)
			req, _ := http.NewRequest("GET", devURL, nil)
			resp, err := performRequest(req)
			if err != nil {
				return // Logged by performRequest
			}
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				result.DevFiles = append(result.DevFiles, devURL)
				log.Printf("[WebScraper] Discovered dev file: %s", devURL)
			}
		}(path)
	}

	// Task 3: Scrape main page for JS files and subdomains
	wg.Add(1)
	go func() {
		defer wg.Done()
		req, _ := http.NewRequest("GET", targetURL, nil)
		resp, err := performRequest(req)
		if err != nil {
			result.Error = fmt.Sprintf("Error fetching main URL %s: %v", targetURL, err)
			log.Printf("Error fetching main URL %s: %v", targetURL, err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			body, _ := ioutil.ReadAll(resp.Body)
			htmlContent := string(body)

			// Regex for JS files
			jsRegex := regexp.MustCompile(`src=["']([^"']+\.js)`)
			jsMatches := jsRegex.FindAllStringSubmatch(htmlContent, -1)
			for _, match := range jsMatches {
				if len(match) > 1 {
					jsURL := match[1]
					if !isAbsolute(jsURL) {
						jsURL = resolveRelativeURL(parsedURL, jsURL)
					}
					result.JavaScriptFiles = append(result.JavaScriptFiles, jsURL)
					log.Printf("[WebScraper] Found JS file: %s", jsURL)
				}
			}

			// Regex for subdomains
			subdomainRegex := regexp.MustCompile(`https?://([a-zA-Z0-9.-]+\` + regexp.QuoteMeta(parsedURL.Host) + `)`)
			subdomainMatches := subdomainRegex.FindAllStringSubmatch(htmlContent, -1)
			for _, match := range subdomainMatches {
				if len(match) > 1 {
					s := match[1]
					// Basic deduplication. A real system would use a database.
					found := false
					for _, existing := range result.NewSubdomains {
						if existing == s {
							found = true
							break
						}
					}
					if !found {
						result.NewSubdomains = append(result.NewSubdomains, s)
						log.Printf("[WebScraper] Found new subdomain: %s", s)
					}
				}
			}
		}
	}()

	wg.Wait()
	return result, nil
}

func isAbsolute(path string) bool {
	return strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") || strings.HasPrefix(path, "//")
}

func resolveRelativeURL(baseURL *url.URL, relativePath string) string {
	rel, err := url.Parse(relativePath)
	if err != nil {
		return relativePath // Fallback
	}
	return baseURL.ResolveReference(rel).String()
}

func main() {
	// In the actual framework, target URLs would come from the Super Agent.
	// For local testing, we'll read them from command line arguments.
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <target_url1> <target_url2> ...")
		return
	}

	targets := os.Args[1:] // Get targets from command line

	for _, target := range targets {
		fmt.Printf("[WebScraper] Starting web scraping for %s...\n", target)
		scrapeResult, err := WebScraper(target)
		if err != nil {
			fmt.Printf("[WebScraper] Scraping failed for %s: %v\n", target, err)
		} else {
			fmt.Printf("[WebScraper] Scraping completed for %s\n", scrapeResult.URL)
			// Simulate sending results to Super Agent/Database
			fmt.Printf("[WebScraper] Simulating DB/Super Agent update for %s: %+v\n", scrapeResult.URL, scrapeResult)
			// A real system would serialize scrapeResult to JSON and send via Pub/Sub or insert into DB.

			// Simulate exploit_context update for discovered items
			if scrapeResult.RobotsTxt != "" {
				fmt.Printf("[WebScraper] Documenting in exploit_context: Discovered robots.txt for %s.\n", scrapeResult.URL)
			}
			if len(scrapeResult.DevFiles) > 0 {
				fmt.Printf("[WebScraper] Documenting in exploit_context: Discovered dev files for %s: %v.\n", scrapeResult.URL, scrapeResult.DevFiles)
			}
			if len(scrapeResult.NewSubdomains) > 0 {
				fmt.Printf("[WebScraper] Documenting in exploit_context: Discovered new subdomains for %s: %v.\n", scrapeResult.URL, scrapeResult.NewSubdomains)
			}
			fmt.Println("---")
		}
	}
}