package proxy

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/shii9/ReconNio/internal/proxy/source"
)

// FastFetchProxies fetches proxies with minimal validation
func FastFetchProxies() ([]string, error) {
	sources := source.GetSources()
	if len(sources) == 0 {
		return nil, errors.New("no proxy sources configured")
	}

	client := &http.Client{
		Timeout: 3 * time.Second,
	}

	type result struct {
		proxies []string
		err     error
	}

	results := make(chan result, len(sources))
	var wg sync.WaitGroup

	for _, source := range sources {
		wg.Add(1)
		go func(src string) {
			defer wg.Done()

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			req, _ := http.NewRequestWithContext(ctx, "GET", src, nil)
			resp, err := client.Do(req)
			if err != nil {
				results <- result{nil, err}
				return
			}
			defer resp.Body.Close()

			scanner := bufio.NewScanner(resp.Body)
			var proxies []string

			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}

				// Quick format check
				if strings.Contains(line, ":") {
					proxies = append(proxies, line)
				}
			}

			results <- result{proxies, nil}
		}(source)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	// Fast deduplication
	seen := make(map[string]bool)
	var out []string

	for r := range results {
		if r.err != nil {
			continue
		}
		for _, proxy := range r.proxies {
			if !seen[proxy] {
				seen[proxy] = true
				out = append(out, proxy)
			}
		}
	}

	if len(out) == 0 {
		return nil, errors.New("no proxies found")
	}
	return out, nil
}

// UltraFastValidate validates proxies with 1-second timeout
func UltraFastValidate(proxies []string) []string {
	if len(proxies) == 0 {
		return []string{}
	}

	valid := make([]string, 0)
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Use semaphore to limit concurrency
	semaphore := make(chan struct{}, 100)

	for _, proxy := range proxies {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Ultra-fast TCP check
			dialer := &net.Dialer{
				Timeout: 1 * time.Second,
			}

			conn, err := dialer.Dial("tcp", p)
			if err != nil {
				return
			}
			conn.Close()

			mu.Lock()
			valid = append(valid, p)
			mu.Unlock()
		}(proxy)
	}

	wg.Wait()
	return valid
}

// GetValidProxies fetches and validates proxies quickly
func GetValidProxies() ([]string, error) {
	proxies, err := FastFetchProxies()
	if err != nil {
		return nil, err
	}

	return UltraFastValidate(proxies), nil
}
