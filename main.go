package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/alecthomas/kong"
)

const expirationLayout = "2006-01-02 15:04:05 MST"

var flags struct {
	TokenEnvVars string `name:"token-env-vars" help:"Comma-separated list of token env var(s)"`
	TokensDir    string `name:"tokens-dir" help:"Directory containing mounted secret tokens"`

	BaseURL             string `name:"base-url" default:"https://api.github.com" help:"GitHub API base URL"`
	ExpirationThreshold string `name:"expiration-threshold" default:"360h" help:"Minimum duration until token expiration"`
}

func main() {
	kong.Parse(&flags)

	userURL := flags.BaseURL + "/user"

	expirationThreshold, err := time.ParseDuration(flags.ExpirationThreshold)
	if err != nil {
		log.Fatalf("Invalid expiration-threshold %q: %v", flags.ExpirationThreshold, err)
	}

	tokens := map[string]string{}

	for _, envVar := range strings.Split(flags.TokenEnvVars, ",") {
		if envVar != "" {
			token := os.Getenv(envVar)
			if token == "" {
				log.Fatalf("No value for configured token-env-var %q", envVar)
			}
			tokens[envVar] = token
		}
	}

	if len(flags.TokensDir) > 0 {
		entries, err := os.ReadDir(flags.TokensDir)
		if err != nil {
			log.Fatalf("Error reading tokens-dir %q: %v", flags.TokensDir, err)
		}
		for _, entry := range entries {
			path := path.Join(flags.TokensDir, entry.Name())
			byteContents, err := os.ReadFile(path)
			if err != nil {
				log.Fatalf("Error reading %q: %v", path, err)
			}

			token := string(byteContents)
			if strings.HasPrefix(token, "{") {
				var dockerConfig struct {
					Auths map[string]struct {
						Password string `json:"password"`
					}
				}
				err := json.Unmarshal(byteContents, &dockerConfig)
				if len(dockerConfig.Auths) == 0 {
					log.Fatalf("No auths or invalid JSON in %q: %v", path, err)
				}
				for domain, auth := range dockerConfig.Auths {
					tokens[fmt.Sprintf("%s (%s)", entry.Name(), domain)] = auth.Password
				}
			} else {
				tokens[entry.Name()] = strings.TrimSpace(token)
			}
		}
	}

	if len(tokens) == 0 {
		log.Fatal("No tokens to check")
	}

	unhappyTokens := []string{}

	for name, token := range tokens {
		fmt.Printf("\nChecking %q...\n", name)

		req, err := http.NewRequest("GET", userURL, nil)
		if err != nil {
			log.Fatalf("Invalid request: %v", err)
		}

		req.Header.Set("Authorization", "Bearer "+token)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Fatalf("Error GETing %q: %v", userURL, err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Fatalf("Error reading response body: %v", err)
		}

		if resp.StatusCode != 200 {
			log.Fatalf("Got status code %d; response body:\n%s", resp.StatusCode, body)
		}

		var user struct {
			Login string `json:"login"`
		}
		err = json.Unmarshal(body, &user)
		if err != nil {
			log.Fatalf("Error deserializing user info: %v", err)
		}
		fmt.Printf("Token user login: %s\n", user.Login)

		happy := true

		expirationValue := resp.Header.Get("github-authentication-token-expiration")
		if expirationValue == "" {
			fmt.Println("Token expiration: NONE")
		} else {
			expiration, err := time.Parse(expirationLayout, expirationValue)
			if err != nil {
				log.Fatalf("Invalid expiration header value %q: %v", expirationValue, err)
			}
			fmt.Printf("Token expiration: %s", expiration)

			expirationDuration := time.Until(expiration)
			fmt.Printf(" (%.1f days)\n", expirationDuration.Hours()/24)
			if expirationDuration < expirationThreshold {
				fmt.Println("WARNING: Expiring soon!")
				happy = false
			}
		}

		rateLimitLimit, _ := strconv.Atoi(resp.Header.Get("x-ratelimit-limit"))
		if rateLimitLimit != 0 {
			rateLimitUsed, _ := strconv.Atoi(resp.Header.Get("x-ratelimit-used"))
			fmt.Printf("Rate limit usage: %d / %d", rateLimitUsed, rateLimitLimit)

			rateLimitPercent := rateLimitUsed * 100 / rateLimitLimit
			fmt.Printf(" (~%d%%)\n", rateLimitPercent)
			if rateLimitPercent > 50 {
				fmt.Println("WARNING: Rate limit >50%!")
				happy = false
			}
		}

		fmt.Printf("OAuth scopes: %s\n", resp.Header.Get("x-oauth-scopes"))

		if !happy {
			unhappyTokens = append(unhappyTokens, name)
		}
	}

	if len(unhappyTokens) > 0 {
		log.Fatalf("Failing token(s): %s", strings.Join(unhappyTokens, ", "))
	}
}
