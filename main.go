package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/alecthomas/kong"
	"go.opentelemetry.io/contrib/exporters/autoexport"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdkTrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

const expirationLayout = "2006-01-02 15:04:05 MST"

var flags struct {
	TokenEnvVars string `name:"token-env-vars" help:"Comma-separated list of token env var(s)"`
	TokensDir    string `name:"tokens-dir" help:"Directory containing mounted secret tokens"`

	BaseURL             *url.URL      `name:"base-url" default:"https://api.github.com" help:"GitHub API base URL"`
	ExpirationThreshold time.Duration `name:"expiration-threshold" default:"360h" help:"Minimum duration until token expiration"`
}

var tracer trace.Tracer

func main() {
	if err := run(); err != nil {
		fmt.Printf("Error: %v", err)
		os.Exit(1)
	}
}

func run() error {
	kong.Parse(&flags)

	ctx := context.Background()

	// Initialize OpenTelemetry tracing with standard OTEL_* env vars
	exporter, err := autoexport.NewSpanExporter(ctx)
	if err != nil {
		return fmt.Errorf("starting opentelemetry: %w", err)
	}

	tracerProvider := sdkTrace.NewTracerProvider(sdkTrace.WithBatcher(exporter))
	defer func() {
		if err := tracerProvider.Shutdown(ctx); err != nil {
			fmt.Printf("Error stopping opentelemetry: %v", err)
		}
	}()
	tracer = tracerProvider.Tracer("")

	return checkTokens(ctx)
}

func checkTokens(ctx context.Context) (err error) {
	ctx, span := tracer.Start(ctx, "checkTokens")
	defer func() {
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
		}
		span.End()
	}()
	span.SetAttributes(
		attribute.Stringer("ghtokmon.base_url", flags.BaseURL),
		attribute.Float64("ghtokmon.expiration_threshold", flags.ExpirationThreshold.Seconds()))

	tokens := map[string]string{}

	for _, envVar := range strings.Split(flags.TokenEnvVars, ",") {
		if envVar != "" {
			token := os.Getenv(envVar)
			if token == "" {
				return fmt.Errorf("no value for configured token-env-var %q", envVar)
			}
			tokens[envVar] = token
		}
	}

	if len(flags.TokensDir) > 0 {
		entries, err := os.ReadDir(flags.TokensDir)
		if err != nil {
			return fmt.Errorf("reading tokens-dir %q: %w", flags.TokensDir, err)
		}
		for _, entry := range entries {
			path := path.Join(flags.TokensDir, entry.Name())
			byteContents, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("reading %q: %w", path, err)
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
					return fmt.Errorf("no auths or invalid JSON in %q: %v", path, err)
				}
				for domain, auth := range dockerConfig.Auths {
					tokens[fmt.Sprintf("%s (%s)", entry.Name(), domain)] = auth.Password
				}
			} else {
				tokens[entry.Name()] = strings.TrimSpace(token)
			}
		}
	}
	span.SetAttributes(attribute.StringSlice("ghtokmon.tokens", slices.Collect(maps.Keys(tokens))))

	if len(tokens) == 0 {
		return fmt.Errorf("no tokens to check")
	}

	unhappyTokens := []string{}
	for name, token := range tokens {
		happy, err := checkToken(ctx, name, token)
		if err != nil {
			log.Printf("Failed checking token %q: %v", name, err)
		}
		if !happy {
			unhappyTokens = append(unhappyTokens, name)
		}
	}
	if len(unhappyTokens) > 0 {
		return fmt.Errorf("checks failed for token(s): %s", strings.Join(unhappyTokens, ", "))
	}
	return nil
}

func checkToken(ctx context.Context, name, token string) (happy bool, err error) {
	ctx, span := tracer.Start(ctx, name)
	defer func() {
		if err != nil {
			span.SetStatus(codes.Error, err.Error())
		}
		span.End()
	}()
	fmt.Printf("\nChecking %q...\n", name)

	userURL := flags.BaseURL.JoinPath("user").String()

	req, err := http.NewRequestWithContext(ctx, "GET", userURL, nil)
	if err != nil {
		return false, fmt.Errorf("new request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("reading body: %w", err)
	}

	if resp.StatusCode != 200 {
		span.SetAttributes(attribute.String("ghtokmon.error_body", strconv.QuoteToASCII(string(body[:1024]))))
		return false, fmt.Errorf("got status code %d != 200", resp.StatusCode)
	}

	var user struct {
		Login string `json:"login"`
	}
	err = json.Unmarshal(body, &user)
	if err != nil {
		return false, fmt.Errorf("deserializing user: %w", err)
	}
	span.SetAttributes(attribute.String("ghtokmon.token.login", user.Login))
	fmt.Printf("Token user login: %s\n", user.Login)

	happy = true

	expirationValue := resp.Header.Get("github-authentication-token-expiration")
	if expirationValue == "" {
		fmt.Println("Token expiration: NONE")
	} else {
		span.SetAttributes(attribute.String("ghtokmon.token.expiration", expirationValue))
		expiration, err := time.Parse(expirationLayout, expirationValue)
		if err != nil {
			return false, fmt.Errorf("invalid expiration header value %q: %w", expirationValue, err)
		}
		fmt.Printf("Token expiration: %s", expiration)

		expirationDuration := time.Until(expiration)
		span.SetAttributes(attribute.Float64("ghtokmon.token.expiration_duration", expirationDuration.Seconds()))

		fmt.Printf(" (%.1f days)\n", expirationDuration.Hours()/24)
		if expirationDuration < flags.ExpirationThreshold {
			fmt.Println("WARNING: Expiring soon!")
			happy = false
			span.SetStatus(codes.Error, "token expiring soon")
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
			span.SetStatus(codes.Error, "high rate limit usage")
			happy = false
		}
	}

	oAuthScopes := resp.Header.Get("x-oauth-scopes")
	span.SetAttributes(attribute.String("ghtokmon.token.oauth_scopes", oAuthScopes))
	fmt.Printf("OAuth scopes: %s\n", oAuthScopes)
	return happy, nil
}
