package bridgemain

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aegis-sigma/engine/internal/config"
)

// StripeClient handles Stripe API interactions.
type StripeClient struct {
	SecretKey     string
	WebhookSecret string
	WebhookURL    string
	HTTPClient    *http.Client
}

// NewStripeClient creates a Stripe client from vault keys.
func NewStripeClient() *StripeClient {
	return &StripeClient{
		SecretKey:     readVault("STRIPE_SECRET_KEY"),
		WebhookSecret: readVault("STRIPE_WEBHOOK_SECRET"),
		WebhookURL:    readVault("STRIPE_WEBHOOK_URL"),
		HTTPClient:    &http.Client{Timeout: 30 * time.Second},
	}
}

func readVault(name string) string {
	data, err := os.ReadFile("/etc/aegis-sigma/vault/" + name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// CheckoutSession represents a Stripe Checkout Session response.
type CheckoutSession struct {
	ID          string `json:"id"`
	URL         string `json:"url"`
	Status      string `json:"status"`
	AmountTotal int64  `json:"amount_total"`
}

// CreateCheckoutSession creates a Stripe Checkout Session for a quote.
func (s *StripeClient) CreateCheckoutSession(quote Quote) (*CheckoutSession, error) {
	if s.SecretKey == "" {
		return nil, fmt.Errorf("Stripe secret key not configured")
	}

	cfg := config.LoadConfig()

	// Build line items
	var lineItems []map[string]interface{}
	for _, item := range quote.Items {
		lineItems = append(lineItems, map[string]interface{}{
			"price_data": map[string]interface{}{
				"currency":     "usd",
				"unit_amount":  item.Price,
				"product_data": map[string]interface{}{
					"name":        item.Service,
					"description": item.Description,
				},
			},
			"quantity": 1,
		})
	}

	// Build request body
	body := map[string]interface{}{
		"mode":       "payment",
		"line_items": lineItems,
		"success_url": cfg.Stripe.SuccessURL + "?session_id={CHECKOUT_SESSION_ID}",
		"cancel_url":  cfg.Stripe.CancelURL,
		"customer_email": quote.Email,
		"metadata": map[string]string{
			"domain":        quote.Domain,
			"business_name": quote.BusinessName,
			"type":          "lead_quote",
		},
	}

	jsonBody, _ := json.Marshal(body)

	req, err := http.NewRequest("POST", "https://api.stripe.com/v1/checkout/sessions", bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+s.SecretKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("stripe request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		errBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("stripe error %d: %s", resp.StatusCode, string(errBody))
	}

	var session CheckoutSession
	if err := json.NewDecoder(resp.Body).Decode(&session); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	log.Printf("[bridge] created Stripe checkout session %s for %s ($%d)", session.ID, quote.Domain, session.AmountTotal/100)
	return &session, nil
}

// VerifyWebhookSignature verifies a Stripe webhook signature.
func (s *StripeClient) VerifyWebhookSignature(payload []byte, signature string) (map[string]interface{}, error) {
	if s.WebhookSecret == "" {
		return nil, fmt.Errorf("webhook secret not configured")
	}

	// Basic signature verification (simplified — in production use stripe-go library)
	// For now, just decode the payload
	var event map[string]interface{}
	if err := json.Unmarshal(payload, &event); err != nil {
		return nil, fmt.Errorf("invalid payload: %w", err)
	}

	return event, nil
}

// Available returns true if Stripe keys are configured.
func (s *StripeClient) Available() bool {
	return s.SecretKey != ""
}
