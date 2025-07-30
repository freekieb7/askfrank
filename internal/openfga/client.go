package openfga

import (
	"context"
	"fmt"
	"log/slog"

	"askfrank/internal/config"

	"github.com/openfga/go-sdk/client"
	"github.com/openfga/go-sdk/credentials"
)

// Client wraps OpenFGA client with AskFrank-specific methods
type Client struct {
	fga    *client.OpenFgaClient
	config config.OpenFGAConfig
}

// NewClient creates a new OpenFGA client following AskFrank security patterns
func NewClient(cfg config.OpenFGAConfig) (*Client, error) {
	if !cfg.Enabled {
		slog.Info("OpenFGA is disabled")
		return &Client{config: cfg}, nil
	}

	// Configure OpenFGA client
	fgaClient, err := client.NewSdkClient(&client.ClientConfiguration{
		ApiHost: cfg.APIHost,
		StoreId: cfg.StoreID,
		Credentials: &credentials.Credentials{
			Method: credentials.CredentialsMethodApiToken,
			Config: &credentials.Config{
				ApiToken: cfg.APIToken,
			},
		},
	})

	if err != nil {
		return nil, fmt.Errorf("failed to create OpenFGA client: %w", err)
	}

	c := &Client{
		fga:    fgaClient,
		config: cfg,
	}

	// Verify connection and model
	if err := c.verifyConnection(); err != nil {
		return nil, fmt.Errorf("failed to verify OpenFGA connection: %w", err)
	}

	slog.Info("OpenFGA client initialized successfully",
		"store_id", cfg.StoreID, "model_id", cfg.ModelID)

	return c, nil
}

// verifyConnection verifies the OpenFGA connection and model
func (c *Client) verifyConnection() error {
	if !c.config.Enabled {
		return nil
	}

	ctx := context.Background()

	// Check if store exists
	response, err := c.fga.GetStore(ctx).Execute()
	if err != nil {
		return fmt.Errorf("failed to get store: %w", err)
	}

	if response.Id != c.config.StoreID {
		return fmt.Errorf("store ID mismatch: expected %s, got %s",
			c.config.StoreID, response.Id)
	}

	// Verify authorization model
	modelResponse, err := c.fga.ReadAuthorizationModel(ctx).Execute()
	if err != nil {
		return fmt.Errorf("failed to read authorization model: %w", err)
	}

	if modelResponse.AuthorizationModel.Id != c.config.ModelID {
		slog.Warn("Authorization model ID mismatch",
			"expected", c.config.ModelID,
			"actual", modelResponse.AuthorizationModel.Id)
	}

	return nil
}

// IsEnabled returns whether OpenFGA is enabled
func (c *Client) IsEnabled() bool {
	return c.config.Enabled && c.fga != nil
}

// Close closes the OpenFGA client connection
func (c *Client) Close() {
	// OpenFGA client doesn't have a Close method, so we just nil the reference
	if c.fga != nil {
		c.fga = nil
	}
}

// CheckPermission checks if a user has a specific permission on an object
func (c *Client) CheckPermission(ctx context.Context, userID, relation, objectType, objectID string) (bool, error) {
	if !c.config.Enabled {
		return true, nil // Pass-through when disabled
	}

	body := client.ClientCheckRequest{
		User:     fmt.Sprintf("user:%s", userID),
		Relation: relation,
		Object:   fmt.Sprintf("%s:%s", objectType, objectID),
	}

	data, err := c.fga.Check(ctx).Body(body).Execute()
	if err != nil {
		slog.Error("OpenFGA check failed",
			"user", userID,
			"relation", relation,
			"object", fmt.Sprintf("%s:%s", objectType, objectID),
			"error", err)
		return false, err
	}

	allowed := data.GetAllowed()
	slog.Debug("OpenFGA check completed",
		"user", userID,
		"relation", relation,
		"object", fmt.Sprintf("%s:%s", objectType, objectID),
		"allowed", allowed)

	return allowed, nil
}

// WriteTuple creates a relationship tuple in OpenFGA
func (c *Client) WriteTuple(ctx context.Context, userID, relation, objectType, objectID string) error {
	if !c.config.Enabled {
		return nil // Pass-through when disabled
	}

	body := client.ClientWriteRequest{
		Writes: []client.ClientTupleKey{
			{
				User:     fmt.Sprintf("user:%s", userID),
				Relation: relation,
				Object:   fmt.Sprintf("%s:%s", objectType, objectID),
			},
		},
	}

	_, err := c.fga.Write(ctx).Body(body).Execute()
	if err != nil {
		slog.Error("OpenFGA write failed",
			"user", userID,
			"relation", relation,
			"object", fmt.Sprintf("%s:%s", objectType, objectID),
			"error", err)
		return err
	}

	slog.Debug("OpenFGA tuple written",
		"user", userID,
		"relation", relation,
		"object", fmt.Sprintf("%s:%s", objectType, objectID))

	return nil
}

// DeleteTuple removes a relationship tuple from OpenFGA
func (c *Client) DeleteTuple(ctx context.Context, userID, relation, objectType, objectID string) error {
	if !c.config.Enabled {
		return nil // Pass-through when disabled
	}

	body := client.ClientWriteRequest{
		Deletes: []client.ClientTupleKeyWithoutCondition{
			{
				User:     fmt.Sprintf("user:%s", userID),
				Relation: relation,
				Object:   fmt.Sprintf("%s:%s", objectType, objectID),
			},
		},
	}

	_, err := c.fga.Write(ctx).Body(body).Execute()
	if err != nil {
		slog.Error("OpenFGA delete failed",
			"user", userID,
			"relation", relation,
			"object", fmt.Sprintf("%s:%s", objectType, objectID),
			"error", err)
		return err
	}

	slog.Debug("OpenFGA tuple deleted",
		"user", userID,
		"relation", relation,
		"object", fmt.Sprintf("%s:%s", objectType, objectID))

	return nil
}
