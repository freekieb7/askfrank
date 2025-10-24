package openfga

// import (
// 	"context"
// 	"encoding/json"
// 	"fmt"
// 	"log/slog"
// 	"os"

// 	openfga "github.com/openfga/go-sdk"
// 	openfgaClient "github.com/openfga/go-sdk/client"
// )

// // Client wraps OpenFGA client with AskFrank-specific methods
// type Client struct {
// 	fga *openfgaClient.OpenFgaClient
// }

// // NewClient creates a new OpenFGA client following AskFrank security patterns
// // func NewClient(cfg config.OpenFGAConfig) (Client, error) {
// // 	var client Client

// // 	// Configure OpenFGA client
// // 	fgaClient, err := openfgaClient.NewSdkClient(&openfgaClient.ClientConfiguration{
// // 		ApiUrl:               cfg.APIURL,
// // 		StoreId:              cfg.StoreID,
// // 		AuthorizationModelId: cfg.AuthorizationModelID,
// // 		// Credentials: &credentials.Credentials{
// // 		// 	Method: credentials.CredentialsMethodApiToken,
// // 		// 	Config: &credentials.Config{
// // 		// 		ApiToken: cfg.APIToken,
// // 		// 	},
// // 		// },
// // 	})

// // 	if err != nil {
// // 		return client, fmt.Errorf("failed to create OpenFGA client: %w", err)
// // 	}

// // 	client.fga = fgaClient

// // 	return client, nil
// // }

// // CheckPermission checks if a user has a specific permission on an object
// func (c *Client) CheckPermission(ctx context.Context, userType, userID, relation, objectType, objectID string) (bool, error) {
// 	body := openfgaClient.ClientCheckRequest{
// 		User:     fmt.Sprintf("%s:%s", userType, userID),
// 		Relation: relation,
// 		Object:   fmt.Sprintf("%s:%s", objectType, objectID),
// 	}

// 	data, err := c.fga.Check(ctx).Body(body).Execute()
// 	if err != nil {
// 		slog.Error("OpenFGA check failed",
// 			"user", userID,
// 			"relation", relation,
// 			"object", fmt.Sprintf("%s:%s", objectType, objectID),
// 			"error", err)
// 		return false, err
// 	}

// 	allowed := data.GetAllowed()
// 	slog.Debug("OpenFGA check completed",
// 		"user", userID,
// 		"relation", relation,
// 		"object", fmt.Sprintf("%s:%s", objectType, objectID),
// 		"allowed", allowed)

// 	return allowed, nil
// }

// // WriteTuple creates a relationship tuple in OpenFGA
// func (c *Client) WriteTuple(ctx context.Context, userID, relation, objectType, objectID string) error {
// 	body := openfgaClient.ClientWriteRequest{
// 		Writes: []openfgaClient.ClientTupleKey{
// 			{
// 				User:     fmt.Sprintf("user:%s", userID),
// 				Relation: relation,
// 				Object:   fmt.Sprintf("%s:%s", objectType, objectID),
// 			},
// 		},
// 	}

// 	_, err := c.fga.Write(ctx).Body(body).Execute()
// 	if err != nil {
// 		slog.Error("OpenFGA write failed",
// 			"user", userID,
// 			"relation", relation,
// 			"object", fmt.Sprintf("%s:%s", objectType, objectID),
// 			"error", err)
// 		return err
// 	}

// 	slog.Debug("OpenFGA tuple written",
// 		"user", userID,
// 		"relation", relation,
// 		"object", fmt.Sprintf("%s:%s", objectType, objectID))

// 	return nil
// }

// // DeleteTuple removes a relationship tuple from OpenFGA
// func (c *Client) DeleteTuple(ctx context.Context, userType, userID, relation, objectType, objectID string) error {
// 	body := openfgaClient.ClientWriteRequest{
// 		Deletes: []openfgaClient.ClientTupleKeyWithoutCondition{
// 			{
// 				User:     fmt.Sprintf("%s:%s", userType, userID),
// 				Relation: relation,
// 				Object:   fmt.Sprintf("%s:%s", objectType, objectID),
// 			},
// 		},
// 	}

// 	_, err := c.fga.Write(ctx).Body(body).Execute()
// 	if err != nil {
// 		slog.Error("OpenFGA delete failed",
// 			"user", userID,
// 			"relation", relation,
// 			"object", fmt.Sprintf("%s:%s", objectType, objectID),
// 			"error", err)
// 		return err
// 	}

// 	slog.Debug("OpenFGA tuple deleted",
// 		"user", userID,
// 		"relation", relation,
// 		"object", fmt.Sprintf("%s:%s", objectType, objectID))

// 	return nil
// }

// func (c *Client) ListStores(ctx context.Context) ([]openfga.Store, error) {
// 	response, err := c.fga.ListStores(ctx).Execute()
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to list stores: %w", err)
// 	}

// 	return response.Stores, nil
// }

// func (c *Client) CreateStore(ctx context.Context, name string) (string, error) {
// 	body := openfgaClient.ClientCreateStoreRequest{
// 		Name: name,
// 	}

// 	res, err := c.fga.CreateStore(ctx).Body(body).Execute()
// 	if err != nil {
// 		slog.Error("OpenFGA create store failed", "error", err)
// 		return "", err
// 	}

// 	return res.Id, nil
// }

// func (c *Client) DeleteStore(ctx context.Context, name string) error {
// 	_, err := c.fga.OpenFgaApi.DeleteStore(ctx, name).Execute()
// 	return err
// }

// func (c *Client) ReadAllModels(ctx context.Context, storeID string) ([]openfga.AuthorizationModel, error) {
// 	c.fga.SetStoreId(storeID)

// 	res, _, err := c.fga.OpenFgaApi.ReadAuthorizationModels(ctx, storeID).Execute()
// 	if err != nil {
// 		slog.Error("OpenFGA read authorization model failed", "store_id", storeID, "error", err)
// 		return nil, err
// 	}

// 	return res.AuthorizationModels, nil
// }

// func (c *Client) WriteAuthorizationModel(ctx context.Context, storeID string) (string, error) {
// 	c.fga.SetStoreId(storeID)

// 	rawModel, err := os.ReadFile("./internal/openfga/models/model.v1.json")
// 	if err != nil {
// 		slog.Error("OpenFGA read model file failed", "error", err)
// 		return "", err
// 	}

// 	var body openfga.WriteAuthorizationModelRequest
// 	if err := json.Unmarshal(rawModel, &body); err != nil {
// 		slog.Error("OpenFGA unmarshal model failed", "error", err)
// 		return "", err
// 	}

// 	res, err := c.fga.WriteAuthorizationModel(ctx).Body(body).Execute()
// 	if err != nil {
// 		slog.Error("OpenFGA write authorization model failed", "error", err)
// 		return "", err
// 	}

// 	return res.AuthorizationModelId, nil
// }

// func (c *Client) ReadAuthorizationModel(ctx context.Context, storeID, authorizationModelID string) (*openfga.AuthorizationModel, error) {
// 	c.fga.SetStoreId(storeID)
// 	c.fga.SetAuthorizationModelId(authorizationModelID)

// 	res, err := c.fga.ReadAuthorizationModel(ctx).Execute()
// 	if err != nil {
// 		slog.Error("OpenFGA read authorization model failed", "error", err)
// 		return nil, err
// 	}

// 	return res.AuthorizationModel, nil
// }
