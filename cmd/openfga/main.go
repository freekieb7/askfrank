package main

import (
	"context"
	"encoding/json"
	"fmt"
	"hp/internal/config"
	"hp/internal/openfga"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	ctx := context.Background()
	command := os.Args[1]

	cfg := config.NewConfig()

	fgaClient, err := openfga.NewClient(cfg.OpenFGA)
	if err != nil {
		panic(err)
	}

	switch command {
	case "list-stores":
		handleListStores(ctx, &fgaClient)
	case "create-store":
		handleCreateStore(ctx, &fgaClient, os.Args[2:])
	case "delete-store":
		handleDeleteStore(ctx, &fgaClient, os.Args[2:])
	case "list-models":
		handleListModels(ctx, &fgaClient, os.Args[2:])
	case "write-model":
		handleWriteModel(ctx, &fgaClient, os.Args[2:])
	case "read-model":
		handleReadModel(ctx, &fgaClient, os.Args[2:])
	default:
		printUsage()
	}
}

func handleListStores(ctx context.Context, fgaClient *openfga.Client) {
	stores, err := fgaClient.ListStores(ctx)
	if err != nil {
		panic(err)
	}

	for _, store := range stores {
		fmt.Printf("Store ID: %s, Name: %s\n", store.Id, store.Name)
	}
}

func handleCreateStore(ctx context.Context, fgaClient *openfga.Client, args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: openfga create-store <name>")
		return
	}

	name := args[0]
	id, err := fgaClient.CreateStore(ctx, name)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Created store with ID: %s\n", id)
}

func handleDeleteStore(ctx context.Context, fgaClient *openfga.Client, args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: openfga delete-store <name>")
		return
	}

	name := args[0]
	if err := fgaClient.DeleteStore(ctx, name); err != nil {
		panic(err)
	}
}

func handleListModels(ctx context.Context, fgaClient *openfga.Client, args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: openfga list-models <store_id>")
		return
	}

	storeID := args[0]
	models, err := fgaClient.ReadAllModels(ctx, storeID)
	if err != nil {
		panic(err)
	}

	for _, model := range models {
		fmt.Printf("Model ID: %s\n", model.Id)
	}
}

func handleWriteModel(ctx context.Context, fgaClient *openfga.Client, args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: openfga write-model <store_id>")
		return
	}

	storeID := args[0]
	modelID, err := fgaClient.WriteAuthorizationModel(ctx, storeID)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Authorization model written with ID: %s\n", modelID)
}

func handleReadModel(ctx context.Context, fgaClient *openfga.Client, args []string) {
	if len(args) < 2 {
		fmt.Println("Usage: openfga read-model <store_id> <authorization_model_id>")
		return
	}

	storeID := args[0]
	authorizationModelID := args[1]

	model, err := fgaClient.ReadAuthorizationModel(ctx, storeID, authorizationModelID)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Authorization Model ID: %s\n", model.Id)
	fmt.Printf("Schema Version: %s\n", model.SchemaVersion)
	out, err := json.MarshalIndent(model.TypeDefinitions, "", "  ")
	if err != nil {
		panic(err)
	}
	fmt.Printf("Type Definitions: %s\n", out)

	conditions, err := json.MarshalIndent(model.Conditions, "", "  ")
	if err != nil {
		panic(err)
	}
	fmt.Printf("Conditions: %s\n", conditions)

}

func printUsage() {
	fmt.Println("Usage: openfga <command>")
	fmt.Println("Commands:")
	fmt.Println("  create-store           Create a new OpenFGA store")
	fmt.Println("  delete-store           Delete an existing OpenFGA store")
	fmt.Println("  write-model            Write the authorization model to OpenFGA")
}
