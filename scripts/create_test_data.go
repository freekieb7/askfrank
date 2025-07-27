package main

import (
	"askfrank/internal/config"
	"askfrank/internal/database"
	"askfrank/internal/model"
	"askfrank/internal/repository"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Connect to the database
	dataSourceName := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Database.Host, cfg.Database.Port, cfg.Database.User, cfg.Database.Password, cfg.Database.Name, cfg.Database.SSLMode)
	db, err := database.NewDatabase(dataSourceName)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Fatalf("Failed to close database connection: %v", err)
		}
	}()

	// Initialize repository
	repo := repository.NewDatabaseRepository(db)

	// Create test users
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("Failed to hash password: %v", err)
	}

	// Admin user (verified)
	adminUser := model.User{
		ID:            uuid.New(),
		Name:          "Admin User",
		Email:         "admin@example.com",
		PasswordHash:  string(hashedPassword),
		EmailVerified: true,
		CreatedAt:     time.Now(),
	}

	// Regular verified user
	regularUser := model.User{
		ID:            uuid.New(),
		Name:          "John Doe",
		Email:         "john@example.com",
		PasswordHash:  string(hashedPassword),
		EmailVerified: true,
		CreatedAt:     time.Now().Add(-24 * time.Hour), // Created yesterday
	}

	// Pending user (not verified)
	pendingUser := model.User{
		ID:            uuid.New(),
		Name:          "Jane Smith",
		Email:         "jane@example.com",
		PasswordHash:  string(hashedPassword),
		EmailVerified: false,
		CreatedAt:     time.Now().Add(-2 * time.Hour), // Created 2 hours ago
	}

	// Another pending user
	pendingUser2 := model.User{
		ID:            uuid.New(),
		Name:          "Bob Wilson",
		Email:         "bob@example.com",
		PasswordHash:  string(hashedPassword),
		EmailVerified: false,
		CreatedAt:     time.Now().Add(-30 * time.Minute), // Created 30 minutes ago
	}

	// Create users
	users := []model.User{adminUser, regularUser, pendingUser, pendingUser2}
	for _, user := range users {
		err = repo.CreateUser(user)
		if err != nil {
			log.Printf("Failed to create user %s: %v", user.Email, err)
		} else {
			fmt.Printf("Created user: %s (%s)\n", user.Name, user.Email)
		}
	}

	// Create registrations for pending users
	registrations := []model.UserRegistration{
		{
			ID:             uuid.New(),
			UserID:         pendingUser.ID,
			ActivationCode: "activation-code-jane",
			CreatedAt:      pendingUser.CreatedAt,
		},
		{
			ID:             uuid.New(),
			UserID:         pendingUser2.ID,
			ActivationCode: "activation-code-bob",
			CreatedAt:      pendingUser2.CreatedAt,
		},
	}

	for _, registration := range registrations {
		err = repo.CreateUserRegistration(registration)
		if err != nil {
			log.Printf("Failed to create registration for user %s: %v", registration.UserID, err)
		} else {
			fmt.Printf("Created registration for user: %s\n", registration.UserID)
		}
	}

	fmt.Println("\nTest data created successfully!")
	fmt.Println("Admin user: admin@example.com (password: password123)")
	fmt.Println("Regular user: john@example.com (password: password123)")
	fmt.Println("Pending users: jane@example.com, bob@example.com (password: password123)")
	fmt.Println("\nYou can now test the admin functionality at http://localhost:8080/admin")
}
