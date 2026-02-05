package main

import (
	"log"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
)

func main() {
	// Create a new Fiber app
	app := fiber.New(fiber.Config{
		AppName: "Fiber Example Server",
	})

	// Middleware
	app.Use(recover.New())
	app.Use(logger.New())

	// Routes
	app.Get("/", handleHome)
	app.Get("/api/hello", handleHello)
	app.Get("/api/time", handleTime)
	app.Post("/api/echo", handleEcho)

	// Start server
	log.Println("Starting server on :3000")
	if err := app.Listen(":3000"); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

// handleHome returns a welcome message
func handleHome(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"message": "Welcome to Fiber Example Server",
		"endpoints": []string{
			"GET  /",
			"GET  /api/hello",
			"GET  /api/time",
			"POST /api/echo",
		},
	})
}

// handleHello returns a greeting with optional name parameter
func handleHello(c *fiber.Ctx) error {
	name := c.Query("name", "World")
	return c.JSON(fiber.Map{
		"message": "Hello, " + name + "!",
	})
}

// handleTime returns the current server time
func handleTime(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"time": time.Now().Format(time.RFC3339),
	})
}

// handleEcho echoes back the request body
func handleEcho(c *fiber.Ctx) error {
	type EchoRequest struct {
		Message string `json:"message"`
	}

	var req EchoRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	return c.JSON(fiber.Map{
		"echo": req.Message,
	})
}
