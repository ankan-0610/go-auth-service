package main

import (
	"context"

	"github.com/redis/go-redis/v9"
    "github.com/gofiber/fiber/v2"
    "github.com/golang-jwt/jwt/v5"
)

// authMiddleware handles token validation
func authMiddleware(c *fiber.Ctx) error {
	// Get token from Authorization header
	authHeader := c.Get("Authorization")
	if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid authorization header",
		})
	}
	tokenString := authHeader[7:]

	// Parse and validate token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(secretKey), nil
	})

	if err != nil || !token.Valid {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid token",
		})
	}

	// Check if token is revoked
	claims := token.Claims.(jwt.MapClaims)
	tokenID := claims["jti"].(string)

	revoked, err := redisClient.Get(context.Background(), "revoked:"+tokenID).Result()
	if err != redis.Nil || revoked != "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Token has been revoked",
		})
	}

	c.Locals("user", token)
	return c.Next()
}

func refreshTokenMiddleware(c *fiber.Ctx) error {
    refreshReq := new(RefreshRequest)
    if err := c.BodyParser(refreshReq); err != nil {
        return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
            "error": "Invalid request body",
        })
    }

    token, err := jwt.Parse(refreshReq.RefreshToken, func(token *jwt.Token) (interface{}, error) {
        return []byte(secretKey), nil
    })

    if err != nil || !token.Valid {
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
            "error": "Invalid refresh token",
        })
    }

    claims := token.Claims.(jwt.MapClaims)
    tokenType, ok := claims["type"].(string)
    if !ok || tokenType != "refresh" {
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
            "error": "Invalid token type",
        })
    }

    tokenID := claims["jti"].(string)
    revoked, err := redisClient.Get(context.Background(), "revoked:"+tokenID).Result()
    if err != redis.Nil || revoked != "" {
        return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
            "error": "Token has been revoked",
        })
    }

    c.Locals("refresh_token", token)
    return c.Next()
}