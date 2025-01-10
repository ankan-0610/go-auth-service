package main

import(
	"context"

	"github.com/gofiber/fiber/v2"
	"golang.org/x/crypto/bcrypt"
	"github.com/redis/go-redis/v9"
	"github.com/golang-jwt/jwt/v5"
)

func handleSignup(c *fiber.Ctx) error {
	user := new(User)

	if err := c.BodyParser(user); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	if user.Email == "" || user.Password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Email and password are required",
		})
	}

	// Check if user already exists
	exists, err := redisClient.Exists(context.Background(), "user:"+user.Email).Result()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Internal server error",
		})
	}
	if exists == 1 {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"error": "User already exists",
		})
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Internal server error",
		})
	}

	// Store user in Redis
	err = redisClient.Set(context.Background(), "user:"+user.Email, string(hashedPassword), 0).Err()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Internal server error",
		})
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"message": "User created successfully",
	})
}

func handleSignin(c *fiber.Ctx) error {
	user := new(User)
	if err := c.BodyParser(user); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid request body",
		})
	}

	storedPassword, err := redisClient.Get(context.Background(), "user:"+user.Email).Result()
	if err == redis.Nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid credentials",
		})
	} else if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Internal server error",
		})
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(user.Password))
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
			"error": "Invalid credentials",
		})
	}

	accessToken, refreshToken, err := generateTokens(user.Email)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Internal server error",
		})
	}

	return c.JSON(TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:   int64(accessTokenDuration.Seconds()),
	})
}

func handleRefreshToken(c *fiber.Ctx) error {
	
    token := c.Locals("refresh_token").(*jwt.Token)
    claims := token.Claims.(jwt.MapClaims)
    email := claims["email"].(string)

    // Generate new tokens
    accessToken, refreshToken, err := generateTokens(email)
    if err != nil {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Internal server error",
        })
    }

    return c.JSON(TokenResponse{
        AccessToken:  accessToken,
        RefreshToken: refreshToken,
        ExpiresIn:   int64(accessTokenDuration.Seconds()),
    })
}

func handleRevokeToken(c *fiber.Ctx) error {
	token := c.Locals("user").(*jwt.Token)
	claims := token.Claims.(jwt.MapClaims)
	tokenID := claims["jti"].(string)

	// Add token to revoked list
	err := redisClient.Set(context.Background(), "revoked:"+tokenID, "1", refreshTokenDuration).Err()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Internal server error",
		})
	}

	return c.JSON(fiber.Map{
		"message": "Token revoked successfully",
	})
}

// handleProtected is an example protected route
func handleProtected(c *fiber.Ctx) error {
	token, ok := c.Locals("user").(*jwt.Token)
    if !ok {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Failed to get user token from context",
        })
    }
	claims, ok := token.Claims.(jwt.MapClaims)
    if !ok {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Invalid token claims format",
        })
    }
	email, ok := claims["email"].(string)
    if !ok {
        return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
            "error": "Email claim not found in token",
        })
    }

	return c.JSON(fiber.Map{
		"message": "Protected route accessed successfully",
		"email":   email,
	})
}