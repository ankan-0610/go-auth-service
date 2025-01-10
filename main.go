package main

import (
	"log"
	"os"
	"time"
	"fmt"

	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
	"github.com/golang-jwt/jwt/v5"
)

const (
	accessTokenDuration  = 15 * time.Minute
	refreshTokenDuration = 7 * 24 * time.Hour
)

type User struct {
	Email string `json:"email"`
	Password string `json:"password"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn   int64  `json:"expires_in"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

var redisClient *redis.Client

func getEnv(key, fallback string) string {
    if value, exists := os.LookupEnv(key); exists {
        return value
    }
    return fallback
}

var secretKey string

func main(){

    redisHost := getEnv("REDIS_HOST", "localhost")
    redisPort := getEnv("REDIS_PORT", "6379")
    secretKey = getEnv("SECRET_KEY", "your-secret-key")

    redisClient = redis.NewClient(&redis.Options{
        Addr:     fmt.Sprintf("%s:%s", redisHost, redisPort),
        Password: "", // no password set
        DB:       0,  // use default DB
    })

	app := fiber.New()

	app.Post("/auth/signup", handleSignup)
	app.Post("/auth/signin", handleSignin)
	app.Post("/auth/refresh", refreshTokenMiddleware, handleRefreshToken)
	app.Post("/auth/revoke", authMiddleware, handleRevokeToken)
	app.Get("/protected", authMiddleware, handleProtected) // example protected route

	log.Fatal(app.Listen(":3000"))
}

// generateTokens creates new access and refresh tokens
func generateTokens(email string) (string, string, error) {
	
	accessTokenID := generateTokenID()
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "email": email,
        "jti":   accessTokenID,
        "type":  "access",
        "exp":   time.Now().Add(accessTokenDuration).Unix(),
    })
	accessTokenString, err := accessToken.SignedString([]byte(secretKey))
	if err != nil {
		return "", "", err
	}

	refreshTokenID := generateTokenID()
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": email,
		"jti":   refreshTokenID,
		"type": "refresh",
		"exp":   time.Now().Add(refreshTokenDuration).Unix(),
	})
	refreshTokenString, err := refreshToken.SignedString([]byte(secretKey))
	if err != nil {
		return "", "", err
	}

	return accessTokenString, refreshTokenString, nil
}

// generateTokenID generates a unique token ID
func generateTokenID() string {
	return os.Args[0] + time.Now().String()
}