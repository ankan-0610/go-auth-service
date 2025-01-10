# Go Auth Service

## Tech Stack
- Go (Golang)
- Fiber (Web Framework)
- Redis (In-Memory Data Store)
- JWT (JSON Web Tokens for Authentication)
- Docker (Containerization)

## Recommended Prerequisites

Replace the accessTokenDuration in main.go with your preferred duration, for testing purposes.
Replace the SECRET_KEY in the docker-compose.yml file, with your own secure key

## Run the auth-service

Ensure you have docker engine running on your system, before running the following

```bash
docker-compose up --build
```

## Curl commands to test the api

1. Sign Up
```bash
curl -X POST http://localhost:3000/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"secret"}'
```

2. Sign In
```bash
curl -X POST http://localhost:3000/auth/signin \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"secret"}'
```

3. Access Protected Route
```bash
curl http://localhost:3000/protected \
  -H "Authorization: Bearer <access_token>"
```

4. Refresh Token
```bash
curl -X POST http://localhost:3000/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"<refresh_token>"}'
```

5. Revoke Token
```bash
curl -X POST http://localhost:3000/auth/revoke \
  -H "Authorization: Bearer <access_token>"
```

## Stop the service

```bash
  docker-compose down
```

## Acknowledgement

I would like to thank the whole Acharya Prashant Team for giving me this opportunity to showcase and practice my Backend skills.

## Contributing

Feel free to raise issues, for feature requests, bugs etc.