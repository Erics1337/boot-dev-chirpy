# Chirpy

This is the Chirpy backend service.

## Prerequisites

*   Go (version specified in `go.mod`)
*   PostgreSQL database running
*   `sqlc` installed (`go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest`)
*   `goose` installed (`go install github.com/pressly/goose/v3/cmd/goose@latest`)

## Setup

1.  **Clone the repository:**
    ```bash
    git clone <repository-url>
    cd boot-dev-chirpy
    ```
2.  **Create a `.env` file:**
    Copy the `.env.example` (if one exists) or create a new `.env` file with the following variables:
    ```dotenv
    DB_URL=postgres://<user>:<password>@<host>:<port>/<database>?sslmode=disable
    JWT_SECRET=<your-strong-jwt-secret>
    # PLATFORM=dev (optional, defaults to dev)
    ```
    Replace the placeholders with your actual database credentials and generate a strong JWT secret.

## Running the Application

1.  **Run Database Migrations:**
    Apply any pending database migrations:
    ```bash
    goose -dir sql/schema postgres "$DB_URL" up
    ```
    *(Note: Ensure your `DB_URL` environment variable is set correctly or replace `"$DB_URL"` with the full connection string)*

2.  **Run the Server:**
    ```bash
    go run main.go
    ```
    The server will start, typically on port 8080.

## Development

*   **Generate SQLC Code:**
    After modifying SQL queries in `sql/queries/` or schema files that affect queries, regenerate the Go database code:
    ```bash
    sqlc generate
    ```

*   **Create New Migrations:**
    Use `goose` to create new migration files:
    ```bash
    goose -dir sql/schema create <migration_name> sql
    ```
    Edit the generated SQL file in `sql/schema/` with your `UP` and `DOWN` migrations.

*   **Rollback Migrations:**
    To roll back the last applied migration:
    ```bash
    goose -dir sql/schema postgres "$DB_URL" down
    ```

## API Endpoints

Base URL: `http://localhost:8080` (when running locally)

### Health & Metrics

*   **`GET /api/healthz`**
    *   Description: Checks the readiness of the server.
    *   Authentication: None.
    *   Success Response: `200 OK` with body `OK`.

*   **`GET /admin/metrics`**
    *   Description: Returns HTML page displaying the number of hits to the fileserver.
    *   Authentication: None.
    *   Success Response: `200 OK` with HTML content.

*   **`POST /admin/reset`**
    *   Description: Resets the fileserver hit counter.
    *   Authentication: None.
    *   Success Response: `200 OK`.

### Users

*   **`POST /api/users`**
    *   Description: Creates a new user.
    *   Authentication: None.
    *   Request Body:
        ```json
        {
          "email": "user@example.com",
          "password": "password123"
        }
        ```
    *   Success Response: `201 Created`
        ```json
        {
          "id": "uuid-string",
          "created_at": "rfc3339-timestamp",
          "updated_at": "rfc3339-timestamp",
          "email": "user@example.com",
          "is_chirpy_red": false
        }
        ```
    *   Error Responses: `400 Bad Request` (invalid body), `500 Internal Server Error`.

*   **`PUT /api/users`**
    *   Description: Updates the authenticated user's email and password.
    *   Authentication: JWT Bearer Token (`Authorization: Bearer <token>`).
    *   Request Body:
        ```json
        {
          "email": "new-email@example.com",
          "password": "new-password"
        }
        ```
    *   Success Response: `200 OK`
        ```json
        {
          "id": "uuid-string",
          "created_at": "rfc3339-timestamp",
          "updated_at": "rfc3339-timestamp",
          "email": "new-email@example.com",
          "is_chirpy_red": false // Or true if upgraded
        }
        ```
    *   Error Responses: `400 Bad Request` (invalid body), `401 Unauthorized` (invalid/missing token), `500 Internal Server Error`.

### Authentication

*   **`POST /api/login`**
    *   Description: Logs in a user and returns access and refresh tokens.
    *   Authentication: None.
    *   Request Body:
        ```json
        {
          "email": "user@example.com",
          "password": "password123"
        }
        ```
    *   Success Response: `200 OK`
        ```json
        {
          "id": "uuid-string",
          "created_at": "rfc3339-timestamp",
          "updated_at": "rfc3339-timestamp",
          "email": "user@example.com",
          "is_chirpy_red": false, // Or true if upgraded
          "token": "access-jwt-string",
          "refresh_token": "refresh-token-string"
        }
        ```
    *   Error Responses: `400 Bad Request` (invalid body), `401 Unauthorized` (incorrect credentials), `500 Internal Server Error`.

*   **`POST /api/refresh`**
    *   Description: Issues a new access token using a valid refresh token.
    *   Authentication: Refresh Token (`Authorization: Bearer <refresh_token>`).
    *   Success Response: `200 OK`
        ```json
        {
          "token": "new-access-jwt-string"
        }
        ```
    *   Error Responses: `401 Unauthorized` (invalid/missing/revoked/expired token).

*   **`POST /api/revoke`**
    *   Description: Revokes a refresh token.
    *   Authentication: Refresh Token (`Authorization: Bearer <refresh_token>`).
    *   Success Response: `204 No Content`.
    *   Error Responses: (Always returns 204, but logs errors internally).

### Chirps

*   **`POST /api/chirps`**
    *   Description: Creates a new chirp. Cleans profane words ("kerfuffle", "sharbert", "fornax").
    *   Authentication: JWT Bearer Token (`Authorization: Bearer <token>`).
    *   Request Body:
        ```json
        {
          "body": "This is a chirp!"
        }
        ```
    *   Success Response: `201 Created`
        ```json
        {
          "id": "uuid-string",
          "created_at": "rfc3339-timestamp",
          "updated_at": "rfc3339-timestamp",
          "body": "This is a chirp!",
          "user_id": "author-uuid-string"
        }
        ```
    *   Error Responses: `400 Bad Request` (invalid body, chirp too long), `401 Unauthorized` (invalid/missing token), `500 Internal Server Error`.

*   **`GET /api/chirps`**
    *   Description: Retrieves a list of chirps.
    *   Authentication: None.
    *   Query Parameters:
        *   `author_id` (optional, UUID string): Filters chirps by the specified author.
        *   `sort` (optional, string): Sort order. Accepts `asc` (default) or `desc`. Sorting is by `created_at`.
    *   Success Response: `200 OK`
        ```json
        [
          {
            "id": "uuid-string",
            "created_at": "rfc3339-timestamp",
            "updated_at": "rfc3339-timestamp",
            "body": "Chirp content",
            "user_id": "author-uuid-string"
          },
          ...
        ]
        ```
    *   Error Responses: `400 Bad Request` (invalid `author_id` format), `500 Internal Server Error`.

*   **`GET /api/chirps/{chirpID}`**
    *   Description: Retrieves a single chirp by its ID.
    *   Authentication: None.
    *   Path Parameters:
        *   `chirpID` (UUID string): The ID of the chirp to retrieve.
    *   Success Response: `200 OK`
        ```json
        {
          "id": "uuid-string",
          "created_at": "rfc3339-timestamp",
          "updated_at": "rfc3339-timestamp",
          "body": "Chirp content",
          "user_id": "author-uuid-string"
        }
        ```
    *   Error Responses: `400 Bad Request` (invalid `chirpID` format), `404 Not Found`, `500 Internal Server Error`.

*   **`DELETE /api/chirps/{chirpID}`**
    *   Description: Deletes a chirp by its ID. Only the author of the chirp can delete it.
    *   Authentication: JWT Bearer Token (`Authorization: Bearer <token>`).
    *   Path Parameters:
        *   `chirpID` (UUID string): The ID of the chirp to delete.
    *   Success Response: `204 No Content`.
    *   Error Responses: `400 Bad Request` (invalid `chirpID` format), `401 Unauthorized` (invalid/missing token), `403 Forbidden` (user is not the author), `404 Not Found`, `500 Internal Server Error`.

### Webhooks

*   **`POST /api/polka/webhooks`**
    *   Description: Endpoint for receiving webhooks from the Polka service. Currently handles the `user.upgraded` event to mark a user as Chirpy Red.
    *   Authentication: Polka API Key (`Authorization: ApiKey <polka_api_key>`). Requires `POLKA_API_KEY` environment variable to be set.
    *   Request Body:
        ```json
        {
          "event": "user.upgraded",
          "data": {
            "user_id": "user-uuid-string"
          }
        }
        ```
    *   Success Response: `204 No Content`.
    *   Error Responses: `400 Bad Request` (invalid body/user ID), `401 Unauthorized` (missing/invalid API key), `404 Not Found` (user ID not found), `500 Internal Server Error`. Returns `204 No Content` for events other than `user.upgraded`.