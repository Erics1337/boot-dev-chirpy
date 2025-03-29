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