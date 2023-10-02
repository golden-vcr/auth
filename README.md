# auth

The **auth**  API facilitates user authentication and authorization via the Twitch API.
For more detail, see:

- **OpenAPI specification:** https://golden-vcr.github.io/auth/

## Prerequisites

Install [Go 1.21](https://go.dev/doc/install). If successful, you should be able to run:

```
> go version
go version go1.21.0 windows/amd64
```

## Initial setup

Create a file in the root of this repo called `.env` that contains the environment
variables required in [`main.go`](./cmd/server/main.go). If you have the
[`terraform`](https://github.com/golden-vcr/terraform) repo cloned alongside this one,
simply open a shell there and run:

- `terraform output -raw twitch_api_env > ../auth/.env`
- `./local-db.sh env >> ../auth/.env`

### Running the database

This API stores persistent data in a PostgreSQL database. When running in a live
environment, each API has its own database, and connection details are configured from
Terraform secrets via .env files.

For local development, we run a self-contained postgres database in Docker, and all
server-side applications share the same set of throwaway credentials.

We use a script in the [`terraform`](https://github.com/golden-vcr/terraform) repo,
called `./local-db.sh`, to manage this local database. To start up a fresh database and
apply migrations, run:

- _(from `terraform`:)_ `./local-db.sh up`
- _(from `auth`:)_ `./db-migrate.sh`

If you need to blow away your local database and start over, just run
`./local-db.sh down` and repeat these steps.

### Generating database queries

If you modify the SQL code in [`db/queries`](./db/queries/), you'll need to generate
new Go code to [`gen/queries`](./gen/queries/). To do so, simply run:

- `./db-generate-queries.sh`

## Running

Once your `.env` file is populated, you should be able to build and run the server:

- `go run cmd/server/main.go`

If successful, you should be able to run `curl http://localhost:5002/access` and
receive a response.
