# Local test databases (MariaDB & MongoDB)

Helper scripts under `scripts/` spin up throwaway MariaDB and MongoDB containers so
you can run the server (or the integration tests) against a real database. They use
**non-standard ports** to avoid colliding with any local 3306/27017 instance, and the
containers are **ephemeral** (`docker run --rm`, no data volume) — every start is a
clean database.

## Prerequisites
- Docker running locally.
- Run the scripts **from the project root** (they guard on `./scripts` existing).

## Ports and credentials

| Service       | Host port | Credentials / notes                                  |
|---------------|-----------|------------------------------------------------------|
| MariaDB       | `13306`   | db `enode`, user `enode` / `password` (root `root`)  |
| phpMyAdmin    | `18080`   | http://localhost:18080                               |
| MongoDB       | `37017`   | no auth; db `enode` created on first write           |
| mongo-express | `18081`   | http://localhost:18081 (login `admin` / `admin`)     |
| Manticore     | `19306`   | SQL protocol, no auth; `19308` is its HTTP API (optional, `scripts/docker-manticore.sh`) |

## Usage

```bash
# Start both databases (and their admin UIs)
./scripts/docker-testdb.sh

# Or start just one
./scripts/docker-mariadb.sh
./scripts/docker-mongodb.sh

# Stop everything (or a single stack)
./scripts/docker-testdb.sh stop
./scripts/docker-mariadb.sh stop
./scripts/docker-mongodb.sh stop
```

Manticore Search, the optional full-text index for the mysql and mongodb engines
(`storage.manticore`, see [manticore-search.local.md](manticore-search.local.md)), has a script
of its own and is not part of `docker-testdb.sh`:

```bash
./scripts/docker-manticore.sh        # start
./scripts/docker-manticore.sh stop   # stop
```

## Pointing the server at a database

`enode.local.yaml` (the gitignored local config) already carries the ports above. To
run the server against a container, set `storage.engine`:

```yaml
storage:
  engine: mysql      # or: mongodb
```

Then start it:

```bash
go run ./cmd/enode -config enode.local.yaml
```

### Schema is created automatically
The **mysql** engine creates its tables on first connect: when the `clients` table is
absent, `storage.MySQLEngine.Init` reads `misc/enode.sql` (relative to the working
directory, overridable via `storage.mysql.schemaFile`) and applies it. There is no
migration support — an existing database is left untouched, so the file is only read on
a fresh one. Because of this the MariaDB container needs nothing mounted; a fresh
container gets its schema the first time the server connects.

The **mongodb** engine self-provisions its collections and indexes in `Init`, so it
needs no schema file.

## Integration tests
The dockertest integration suites (`ENODE_INTEGRATION=1 go test ./storage ./ed2k -run
Integration` / `-run Dockertest`) manage their **own** ephemeral containers on random
ports and do not use these scripts. They rely on the same first-connect schema
creation, locating `misc/enode.sql` from any package via
`tests.FixRelativeTestingPath` in `tests/setup.go`.
