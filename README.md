
# Quickstart

```
cat << EOF > .env
HOST=localhost
PORT=8000
DATABASE_URL=postgresql://postgres:password@localhost:5432/db?schema=public
POSTGRES_USER=postgres
POSTGRES_PASSWORD=password
POSTGRES_DB=db
REDIS_URL=redis://localhost:6379
EOF

podman run -d --name pg -p5432:5432 --env-file .env docker.io/postgres:16
podman run -d --name redis -p6379:6379  docker.io/redis

cargo prisma migrate dev

cargo run
```

# Docker

Nothing special with docker. Just `podman build .`. The docker file is insane, but it won't unnecessarily rebuild dependencies