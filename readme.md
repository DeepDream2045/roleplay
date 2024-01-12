# Roleplay Project

## How to running

```terminal
docker compose -f docker-roleplay-compose.yml up --build -d
```

## Delete the container

```terminal
docker compose -f docker-roleplay-compose.yml down -v
```

## Generate Migration

changes roleplay-app-1 to app container name

```terminal
docker exec -it roleplay-app-1 python manage.py makemigrations
```

## Running Migration

changes roleplay-app-1 to app container name

```terminal
docker exec -it roleplay-app-1 python manage.py migrate
```
