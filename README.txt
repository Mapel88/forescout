prerequisites:
dockerDesktop installed

cd dockers
docker compose -f agents-compose.yaml build
docker compose -f .\jenkins-compose.yaml up -d --build

login jenkins:
https://localhost:8080
admin - Aa123456


run job