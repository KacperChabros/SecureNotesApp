#!/bin/bash

mkdir -p ./app/data
sudo chown www-data:docker ./app/data
sudo chmod 770 ./app/data

docker-compose down --volumes --remove-orphans
docker-compose up --build
