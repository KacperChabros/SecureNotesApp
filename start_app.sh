#!/bin/bash

mkdir -p ./app/data
sudo chown 33:33 ./app/data
sudo chmod 770 ./app/data

sudo docker-compose down --volumes --remove-orphans
sudo docker-compose up --build
