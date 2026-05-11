#!/bin/bash

docker-compose -f docker-compose-elastic.yml up -d

python3 elastic_shipper.py

