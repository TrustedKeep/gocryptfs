#!/bin/bash

set -x

umount -l /tkfs/data
rm -rf /tkfs/*
mkdir /tkfs/data -p
mkdir /tkfs/cipher

./tkfs -init -mock-kms -gateway-host asdfasdfaasdf /tkfs/cipher
./tkfs -fg -health-check-port 8000 /tkfs/cipher /tkfs/data/
