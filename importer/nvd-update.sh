#!/bin/bash


while [ : ]
do
    sleep 5m
    echo "updating nvd in $MONGO_URI"
    curl -s https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz | \
        gunzip | \
        jq -M '.CVE_Items' | \
        mongoimport --uri=$MONGO_URI -c nvdmirror --jsonArray --upsertFields="cve.CVE_data_meta.ID"
done
