#!/bin/bash


curl -s https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2002.json.gz | gunzip | jq -M '.CVE_Items' |  mongoimport -d vulns -c nvd --jsonArray --upsertFields="cve.CVE_data_meta.ID"
curl -s https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2003.json.gz | gunzip | jq -M '.CVE_Items' |  mongoimport -d vulns -c nvd --jsonArray --upsertFields="cve.CVE_data_meta.ID"
curl -s https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2004.json.gz | gunzip | jq -M '.CVE_Items' |  mongoimport -d vulns -c nvd --jsonArray --upsertFields="cve.CVE_data_meta.ID"
curl -s https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2005.json.gz | gunzip | jq -M '.CVE_Items' |  mongoimport -d vulns -c nvd --jsonArray --upsertFields="cve.CVE_data_meta.ID"
curl -s https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2006.json.gz | gunzip | jq -M '.CVE_Items' |  mongoimport -d vulns -c nvd --jsonArray --upsertFields="cve.CVE_data_meta.ID"
curl -s https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2007.json.gz | gunzip | jq -M '.CVE_Items' |  mongoimport -d vulns -c nvd --jsonArray --upsertFields="cve.CVE_data_meta.ID"
curl -s https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2008.json.gz | gunzip | jq -M '.CVE_Items' |  mongoimport -d vulns -c nvd --jsonArray --upsertFields="cve.CVE_data_meta.ID"
curl -s https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2009.json.gz | gunzip | jq -M '.CVE_Items' |  mongoimport -d vulns -c nvd --jsonArray --upsertFields="cve.CVE_data_meta.ID"
curl -s https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2010.json.gz | gunzip | jq -M '.CVE_Items' |  mongoimport -d vulns -c nvd --jsonArray --upsertFields="cve.CVE_data_meta.ID"
curl -s https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2011.json.gz | gunzip | jq -M '.CVE_Items' |  mongoimport -d vulns -c nvd --jsonArray --upsertFields="cve.CVE_data_meta.ID"
curl -s https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2012.json.gz | gunzip | jq -M '.CVE_Items' |  mongoimport -d vulns -c nvd --jsonArray --upsertFields="cve.CVE_data_meta.ID"
curl -s https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2013.json.gz | gunzip | jq -M '.CVE_Items' |  mongoimport -d vulns -c nvd --jsonArray --upsertFields="cve.CVE_data_meta.ID"
curl -s https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2014.json.gz | gunzip | jq -M '.CVE_Items' |  mongoimport -d vulns -c nvd --jsonArray --upsertFields="cve.CVE_data_meta.ID"
curl -s https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2015.json.gz | gunzip | jq -M '.CVE_Items' |  mongoimport -d vulns -c nvd --jsonArray --upsertFields="cve.CVE_data_meta.ID"
curl -s https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2016.json.gz | gunzip | jq -M '.CVE_Items' |  mongoimport -d vulns -c nvd --jsonArray --upsertFields="cve.CVE_data_meta.ID"
curl -s https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2017.json.gz | gunzip | jq -M '.CVE_Items' |  mongoimport -d vulns -c nvd --jsonArray --upsertFields="cve.CVE_data_meta.ID"
curl -s https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2018.json.gz | gunzip | jq -M '.CVE_Items' |  mongoimport -d vulns -c nvd --jsonArray --upsertFields="cve.CVE_data_meta.ID"
curl -s https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2019.json.gz | gunzip | jq -M '.CVE_Items' |  mongoimport -d vulns -c nvd --jsonArray --upsertFields="cve.CVE_data_meta.ID"
