import pymongo
import pprint
import re
from distutils.version import LooseVersion

client = pymongo.MongoClient("localhost", 27017)
db = client.vulns
col = db.nvd


#testdata = {"vulnerable" : True, "cpe23Uri" : "cpe:2.3:a:fasterxml:jackson-databind:*:*:*:*:*:*:*:*", "versionEndExcluding" : "2.6.7.2" }

def build_query(grp, art):
    return {"configurations.nodes.cpe_match.cpe23Uri": {
        "$regex": "cpe:2\\.3:\\w:%s:%s:.+" % (grp, art)
    }}

def extract_data(cpe):
    rx = r'cpe:2\.3:\S:(?P<group>[^:]+):(?P<artefact>[^:]+):(?P<version>[^:]+):(?P<patch>[^:]+):.*'
    m = re.match(rx, cpe)
    if m == None:
        return {}
    else:
        return m.groupdict()

def compare_range(cpe_ver, ver):
    v   = LooseVersion(ver)
    vsi = LooseVersion(cpe_ver.get('versionStartIncluding', '0.0.0.0'))
    vse = LooseVersion(cpe_ver.get('versionStartExcluding', '0.0.0.0'))
    vei = LooseVersion(cpe_ver.get('versionEndIncluding', '99999.99999.99999.99999'))
    vee = LooseVersion(cpe_ver.get('versionEndExcluding', '99999.99999.99999.99999'))
    res = v < vee and v <= vei and v > vse and v >= vsi
    return res

def match_version(cpe_match, group, artefact, ver):
    cpe_data = extract_data(cpe_match['cpe23Uri'])

    if cpe_data['group'] != group or cpe_data['artefact'] !=  artefact:
        return False

    if cpe_data["version"] == "*":
        if compare_range(cpe_match, ver):
            return True
        pass
    else:
        # do exact match
        va = LooseVersion(cpe_data['version'] )
        vb = LooseVersion(ver)
        if va == vb:
            return True
        pass
    # default to false
    return False 

def run(group, artefact, version):
    for result in col.find(build_query(group, artefact)):
        config = result['configurations']
        for node in config['nodes']:
            for cpe in node['cpe_match']:
                if match_version(cpe, group, artefact, version):
                    pprint.pprint(cpe)
                    print("vuln found!!")
                    print(result['cve']['CVE_data_meta']['ID'])
                    return result['cve']
    return {'msg': "No vulns found"}