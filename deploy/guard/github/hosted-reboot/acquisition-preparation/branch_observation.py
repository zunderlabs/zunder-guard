"""Closed inert branch metadata; it never grants source or runtime authority."""
import json
import re
import sys

REF='refs/heads/codex/no-key-linux-acquisition-preparation'
KIND='fixed-branch-linux-preparation-observation'
FLAGS=('privateInput','sourceAdmitted','runtimeAdmitted','trustAdmitted','nativeAccepted','releaseReady')


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)


def make_observation(source,run_id,attempt):
    if not isinstance(source,str) or not re.fullmatch('[a-f0-9]{40}',source):raise ValueError()
    if type(run_id)is not int or not 1<=run_id<=9007199254740991:raise ValueError()
    if type(attempt)is not int or not 1<=attempt<=1000:raise ValueError()
    value={'schema':1,'kind':KIND,'ref':REF,'controlSource':source,'runId':run_id,'attempt':attempt,
           'artifactName':'linux-acquisition-branch-inert-'+str(run_id)+'-'+str(attempt),
           **{name:False for name in FLAGS}}
    if len(canonical(value).encode())>1024:raise ValueError()
    return value


def pairs(rows):
    value={}
    for key,member in rows:
        if key in value:raise ValueError()
        value[key]=member
    return value


def validate_observation(raw):
    if not isinstance(raw,str) or not raw.isascii() or not 0<len(raw.encode())<=1024:raise ValueError()
    value=json.loads(raw,object_pairs_hook=pairs)
    if not isinstance(value,dict):raise ValueError()
    expected=make_observation(value.get('controlSource'),value.get('runId'),value.get('attempt'))
    if set(value)!=set(expected) or canonical(value)!=raw or value!=expected:raise ValueError()
    if type(value['schema'])is not int or any(value[name]is not False for name in FLAGS):raise ValueError()
    return value


def main():
    try:
        if len(sys.argv)!=4 or not all(re.fullmatch('[1-9][0-9]{0,15}',v)for v in sys.argv[2:]):raise ValueError()
        value=make_observation(sys.argv[1],int(sys.argv[2]),int(sys.argv[3]))
        validate_observation(canonical(value));print(canonical(value));return 0
    except (ValueError,TypeError):
        print(canonical({'schema':1,'kind':'fixed-branch-observation-context-refused',
                         'reason':'invalid-metadata',**{name:False for name in FLAGS}}));return 1


if __name__=='__main__':raise SystemExit(main())
