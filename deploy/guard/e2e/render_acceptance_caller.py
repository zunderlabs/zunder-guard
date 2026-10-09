#!/usr/bin/env python3
"""Render main-only caller AFTER reviewed immutable reusable source commit exists."""
import argparse
from pathlib import Path
import re
from release_flow import need
from acceptance_admission import REPOSITORY,WORKFLOW,NEGATIVE_WORKFLOW


def render(source):
    need(type(source)is str and re.fullmatch('[0-9a-f]{40}',source),'Actual immutable reusable controller SHA required')
    return '''name: release acceptance admission
on:
  workflow_dispatch:
permissions: {}
concurrency:
  group: release-owner-admission
  cancel-in-progress: false
jobs:
  verify:
    if: github.ref == 'refs/heads/main'
    permissions:
      contents: read
      actions: read
      id-token: write
    uses: '''+REPOSITORY+'/'+WORKFLOW+'@'+source+'''
  negative:
    needs: verify
    if: github.ref == 'refs/heads/main'
    permissions:
      contents: read
      actions: read
      id-token: write
    uses: '''+REPOSITORY+'/'+NEGATIVE_WORKFLOW+'@'+source+'\n'


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--control-source',required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();need(args.output.is_absolute() and args.output.parent.is_dir() and not args.output.exists(),'Fresh absolute caller workflow output required')
    with args.output.open('x')as stream:stream.write(render(args.control_source))
