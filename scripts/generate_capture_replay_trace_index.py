#!/usr/bin/env python3
# Copyright 2022 The GPGMM Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import sys
import os
import argparse
import json

parser = argparse.ArgumentParser(
    description="Generate capture replay trace index.",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
)

parser.add_argument('--traces_dir', type=str,
                    help='Directory containing captured trace files.')

parser.add_argument('--trace_index', type=str,
                    help='Path to generated trace index file.')

args = parser.parse_args()


def main():
    traceFileIndexData = {'traceFiles': []}
    for traceFilename in os.listdir(args.traces_dir):

        traceName = traceFilename.split('.')[0]  # strip extension part

        traceFilePath = os.path.abspath(
            os.path.join(args.traces_dir, traceFilename))
        traceFile = {'name': traceName, 'path': traceFilePath}
        traceFileIndexData['traceFiles'].append(traceFile)

    with open(args.trace_index, 'w') as outFile:
        json.dump(traceFileIndexData, outFile)


if __name__ == '__main__':
    sys.exit(main())
