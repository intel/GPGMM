#!/usr/bin/env python3
#
# Copyright 2021 The GPGMM Authors
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

import glob
import subprocess
import sys
import os
import re
import json
from argparse import ArgumentParser

parser = ArgumentParser(description='Run and analyze d3d resource alignment rejects. ' +
'To use, build with `gpgmm_enable_d3d12_resource_alignment_warning = true` then run this script.')

# Common options
parser.add_argument("testname", type=str, nargs='?', default="dawn_end2end_tests")
parser.add_argument('--build-dir', type=str, default="out/Debug")

# dawn_end2end_tests specific options
parser.add_argument('--dawn-backend', type=str, default="d3d12")
parser.add_argument('--dawn-adapter-vendor-id', type=str, default="0x1414")
parser.add_argument('--dawn-test-filter', type=str, default="*")

args = vars(parser.parse_args())

def run_dawn_end2end_tests(binary_path, dawn_backend, dawn_vendor_id, dawn_test_filter):
  """ Run dawn_end2end_tests and report rejects."""
  extra_args = ["--backend=" + dawn_backend, '--adapter-vendor-id=' + dawn_vendor_id, '--gtest_filter=' + dawn_test_filter]
  process = subprocess.Popen([binary_path] + extra_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
  output, err = process.communicate()
  data = output.decode("utf-8")

  dict_resource_rej_count = {}
  dict_test_rej_count = {}

  curr_test_name = ""
  for line in data.split("\r\n"):
    test_name_regex = re.search(r'RUN.*\] (.*)\/', line)
    if test_name_regex:
      curr_test_name = test_name_regex.group(1)

    rej_resource_desc = ""
    rej_resource_desc_regex = re.search(r'.*Resource alignment.*resource : ({.*})', line)
    if rej_resource_desc_regex:
      rej_resource_desc = rej_resource_desc_regex.group(1)
    else:
      continue # skip

    if rej_resource_desc not in dict_resource_rej_count:
        dict_resource_rej_count[rej_resource_desc] = 0
    dict_resource_rej_count[rej_resource_desc] += 1

    if curr_test_name not in dict_test_rej_count:
        dict_test_rej_count[curr_test_name] = 0
    dict_test_rej_count[curr_test_name] += 1

  if not len(dict_resource_rej_count):
    print("No rejects detected.")
    sys.exit(0)

  # Occurrence by resource request
  print("Unique resources rejected: " + str(len(dict_resource_rej_count)) + "\n")

  print("Total occurrences per test (test name, occurrences):")
  for test_name, count in sorted(dict_test_rej_count.items(), key=lambda x:x[1], reverse=True):
    print(test_name + ", " + str(count))
  print("")

  # Occurrences by format
  dict_format_count = {}
  for resource_desc, count in dict_resource_rej_count.items():
    resource_desc_json = json.loads(resource_desc)
    resource_format = resource_desc_json['Format']
    if resource_format not in dict_format_count:
        dict_format_count[resource_format] = 0
    dict_format_count[resource_format] += 1

  print("Total occurrences per format (format id, occurrences):")
  for format_id, count in sorted(dict_format_count.items(), key=lambda x:x[1], reverse=True):
    print(str(format_id) + ", " + str(count))
  print("")

  # Occurrences by resource label (ie. <type>_WxHxD)
  dict_resource_count = {}
  for resource_desc, count in dict_resource_rej_count.items():
    resource_json = json.loads(resource_desc)
    resource_label = str(resource_json['Width']) + "x" + str(resource_json['Height']) + "x" + str(resource_json['DepthOrArraySize'])

    if (dawn_backend == "d3d12"):
        resource_label = get_d3d_resource_type(resource_json['Dimension']) + "_" + resource_label

    if resource_label not in dict_resource_count:
        dict_resource_count[resource_label] = 0
    dict_resource_count[resource_label] += 1

  print("Total occurrences per resource (resource, occurrences):")
  for resource_label, count in sorted(dict_resource_count.items(), key=lambda x:x[1], reverse=True):
    print(str(resource_label) + ", " + str(count))
  print("")

def get_d3d_resource_type(dimension_id):
  """ Returns the name of the d3d resource type."""
  if dimension_id == 0: return "Unknown"
  elif dimension_id == 1: return "Buffer"
  else: return "Texture"

def get_binary_path(testname, build_dir):
  """ Returns full path to test executable."""
  base_path = os.path.abspath(
      os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))

  binary_name = testname
  if sys.platform == 'win32':
      binary_name += '.exe'

  build_path = os.path.normpath(build_dir)
  binary_path = os.path.join(base_path, build_path, binary_name)
  return binary_path

if (args['testname'] == "dawn_end2end_tests"):
  run_dawn_end2end_tests(
    binary_path=get_binary_path(args['testname'], args['build_dir']),
    dawn_backend=args['dawn_backend'],
    dawn_vendor_id=args['dawn_adapter_vendor_id'],
    dawn_test_filter=args['dawn_test_filter'])
else:
  print("Unsupported test:" + args['testname'])
  sys.exit(1)
