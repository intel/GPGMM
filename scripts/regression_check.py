# Copyright 2021 The WebNN Authors
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

import json
import pathlib
import sys
from xml.dom import minidom

def parseJson(filename, onlyFailure = False):
  failuresDict = {}
  with open(filename) as rf:
    c = json.load(rf)
    if onlyFailure:
      if c['failures'] == 0:
        return failuresDict
      else:
        testsuitesList = c['testsuites']
        for testsuite in testsuitesList:
          if testsuite['failures'] == 0:
            continue
          else:
            suiteName = testsuite['name']
            testcaseList = testsuite['testsuite']
            for testcase in testcaseList:
              if testcase.get('failures'):
                if failuresDict.get(suiteName):
                  failuresDict[suiteName].append(
                    (testcase['name'], testcase['failures']))
                else:
                  failuresDict[suiteName] = [
                    (testcase['name'], testcase['failures'])]
      return failuresDict
    else:
      return c

def parseXml(filename,  onlyFailure = False):
  resultDict = {}
  doc = minidom.parse(filename)
  tcList = doc.getElementsByTagName('testcase')
  for tc in tcList:
    className = tc.getAttribute('classname')
    name = tc.getAttribute('name')
    if resultDict.get(className) == None:
      resultDict[className] = []
    if tc.firstChild:
      if tc.firstChild.nodeName == 'skipped':
        if onlyFailure:
          continue
        else:
          resultDict[className].append((name, 'SKIPPED', ''))
      elif tc.firstChild.nodeName == 'failure':
        resultDict[className].append(
          (name, 'FAILED', tc.firstChild.firstChild.data))
    else:
        if onlyFailure:
          continue
        else:
          resultDict[className].append((name, 'PASSED', ''))
  return resultDict

def getRegressionResultsListXml(baseline, target):
  regressionResultsList = []
  failureResultsDict = parseXml(target, True)

  if len(failureResultsDict) == 0:
    return regressionResultsList
  else:
    baseResultsDict = parseXml(baseline)
    baseClassnameList = baseResultsDict.keys()
    for className, failureResultsList in failureResultsDict.items():
      if className not in baseClassnameList:
        # Skip failure test case of new added class name
        continue
      else:
        tcListByClassName = baseResultsDict[className]
        baseTestcaseNameList = [
          resultTuple[0] for resultTuple in tcListByClassName ]
        for testcaseTuple in failureResultsList:
          testcaseName = testcaseTuple[0]
          if testcaseName not in baseTestcaseNameList:
            # Skip new added failure testcase
            continue
          else:
            baseTestcaseResultTuple = \
              tcListByClassName[baseTestcaseNameList.index(testcaseName)]
            if baseTestcaseResultTuple[1] in ['PASSED', 'SKIPPED']:
              # Catch it, this one is a regression test.
              errorMsg = testcaseTuple[2]
              regressionResultsList.append((className, testcaseName, errorMsg))

  return regressionResultsList

def getRegressionResultsListJson(baseline, target):
  regressionResultsList = []
  failureResultsDict = parseJson(target, True)

  if len(failureResultsDict) == 0:
    return regressionResultsList
  else:
    baseResultsDict = parseJson(baseline)
    baseSuiteList = baseResultsDict['testsuites']
    baseSuiteNameList = [
      testsuiteDict['name'] for testsuiteDict in baseSuiteList ]
    for suiteName, failureResultsList in failureResultsDict.items():
      if suiteName not in baseSuiteNameList:
        # Skip failure test case of new added testsuite
        continue
      else:
        suiteDict = baseSuiteList[baseSuiteNameList.index(suiteName)]
        baseTestcaseNameList = [
          testcaseDict['name'] for testcaseDict in suiteDict['testsuite'] ]
        for testcaseTuple in failureResultsList:
          testcaseName = testcaseTuple[0]
          if testcaseName not in baseTestcaseNameList:
            # Skip new added failure testcase
            continue
          else:
            baseTestcaseDict = \
              suiteDict['testsuite'][baseTestcaseNameList.index(testcaseName)]
            if baseTestcaseDict.get('failures') is None:
              # Catch it, this one is a regression test.
              errorMsg = '\n'.join([
                failureDict['failure'] for failureDict in testcaseTuple[1] ])
              regressionResultsList.append((suiteName, testcaseName, errorMsg))

  return regressionResultsList

def getRegressionResultsList(baseline, target, suffix):
    if suffix == '.json':
      return getRegressionResultsListJson(baseline, target)
    elif suffix == '.xml':
      return getRegressionResultsListXml(baseline, target)
    else:
      print("Unsupported to check '%s' file" % suffix)
      sys.exit(1)

if __name__ == '__main__':
  baselineFile = sys.argv[1]
  targetFile = sys.argv[2]
  fileSuffix = pathlib.Path(baselineFile).suffix

  resultsList = getRegressionResultsList(baselineFile, targetFile, fileSuffix)

  if resultsList:
    print('Regression check: FAIL, %d regression tests:' % len(resultsList))
    char = '.' if fileSuffix == '.json' else '/'
    for result in resultsList:
        print('[  FAILED  ] %s%s%s\n%s' % \
              (result[0], char, result[1], result[2]))
    sys.exit(1)
  else:
    print('Regression check: PASS')
    sys.exit(0)
