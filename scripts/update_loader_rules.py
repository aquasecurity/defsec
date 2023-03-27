#!/usr/bin/python3

import glob

lines = []


def addLine(line):
    lines.append(f'{line}\n')


addLine('package rules')
addLine('')
addLine('import (')


for f in glob.glob(f'./policies/*/*'):
    f = f.replace('./rules/', '_ "github.com/aquasecurity/defsec/rules/') + '"'
    addLine(f)

addLine(')')


with open('./pkg/rules/rules.go', 'w') as fw:
    fw.writelines(lines)

