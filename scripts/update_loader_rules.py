#!/usr/bin/python3

import glob

lines = []


def addLine(line):
    lines.append(f'{line}\n')


addLine('package loader')
addLine('')
addLine('import (')


for f in glob.glob(f'./rules/*/*'):
    f = f.replace('./rules/', '_ "github.com/aquasecurity/defsec/rules/') + '"'
    addLine(f)

addLine(')')


with open('./loader/rules.go', 'w') as fw:
    fw.writelines(lines)

