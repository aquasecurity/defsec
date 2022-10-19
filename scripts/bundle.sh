#!/bin/bash

rm -rf bundle || true
rm bundle.tar.gz || true
RELEASE_VERSION=${GITHUB_REF/refs\/tags\/v/}
MINOR_VERSION=$(echo ${RELEASE_VERSION} | cut -d. -f1,2)
MAJOR_VERSION=$(echo ${RELEASE_VERSION} | cut -d. -f1)
if [ -n "$GITHUB_ENV" ]; then
  echo "RELEASE_VERSION=$RELEASE_VERSION" >> $GITHUB_ENV
  echo "MINOR_VERSION=$MINOR_VERSION" >> $GITHUB_ENV
  echo "MAJOR_VERSION=$MAJOR_VERSION" >> $GITHUB_ENV
fi
mkdir -p bundle/policies
rsync -avr --exclude=README.md --exclude="*_test.rego" --exclude="*.go" --exclude=test --exclude=advanced internal/rules/policies/ bundle/policies/
cp internal/rules/policies/.manifest bundle/
rm bundle/policies/.manifest
sed -i -e "s/\[GITHUB_SHA\]/${RELEASE_VERSION}/" bundle/.manifest
tar -C bundle -czvf bundle.tar.gz .
rm -rf bundle
