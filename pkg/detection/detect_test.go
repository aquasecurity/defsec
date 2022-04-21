package detection

import (
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Detection(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		r        io.Reader
		expected []FileType
	}{
		{
			name:     "text file, no reader",
			path:     "something.txt",
			r:        nil,
			expected: nil,
		},
		{
			name:     "text file, with reader",
			path:     "something.txt",
			r:        strings.NewReader("some file content"),
			expected: nil,
		},
		{
			name: "terraform, no reader",
			path: "main.tf",
			r:    nil,
			expected: []FileType{
				FileTypeTerraform,
			},
		},
		{
			name: "terraform, with reader",
			path: "main.tf",
			r:    strings.NewReader("some file content"),
			expected: []FileType{
				FileTypeTerraform,
			},
		},
		{
			name: "cloudformation, no reader",
			path: "main.yaml",
			r:    nil,
			expected: []FileType{
				FileTypeYAML,
			},
		},
		{
			name: "cloudformation, with reader",
			path: "main.yaml",
			r: strings.NewReader(`---
AWSTemplateFormatVersion: 2010-09-09

Description: CodePipeline for continuous integration and continuous deployment

Parameters:
  RepositoryName:
    Type: String
    Description: Name of the CodeCommit repository
  BuildDockerImage:
    Type: String
    Default: aws/codebuild/ubuntu-base:14.04
    Description: Docker image to use for the build phase
  DeployDockerImage:
    Type: String
    Default: aws/codebuild/ubuntu-base:14.04
    Description: Docker image to use for the deployment phase

Resources:
  PipelineS3Bucket:
    Type: AWS::S3::Bucket
`),
			expected: []FileType{
				FileTypeCloudFormation,
				FileTypeYAML,
			},
		},
		{
			name: "Dockerfile, no reader",
			path: "Dockerfile",
			r:    nil,
			expected: []FileType{
				FileTypeDockerfile,
			},
		},
		{
			name: "Dockerfile, reader",
			path: "Dockerfile",
			r:    strings.NewReader("FROM ubuntu\n"),
			expected: []FileType{
				FileTypeDockerfile,
			},
		},
		{
			name: "Dockerfile extension",
			path: "lol.Dockerfile",
			r:    nil,
			expected: []FileType{
				FileTypeDockerfile,
			},
		},
		{
			name: "Kubernetes, no reader",
			path: "k8s.yml",
			r:    nil,
			expected: []FileType{
				FileTypeYAML,
			},
		},
		{
			name: "Kubernetes, reader",
			path: "k8s.yml",
			r: strings.NewReader(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
  labels:
    app: nginx
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx:1.14.2
        ports:
        - containerPort: 80`),
			expected: []FileType{
				FileTypeKubernetes,
				FileTypeYAML,
			},
		},
		{
			name: "YAML, no reader",
			path: "file.yaml",
			r:    nil,
			expected: []FileType{
				FileTypeYAML,
			},
		},
		{
			name: "YML, no reader",
			path: "file.yml",
			r:    nil,
			expected: []FileType{
				FileTypeYAML,
			},
		},
		{
			name: "YML uppercase",
			path: "file.YML",
			r:    nil,
			expected: []FileType{
				FileTypeYAML,
			},
		},
		{
			name: "TOML, no reader",
			path: "file.toml",
			r:    nil,
			expected: []FileType{
				FileTypeTOML,
			},
		},
		{
			name: "JSON, no reader",
			path: "file.json",
			r:    nil,
			expected: []FileType{
				FileTypeJSON,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Run("GetTypes", func(t *testing.T) {
				actualDetections := GetTypes(test.path, test.r)
				assert.Equal(t, len(test.expected), len(actualDetections))
				for _, expected := range test.expected {
					var found bool
					for _, actual := range actualDetections {
						if actual == expected {
							found = true
							break
						}
					}
					assert.True(t, found, "%s should be detected", expected)
				}
			})
			for _, expected := range test.expected {
				t.Run(fmt.Sprintf("IsType_%s", expected), func(t *testing.T) {
					assert.True(t, IsType(test.path, test.r, expected))
				})
			}
			t.Run("IsType_invalid", func(t *testing.T) {
				assert.False(t, IsType(test.path, test.r, "invalid"))
			})
		})
	}
}
