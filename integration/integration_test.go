package integration_test

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/external"
	"github.com/aquasecurity/fanal/types"
)

func TestDockerfile(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		filePatterns []string
		want         []types.Misconfiguration
	}{
		{
			name:  "DS001: latest tag",
			input: "testdata/DS001",
			want: []types.Misconfiguration{
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.allowed",
				},
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.denied",
					Failures: types.MisconfResults{
						{
							Namespace: "appshield.dockerfile.DS001",
							Message:   "Specify a tag in the 'FROM' statement for image 'debian'",
						},
					},
				},
			},
		},
		{
			name:  "DS002: root user",
			input: "testdata/DS002",
			want: []types.Misconfiguration{
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.allowed",
				},
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.denied",
					Failures: types.MisconfResults{
						{
							Namespace: "appshield.dockerfile.DS002",
							Message:   "Specify at least 1 USER command in Dockerfile with non-root user as argument",
						},
					},
				},
			},
		},
		{
			name:  "DS004: Exposing Port 22",
			input: "testdata/DS004",
			want: []types.Misconfiguration{
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.allowed",
				},
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.denied",
					Failures: types.MisconfResults{
						{
							Namespace: "appshield.dockerfile.DS004",
							Message:   "Port 22 should not be exposed in Dockerfile",
						},
					},
				},
			},
		},
		{
			name:  "DS005: COPY Instead of ADD",
			input: "testdata/DS005",
			want: []types.Misconfiguration{
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.allowed",
				},
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.denied",
					Failures: types.MisconfResults{
						{
							Namespace: "appshield.dockerfile.DS005",
							Message:   `Consider using 'COPY "/target/app.jar" "app.jar"' command instead of 'ADD "/target/app.jar" "app.jar"'`,
						},
					},
				},
			},
		},
		{
			name:  "DS006: COPY '--from' references current image FROM alias",
			input: "testdata/DS006",
			want: []types.Misconfiguration{
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.allowed",
				},
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.denied",
					Failures: types.MisconfResults{
						{
							Namespace: "appshield.dockerfile.DS006",
							Message:   `'COPY --from' should not mention current alias 'dep' since it is impossible to copy from itself`,
						},
					},
				},
			},
		},
		{
			name:  "DS007: Multiple ENTRYPOINT Instructions Listed",
			input: "testdata/DS007",
			want: []types.Misconfiguration{
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.allowed",
				},
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.denied",
					Failures: types.MisconfResults{
						{
							Namespace: "appshield.dockerfile.DS007",
							Message:   "There are 2 duplicate ENTRYPOINT instructions for stage 'golang:1.7.3 as dep'",
						},
					},
				},
			},
		},
		{
			name:  "DS008: UNIX Ports Out Of Range",
			input: "testdata/DS008",
			want: []types.Misconfiguration{
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.allowed",
				},
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.denied",
					Failures: types.MisconfResults{
						{
							Namespace: "appshield.dockerfile.DS008",
							Message:   `'EXPOSE' contains port which is out of range [0, 65535]: 65536`,
						},
					},
				},
			},
		},
		{
			name:  "DS009: WORKDIR Path Not Absolute",
			input: "testdata/DS009",
			want: []types.Misconfiguration{
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.allowed",
				},
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.denied",
					Failures: types.MisconfResults{
						{
							Namespace: "appshield.dockerfile.DS009",
							Message:   "WORKDIR path 'path/to/workdir' should be absolute",
						},
					},
				},
			},
		},
		{
			name:  "DS010: Run Using Sudo",
			input: "testdata/DS010",
			want: []types.Misconfiguration{
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.allowed",
				},
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.denied",
					Failures: types.MisconfResults{
						{
							Namespace: "appshield.dockerfile.DS010",
							Message:   `Using 'sudo' in Dockerfile should be avoided`,
						},
					},
				},
			},
		},
		{
			name:  "DS011: Copy With More Than Two Arguments Not Ending With Slash",
			input: "testdata/DS011",
			want: []types.Misconfiguration{
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.allowed",
				},
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.denied",
					Failures: types.MisconfResults{
						{
							Namespace: "appshield.dockerfile.DS011",
							Message:   `Slash is expected at the end of COPY command argument 'myapp'`,
						},
					},
				},
			},
		},
		{
			name:  "DS012: Same Alias In Different Froms",
			input: "testdata/DS012",
			want: []types.Misconfiguration{
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.allowed",
				},
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.denied",
					Failures: types.MisconfResults{
						{
							Namespace: "appshield.dockerfile.DS012",
							Message:   `Duplicate aliases 'build' are found in different FROMs`,
						},
					},
				},
			},
		},
		{
			name:  "DS013: RUN Instruction Using 'cd' Instead of WORKDIR",
			input: "testdata/DS013",
			want: []types.Misconfiguration{
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.allowed",
				},
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.denied",
					Failures: types.MisconfResults{
						{
							Namespace: "appshield.dockerfile.DS013",
							Message:   `RUN should not be used to change directory: 'cd /usr/share/nginx/html'. Use 'WORKDIR' statement instead.`,
						},
					},
				},
			},
		},
		{
			name:  "DS014: Run Using 'wget' and 'curl'",
			input: "testdata/DS014",
			want: []types.Misconfiguration{
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.allowed",
				},
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.denied",
					Failures: types.MisconfResults{
						{
							Namespace: "appshield.dockerfile.DS014",
							Message:   `Shouldn't use both curl and wget`,
						},
					},
				},
			},
		},
		{
			name:  "DS015: Yum Clean All Missing",
			input: "testdata/DS015",
			want: []types.Misconfiguration{
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.allowed",
				},
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.denied",
					Failures: types.MisconfResults{
						{
							Namespace: "appshield.dockerfile.DS015",
							Message:   `'yum clean all' is missed: yum install vim`,
						},
					},
				},
			},
		},
		{
			name:  "DS016: Multiple CMD Instructions Listed",
			input: "testdata/DS016",
			want: []types.Misconfiguration{
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.allowed",
				},
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.denied",
					Failures: types.MisconfResults{
						{
							Namespace: "appshield.dockerfile.DS016",
							Message:   `There are 2 duplicate CMD instructions for stage 'golang:1.7.3'`,
						},
					},
				},
			},
		},
		{
			name:  "DS017: Update Instruction Alone",
			input: "testdata/DS017",
			want: []types.Misconfiguration{
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.allowed",
				},
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.denied",
					Failures: types.MisconfResults{
						{
							Namespace: "appshield.dockerfile.DS017",
							Message:   `The instruction 'RUN <package-manager> update' should always be followed by '<package-manager> install' in the same RUN statement.`,
						},
					},
				},
			},
		},
		{
			name:  "DS018: COPY '--from' Without FROM Alias Defined Previously",
			input: "testdata/DS018",
			want: []types.Misconfiguration{
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.allowed",
				},
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.denied",
					Failures: types.MisconfResults{
						{
							Namespace: "appshield.dockerfile.DS018",
							Message:   `The alias '--from=dep' is not defined in the previous stages`,
						},
					},
				},
			},
		},
		{
			name:  "DS019: Missing Dnf Clean All",
			input: "testdata/DS019",
			want: []types.Misconfiguration{
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.allowed",
				},
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.denied",
					Failures: types.MisconfResults{
						{
							Namespace: "appshield.dockerfile.DS019",
							Message:   `'dnf clean all' is missed: set -uex &&     dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo &&     sed -i 's/\\$releasever/26/g' /etc/yum.repos.d/docker-ce.repo &&     dnf install -vy docker-ce`,
						},
					},
				},
			},
		},
		{
			name:  "DS020: Missing Zypper Clean",
			input: "testdata/DS020",
			want: []types.Misconfiguration{
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.allowed",
				},
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.denied",
					Failures: types.MisconfResults{
						{
							Namespace: "appshield.dockerfile.DS020",
							Message:   `'zypper clean' is missed: 'zypper install bash'`,
						},
					},
				},
			},
		},
		{
			name:  "DS021: APT-GET Missing '-y' To Avoid Manual Input",
			input: "testdata/DS021",
			want: []types.Misconfiguration{
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.allowed",
				},
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.denied",
					Failures: types.MisconfResults{
						{
							Namespace: "appshield.dockerfile.DS021",
							Message:   `'-y' flag is missed: 'apt-get install apt-utils && apt-get clean'`,
						},
					},
				},
			},
		},
		{
			name:  "DS022: MAINTAINER is deprecated",
			input: "testdata/DS022",
			want: []types.Misconfiguration{
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.allowed",
				},
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.denied",
					Failures: types.MisconfResults{
						{
							Namespace: "appshield.dockerfile.DS022",
							Message:   "MAINTAINER should not be used: 'MAINTAINER Lukas Martinelli <me@lukasmartinelli.ch>'",
						},
					},
				},
			},
		},
		{
			name:  "DS023: Multiple HEALTHCHECK instructions",
			input: "testdata/DS023",
			want: []types.Misconfiguration{
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.allowed",
				},
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.denied",
					Failures: types.MisconfResults{
						{
							Namespace: "appshield.dockerfile.DS023",
							Message:   "There are 2 duplicate HEALTHCHECK instructions in the stage 'busybox:1.33.1'",
						},
					},
				},
			},
		},
		{
			name:  "DS024: Do not use apt-get dist-upgrade",
			input: "testdata/DS024",
			want: []types.Misconfiguration{
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.allowed",
				},
				{
					FileType: types.Dockerfile,
					FilePath: "Dockerfile.denied",
					Failures: types.MisconfResults{
						{
							Namespace: "appshield.dockerfile.DS024",
							Message:   "'apt-get dist-upgrade' should not be used in Dockerfile",
						},
					},
				},
			},
		},
	}

	policyPaths := []string{"../docker"}
	namespaces := []string{"appshield"}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := external.NewConfigScanner(t.TempDir(), policyPaths, nil, namespaces)
			require.NoError(t, err)

			got, err := s.Scan(tt.input)
			require.NoError(t, err)

			// Do not assert successes and policy metadata
			for i := range got {
				got[i].Successes = nil
				for j := range got[i].Failures {
					got[i].Failures[j].PolicyMetadata = types.PolicyMetadata{}
				}
			}

			// For consistency
			sort.Slice(got, func(i, j int) bool {
				return got[i].FilePath < got[j].FilePath
			})

			// Assert the scan result
			assert.Equal(t, tt.want, got)
		})
	}
}
