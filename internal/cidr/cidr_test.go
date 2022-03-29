package cidr

import (
	"fmt"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPublicDetection(t *testing.T) {

	var tests = []struct {
		input  string
		public bool
	}{
		{
			input:  "1.2.3.4",
			public: true,
		},
		{
			input:  "127.0.0.1",
			public: false,
		},
		{
			input:  "192.168.0.0",
			public: false,
		},
		{
			input:  "192.168.0.1/16",
			public: false,
		},
		{
			input:  "192.168.0.1/24",
			public: false,
		},
		{
			input:  "192.168.0.1/8",
			public: true,
		},
		{
			input:  "10.0.0.0",
			public: false,
		},
		{
			input:  "10.0.0.0/8",
			public: false,
		},
		{
			input:  "10.0.0.0/7",
			public: true,
		},
		{
			input:  "169.254.0.0/16",
			public: false,
		},
		{
			input:  "172.16.0.0/12",
			public: false,
		},
		{
			input:  "172.16.0.0/2",
			public: true,
		},
		{
			input:  "0.0.0.0/0",
			public: true,
		},
		{
			input:  "127.0.0.1/0",
			public: true,
		},
		{
			input:  "0000:0000:0000:0000:0000:0000:0000:0001",
			public: false,
		},
		{
			input:  "::1/128",
			public: false,
		},
		{
			input:  "fe80::/10",
			public: false,
		},
		{
			input:  "fc00::/7",
			public: false,
		},
		{
			input:  "fd00:1234:1234:1234:1234:1234:1234:1234",
			public: false,
		},
		{
			input:  "6666:6666:6666:6666:6666:6666:6666:6666",
			public: true,
		},
		{
			input:  "nonsense",
			public: false,
		},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			assert.Equal(t, test.public, IsPublic(test.input))
		})
	}

}

func TestCountCIDRAddresses(t *testing.T) {
	tests := []struct {
		cidr     string
		expected uint64
	}{
		{
			cidr:     "127.0.0.1",
			expected: 1,
		},
		{
			cidr:     "192.168.0.1/16",
			expected: 0x10000,
		},
		{
			cidr:     "1.2.3.4/0",
			expected: 0x100000000,
		},
		{
			cidr:     "::0/0",
			expected: math.MaxUint64,
		},
	}
	for _, test := range tests {
		t.Run(
			fmt.Sprintf("%s => %d", test.cidr, test.expected),
			func(t *testing.T) {
				actual := CountAddresses(test.cidr)
				assert.Equal(t, test.expected, actual)
			},
		)
	}
}
