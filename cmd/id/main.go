package main

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/aquasecurity/defsec/pkg/framework"

	_ "github.com/aquasecurity/defsec/pkg/rego"
	"github.com/aquasecurity/defsec/pkg/rules"
)

func main() {

	// organise existing rules by provider
	keyMap := make(map[string][]string)
	for _, rule := range rules.GetRegistered(framework.ALL) {
		id := rule.Rule().AVDID
		if id == "" {
			continue
		}
		parts := strings.Split(id, "-")
		if len(parts) != 3 {
			continue
		}
		keyMap[parts[1]] = append(keyMap[parts[1]], parts[2])
	}

	fmt.Print("\nThe following IDs are free - choose the one for the service you are targeting.\n\n")

	var freeIDs []string
	for key := range keyMap {
		sort.Strings(keyMap[key])
		all := keyMap[key]
		max := all[len(all)-1]
		i, err := strconv.Atoi(max)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "Error, invalid AVD ID: AVD-%s-%s\n", key, max)
		}
		free := fmt.Sprintf("AVD-%s-%04d", key, i+1)
		freeIDs = append(freeIDs, fmt.Sprintf("%16s: %s", key, free))
	}

	sort.Slice(freeIDs, func(i, j int) bool {
		return strings.TrimSpace(freeIDs[i]) < strings.TrimSpace(freeIDs[j])
	})
	fmt.Println(strings.Join(freeIDs, "\n"))

}
