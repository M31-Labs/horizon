package emitc

import "strings"

func NormalizeC(source string) string {
	lines := strings.Split(source, "\n")
	for i := range lines {
		lines[i] = strings.TrimRight(lines[i], " \t")
	}
	return strings.Join(lines, "\n")
}
