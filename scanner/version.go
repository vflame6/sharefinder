package scanner

import (
	"fmt"
	"strings"
)

func buildWindowsVersionString(productName, displayVersion, releaseID, currentVersion, build string, ubr uint32, fallback string) string {
	productName = strings.TrimSpace(productName)
	displayVersion = strings.TrimSpace(displayVersion)
	releaseID = strings.TrimSpace(releaseID)
	currentVersion = strings.TrimSpace(currentVersion)
	build = strings.TrimSpace(build)
	fallback = strings.TrimSpace(fallback)

	if productName == "" {
		if fallback != "" {
			return fallback
		}
		if currentVersion != "" && build != "" {
			if ubr > 0 {
				return fmt.Sprintf("Windows %s Build %s.%d", currentVersion, build, ubr)
			}
			return fmt.Sprintf("Windows %s Build %s", currentVersion, build)
		}
		return "unknown"
	}

	parts := []string{productName}
	if displayVersion != "" {
		parts = append(parts, displayVersion)
	} else if releaseID != "" {
		parts = append(parts, releaseID)
	} else if currentVersion != "" && !strings.Contains(productName, currentVersion) {
		parts = append(parts, currentVersion)
	}

	result := strings.Join(parts, " ")
	if build != "" {
		if ubr > 0 {
			result += fmt.Sprintf(" Build %s.%d", build, ubr)
		} else {
			result += fmt.Sprintf(" Build %s", build)
		}
	}

	return strings.TrimSpace(result)
}
