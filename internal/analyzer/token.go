package analyzer

import (
	"bytes"
	"errors"
)

func LoadToken(path string) ([]byte, error) {
	return loadToken(path, "analyzer ingest token file is unavailable or unsafe")
}

func LoadMaintenanceToken(path string) ([]byte, error) {
	return loadToken(path, "analyzer maintenance token file is unavailable or unsafe")
}

func loadToken(path, message string) ([]byte, error) {
	contents, err := readNoFollowFile(path, 129)
	if err != nil {
		return nil, errors.New(message)
	}
	token := bytes.TrimSpace(contents)
	if len(token) < 32 || len(token) > 128 {
		return nil, errors.New(message)
	}
	return append([]byte(nil), token...), nil
}
