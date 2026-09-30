package inventory

import (
	"errors"
	"os"
	"path/filepath"
)

func MigrateLegacyStore(destination, legacy *Store) error {
	if destination == nil || legacy == nil || destination.Path == "" || legacy.Path == "" || !filepath.IsAbs(destination.Path) || !filepath.IsAbs(legacy.Path) {
		return errors.New("inventory migration paths must be absolute")
	}
	if filepath.Clean(destination.Path) == filepath.Clean(legacy.Path) {
		return nil
	}
	if _, err := os.Lstat(destination.Path); err == nil {
		if _, validateErr := destination.Snapshot(); validateErr != nil {
			return validateErr
		}
		return archiveLegacyStore(legacy.Path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if _, err := os.Lstat(legacy.Path); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	legacy.mu.Lock()
	doc, err := legacy.load()
	legacy.mu.Unlock()
	if err != nil {
		return err
	}
	destination.mu.Lock()
	defer destination.mu.Unlock()
	if _, err := os.Lstat(destination.Path); err == nil {
		return errors.New("inventory migration destination appeared concurrently")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := destination.save(doc); err != nil {
		return err
	}
	return archiveLegacyStore(legacy.Path)
}

func archiveLegacyStore(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("legacy inventory archive source is unsafe")
	}
	archived := path + ".migrated"
	if _, err := os.Lstat(archived); err == nil {
		return errors.New("legacy inventory archive already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(path, archived); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
