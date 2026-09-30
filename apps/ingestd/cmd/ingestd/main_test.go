package main

import (
	"testing"

	"shakerproxy.dev/shakerproxy/internal/savedview"
)

func TestOptionalSavedViewRepositoryDoesNotBoxNilStore(t *testing.T) {
	if repository := optionalSavedViewRepository(nil); repository != nil {
		t.Fatal("nil saved-view store became a configured repository")
	}

	store := &savedview.PostgresStore{}
	if repository := optionalSavedViewRepository(store); repository != store {
		t.Fatal("configured saved-view store was not preserved")
	}
}
