package networktransaction

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestRollbackSpecValidatesAccessPointSnapshot(t *testing.T) {
	digest := strings.Repeat("a", 64)
	valid := []RollbackSpec{
		rollbackSpec(),
		func() RollbackSpec { spec := rollbackSpec(); spec.HostapdManaged = true; return spec }(),
		func() RollbackSpec {
			spec := rollbackSpec()
			spec.HostapdManaged, spec.HostapdConfigExisted, spec.HostapdConfigSHA256, spec.HostapdConfigMode = true, true, digest, 0o600
			return spec
		}(),
	}
	for _, spec := range valid {
		if err := spec.Validate(); err != nil {
			t.Fatalf("valid access point snapshot rejected: %+v: %v", spec, err)
		}
	}
	invalid := map[string]func(*RollbackSpec){
		"backup without managed access point": func(spec *RollbackSpec) { spec.HostapdConfigExisted, spec.HostapdConfigSHA256 = true, digest },
		"digest without backup":               func(spec *RollbackSpec) { spec.HostapdManaged, spec.HostapdConfigSHA256 = true, digest },
		"mode without backup":                 func(spec *RollbackSpec) { spec.HostapdManaged, spec.HostapdConfigMode = true, 0o600 },
		"malformed digest": func(spec *RollbackSpec) {
			spec.HostapdManaged, spec.HostapdConfigExisted, spec.HostapdConfigSHA256 = true, true, "not-a-digest"
		},
		"mode outside permission bits": func(spec *RollbackSpec) {
			spec.HostapdManaged, spec.HostapdConfigExisted, spec.HostapdConfigSHA256, spec.HostapdConfigMode = true, true, digest, 0o4600
		},
	}
	for name, edit := range invalid {
		t.Run(name, func(t *testing.T) {
			spec := rollbackSpec()
			edit(&spec)
			if err := spec.Validate(); err == nil {
				t.Fatalf("invalid access point snapshot accepted: %+v", spec)
			}
		})
	}
}

func TestWiredManifestJSONOmitsAccessPointFields(t *testing.T) {
	now := time.Unix(2000, 0)
	manifest, err := NewWatchdogManifest(preparingRecord(t, now), now, 2*time.Minute, rollbackSpec())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "hostapd") {
		t.Fatalf("wired rollback manifest changed shape: %s", encoded)
	}
}

func TestAccessPointManifestRoundTrips(t *testing.T) {
	root := t.TempDir()
	store := FileStore{Root: root}
	now := time.Unix(2000, 0)
	spec := rollbackSpec()
	spec.HostapdManaged, spec.HostapdConfigExisted, spec.HostapdConfigSHA256, spec.HostapdConfigMode = true, true, strings.Repeat("b", 64), 0o600
	manifest, err := NewWatchdogManifest(preparingRecord(t, now), now, 2*time.Minute, spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.WriteManifest(manifest); err != nil {
		t.Fatal(err)
	}
	read, err := store.ReadManifest(manifest.ApplyID)
	if err != nil || read != manifest {
		t.Fatalf("access point manifest did not round-trip: %+v %v", read, err)
	}
}
