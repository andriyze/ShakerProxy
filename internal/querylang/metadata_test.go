package querylang

import "testing"

func TestAutocompleteMetadataMatchesParserAndIsDefensive(t *testing.T) {
	metadata := AutocompleteMetadata()
	if metadata.Schema != 1 || metadata.MaxQueryBytes != MaxQueryBytes || metadata.MaxTokens != maxTokens || metadata.MaxDepth != maxDepth || len(metadata.Fields) == 0 || len(metadata.Fields) != len(metadataFields) {
		t.Fatalf("unexpected autocomplete metadata bounds: %#v", metadata)
	}
	seen := make(map[string]bool, len(metadata.Fields))
	for _, field := range metadata.Fields {
		if seen[field.Name] || !knownField(field.Name) || len(field.Operators) == 0 || len(field.Suggestions) == 0 {
			t.Fatalf("invalid autocomplete field: %#v", field)
		}
		seen[field.Name] = true
		for _, suggestion := range field.Suggestions {
			if _, err := Parse(suggestion); err != nil {
				t.Fatalf("autocomplete suggestion %q is not parseable: %v", suggestion, err)
			}
		}
	}
	metadata.Fields[0].Name = "forged"
	metadata.Fields[0].Suggestions[0] = "payload:secret"
	fresh := AutocompleteMetadata()
	if fresh.Fields[0].Name != "source" || fresh.Fields[0].Suggestions[0] != "source:ZEEK" {
		t.Fatal("autocomplete metadata was mutable across callers")
	}
}
