package analyzer

import (
	"reflect"
	"testing"
)

func TestZeekArgumentsLoadSitePolicyWithoutDeterministicMode(t *testing.T) {
	expected := []string{"-C", "-r", "/proc/self/fd/3", "LogAscii::use_json=T", "/etc/shakerproxy/zeek/shakerproxy.zeek"}
	if arguments := zeekArguments(); !reflect.DeepEqual(arguments, expected) {
		t.Fatalf("unexpected Zeek arguments:\nwant %q\n got %q", expected, arguments)
	}
	for _, argument := range zeekArguments() {
		if argument == "-D" || argument == "--deterministic" {
			t.Fatal("Zeek deterministic mode would make connection UIDs collide across captures")
		}
	}
}
