package main

import "testing"

func TestParsePortSet(t *testing.T) {
	ports, err := parsePortSet("9,445,5000-5002")
	if err != nil {
		t.Fatal(err)
	}
	for _, port := range []int{9, 445, 5000, 5001, 5002} {
		if !ports[port] {
			t.Fatalf("expected port %d", port)
		}
	}
	if ports[5003] {
		t.Fatal("did not expect port 5003")
	}
}
