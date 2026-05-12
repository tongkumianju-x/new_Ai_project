package iprange

import "testing"

func TestParsePorts(t *testing.T) {
	cases := map[string][]int{
		"5353":              {5353},
		"80,443":            {80, 443},
		"5353-5355":         {5353, 5354, 5355},
		"80,443,5353-5355":  {80, 443, 5353, 5354, 5355},
	}
	for in, want := range cases {
		got, err := ParsePorts(in)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if len(got) != len(want) {
			t.Fatalf("%q: got %v want %v", in, got, want)
		}
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("%q[%d]: got %d want %d", in, i, got[i], want[i])
			}
		}
	}
	if _, err := ParsePorts("70000"); err == nil {
		t.Fatal("expected error for out of range port")
	}
}

func TestCIDRIterator_Slash30(t *testing.T) {
	it, err := NewFromCIDR("10.0.0.0/30")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3"}
	got := []string{}
	for {
		ip := it.Next()
		if ip == nil {
			break
		}
		got = append(got, ip.String())
	}
	if len(got) != len(want) {
		t.Fatalf("count: got %v want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("[%d]: got %s want %s", i, got[i], want[i])
		}
	}
}

func TestCIDRIterator_SingleIP(t *testing.T) {
	it, err := NewFromCIDR("192.168.1.10")
	if err != nil {
		t.Fatal(err)
	}
	if ip := it.Next(); ip == nil || ip.String() != "192.168.1.10" {
		t.Fatalf("got %v", ip)
	}
	if ip := it.Next(); ip != nil {
		t.Fatalf("expected exhaustion, got %v", ip)
	}
}
