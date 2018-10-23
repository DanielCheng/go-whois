package whois

import (
	"testing"
)

func TestWhois(t *testing.T) {
	var tests = [][3]string{
		{"66.226.11.227", "7296", "ALCHEMYNET - Alchemy Communications, Inc., US"},
	}

	for _, test := range tests {
		r, err := Lookup(test[0])
		if err != nil {
			t.Errorf("Whosis: %s", err)
		} else if AS := r.Get("AS"); AS != test[1] {
			t.Errorf("expected country of %q, got %q", test[1], AS)
		}

		//t.Logf("%s: %#v", test[0], r)
	}
}
