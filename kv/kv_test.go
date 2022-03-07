package kv

import (
	"bytes"
	"log"
	"strings"
	"testing"

	"github.com/charmbracelet/charm/client"
	badger "github.com/dgraph-io/badger/v3"
)

func setup(t *testing.T) *KV {
	t.Helper()
	opt := badger.DefaultOptions("").WithInMemory(true)
	cc, err := client.NewClientWithDefaults()
	if err != nil {
		log.Fatal(err)
	}
	kv, err := Open(cc, "test", opt)
	if err != nil {
		log.Fatal(err)
	}
	return kv
}

// TestGet

func TestGetForEmptyDB(t *testing.T) {
	kv := setup(t)
	_, err := kv.Get([]byte("1234"))
	if err == nil {
		t.Errorf("expected error")
	}
}

func TestGet(t *testing.T) {
	tests := []struct {
		testname  string
		key       []byte
		want      []byte
		expectErr bool
	}{
		{"valid kv pair", []byte("1234"), []byte("valid"), false},
		{"invalid key", []byte{}, []byte{}, true},
	}

	for _, tc := range tests {
		kv := setup(t)
		kv.Set(tc.key, tc.want)
		got, err := kv.Get(tc.key)
		if tc.expectErr {
			if err == nil {
				t.Errorf("%s: expected error", tc.testname)
			}
		} else {
			if err != nil {
				t.Errorf("%s: unexpected error %v", tc.testname, err)
			}
			if bytes.Compare(got, tc.want) != 0 {
				t.Errorf("%s: got %s, want %s", tc.testname, got, tc.want)
			}
		}
	}
}

// TestSetReader

func TestSetReader(t *testing.T) {
	tests := []struct {
		testname  string
		key       []byte
		want      string
		expectErr bool
	}{
		{"set valid value", []byte("am key"), "hello I am a very powerful test *flex*", false},
		{"set empty key", []byte(""), "", true},
	}

	for _, tc := range tests {
		kv := setup(t)
		kv.SetReader(tc.key, strings.NewReader(tc.want))
		got, err := kv.Get(tc.key)
		if tc.expectErr {
			if err == nil {
				t.Errorf("case: %s expected an error but did not get one", tc.testname)
			}
		} else {
			if err != nil {
				t.Errorf("case: %s unexpected error %v", tc.testname, err)
			}
			if bytes.Compare(got, []byte(tc.want)) != 0 {
				t.Errorf("case: %s got %s, want %s", tc.testname, got, tc.want)

			}
		}
	}
}

// TestDelete

func TestDelete(t *testing.T) {
	tests := []struct {
		testname  string
		key       []byte
		value     []byte
		expectErr bool
	}{
		{"valid key", []byte("hello"), []byte("value"), false},
		{"empty key with value", []byte{}, []byte("value"), true},
		{"empty key no value", []byte{}, []byte{}, true},
	}

	for _, tc := range tests {
		kv := setup(t)
		kv.Set(tc.key, tc.value)
		if tc.expectErr {
			if err := kv.Delete(tc.key); err == nil {
				t.Errorf("%s: expected error", tc.testname)
			}
		} else {
			if err := kv.Delete(tc.key); err != nil {
				t.Errorf("%s: unexpected error in Delete %v", tc.testname, err)
			}

			want := []byte{} // want an empty result
			if get, _ := kv.Get(tc.key); bytes.Compare(get, want) != 0 {
				t.Errorf("%s: expected an empty string %s, got %s", tc.testname, want, get)

			}

		}
	}
}
