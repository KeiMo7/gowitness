package cmd

import "testing"

func TestSARIFOutputIsOptIn(t *testing.T) {
	sarifFlag := scanCmd.PersistentFlags().Lookup("write-sarif")
	if sarifFlag == nil {
		t.Fatal("--write-sarif flag is missing")
	}
	if sarifFlag.DefValue != "false" {
		t.Fatalf("--write-sarif default = %q, want false", sarifFlag.DefValue)
	}

	fileFlag := scanCmd.PersistentFlags().Lookup("write-sarif-file")
	if fileFlag == nil {
		t.Fatal("--write-sarif-file flag is missing")
	}
	if fileFlag.DefValue != "gowitness.sarif" {
		t.Fatalf("--write-sarif-file default = %q, want gowitness.sarif", fileFlag.DefValue)
	}
}
