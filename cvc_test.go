package main

import (
	"testing"
)

func TestCVCHelloWorld(t *testing.T) {
	result := CVCHelloWorld()
	if result == "" {
		t.Fatal("CVCHelloWorld returned empty string")
	}
	t.Logf("CVC library result: %s", result)
}

func TestMiraclBigAdd(t *testing.T) {
	if !CVCTestMiraclBigAdd() {
		t.Fatal("MIRACL big number addition test failed (expected 123 + 456 = 579)")
	}
	t.Log("✅ MIRACL big number addition test: PASSED (123 + 456 = 579)")
}

func TestLibraryIntegration(t *testing.T) {
	t.Run("BasicLibraryFunction", TestCVCHelloWorld)
	t.Run("MiraclIntegration", TestMiraclBigAdd)
}
