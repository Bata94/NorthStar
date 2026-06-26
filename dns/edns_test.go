// Copyright (c) 2026 bata94
// SPDX-License-Identifier: MIT WITH Commons-Clause

package dns

import (
	"encoding/binary"
	"testing"
)

func TestBuildPaddingOption(t *testing.T) {
	tests := []struct {
		name       string
		currentLen int
		blockSize  int
		wantNil    bool
	}{
		{"blockSize zero", 0, 0, true},
		{"blockSize one", 10, 1, true},
		{"already aligned 124+4=128", 124, 128, true},
		{"need padding 0->128", 0, 128, false},
		{"need padding 4->128", 4, 128, false},
		{"already aligned 60+4=64", 60, 64, true},
		{"need padding 0->64", 0, 64, false},
		{"need padding 58->64", 58, 64, false},
		{"need padding 120->128", 120, 128, false},
		{"already aligned 252+4=256", 252, 128, true},
		{"need padding 0->256", 0, 256, false},
		{"need padding 100->128", 100, 128, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildPaddingOption(tt.currentLen, tt.blockSize)
			if tt.wantNil {
				if got != nil {
					t.Errorf("BuildPaddingOption() = %v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatal("BuildPaddingOption() = nil, want non-nil")
			}
			if len(got) < 4 {
				t.Fatal("padding option too short")
			}
			code := binary.BigEndian.Uint16(got[0:2])
			if code != EDNS0OptionPadding {
				t.Errorf("option code = %d, want %d", code, EDNS0OptionPadding)
			}
			padLen := binary.BigEndian.Uint16(got[2:4])
			if len(got) != 4+int(padLen) {
				t.Errorf("option length mismatch: header says %d, actual payload %d", padLen, len(got)-4)
			}
			total := tt.currentLen + 4 + int(padLen)
			if total%tt.blockSize != 0 {
				t.Errorf("total RData + option = %d, not multiple of %d", total, tt.blockSize)
			}
			// Verify padding bytes are zero
			for i := 4; i < len(got); i++ {
				if got[i] != 0 {
					t.Errorf("padding byte %d = %d, want 0", i, got[i])
					break
				}
			}
		})
	}
}

func TestBuildPaddingOptionAfterECS(t *testing.T) {
	ecs := BuildECSOption("192.168.1.1", 24)
	if ecs == nil {
		t.Fatal("BuildECSOption returned nil")
	}
	// ECS option has its own 4-byte header, so total RData = len(ecs)
	blockSize := 128
	pad := BuildPaddingOption(len(ecs), blockSize)
	if pad == nil {
		t.Fatal("BuildPaddingOption should not be nil")
	}
	total := len(ecs) + 4 + int(binary.BigEndian.Uint16(pad[2:4]))
	if total%blockSize != 0 {
		t.Errorf("ECS + padding option total = %d, not multiple of %d", total, blockSize)
	}
}

func TestBuildPaddingOptionNil(t *testing.T) {
	if got := BuildPaddingOption(0, 0); got != nil {
		t.Error("expected nil for blockSize 0")
	}
	if got := BuildPaddingOption(0, 1); got != nil {
		t.Error("expected nil for blockSize 1")
	}
}

func TestBuildPaddingOptionEdgeCases(t *testing.T) {
	// When currentLen + 4 is already a multiple of blockSize, should return nil
	if got := BuildPaddingOption(124, 128); got != nil {
		t.Error("expected nil when already aligned")
	}
	if got := BuildPaddingOption(60, 64); got != nil {
		t.Error("expected nil when already aligned")
	}
	if got := BuildPaddingOption(252, 128); got != nil {
		t.Error("expected nil when already aligned")
	}
}

func TestBuildPaddingOptionLargeBlock(t *testing.T) {
	// blockSize 256, currentLen 0 → total = 4, pad to 256
	pad := BuildPaddingOption(0, 256)
	if pad == nil {
		t.Fatal("unexpected nil")
	}
	total := 0 + 4 + int(binary.BigEndian.Uint16(pad[2:4]))
	if total != 256 {
		t.Errorf("total = %d, want 256", total)
	}
}
