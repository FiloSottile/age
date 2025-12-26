package inspect

import (
	"fmt"
	"testing"

	"filippo.io/age/internal/stream"
)

func TestStreamOverhead(t *testing.T) {
	tests := []struct {
		payloadSize int64
		want        int64
		wantErr     bool
	}{
		{payloadSize: 0, wantErr: true},
		{payloadSize: 15, wantErr: true},
		{payloadSize: 16, wantErr: true},
		{payloadSize: 16 + 15, wantErr: true},
		{payloadSize: 16 + 16, want: 16 + 16}, // empty plaintext
		{payloadSize: 16 + 1 + 16, want: 16 + 16},
		{payloadSize: 16 + stream.ChunkSize + 16, want: 16 + 16},
		{payloadSize: 16 + stream.ChunkSize + 16 + 1, wantErr: true},
		{payloadSize: 16 + stream.ChunkSize + 16 + 15, wantErr: true},
		{payloadSize: 16 + stream.ChunkSize + 16 + 16, wantErr: true}, // empty final chunk
		{payloadSize: 16 + stream.ChunkSize + 16 + 1 + 16, want: 16 + 16 + 16},
	}
	for _, tt := range tests {
		name := "payloadSize=" + fmt.Sprint(tt.payloadSize)
		t.Run(name, func(t *testing.T) {
			got, gotErr := streamOverhead(tt.payloadSize)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("streamOverhead() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("streamOverhead() succeeded unexpectedly")
			}
			if got != tt.want {
				t.Errorf("streamOverhead() = %v, want %v", got, tt.want)
			}
		})
	}
}
