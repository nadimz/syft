package kernel

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

const testARM32KernelBanner = "5.10.240 (builderbob@846573de31e4) (arm-linux-gnueabihf-gcc (GCC) 9.2.1 20191025, GNU ld (Linaro_Binutils-2019.12) 2.33.1.20191209) #1 SMP Tue Dec 9 12:21:15 MST 2025"

func testARM32KernelEntry(t *testing.T) []byte {
	t.Helper()
	entry, err := hex.DecodeString("1e2304eb00900fe11a9029e21f0019e31f90c9e3d39089e30400001a019c89e30ce08fe209f06fe10ef32ee16e0060e109f021e1109f10eecbe503eb05a0b0e1")
	require.NoError(t, err)
	return entry
}

func TestParseARM32LinuxKernel(t *testing.T) {
	tests := []struct {
		name  string
		entry func(t *testing.T) []byte
	}{
		{
			name: "optional initial branch",
			entry: func(t *testing.T) []byte {
				return testARM32KernelEntry(t)
			},
		},
		{
			name: "no initial branch",
			entry: func(t *testing.T) []byte {
				return testARM32KernelEntry(t)[4:]
			},
		},
		{
			name: "varied external branch displacements",
			entry: func(t *testing.T) []byte {
				entry := testARM32KernelEntry(t)
				entry[0] ^= 0x7f
				entry[56] ^= 0x35
				return entry
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entry := test.entry(t)
			entry = append(entry, []byte("Linux version "+testARM32KernelBanner+"\n\x00")...)
			metadata, recognized, err := parseARM32LinuxKernel(context.Background(), bytes.NewReader(entry))
			require.NoError(t, err)
			require.True(t, recognized)
			require.Equal(t, pkg.LinuxKernel{Architecture: "arm", Format: "Image", Version: "5.10.240", ExtendedVersion: testARM32KernelBanner}, metadata)
		})
	}
}

func TestParseARM32LinuxKernelRejectsNonKernel(t *testing.T) {
	entry := testARM32KernelEntry(t)
	validBanner := []byte("Linux version " + testARM32KernelBanner + "\x00")
	incorrectLookupBranchCondition := append(append([]byte(nil), entry...), validBanner...)
	incorrectLookupBranchCondition[59] = 0x1b
	tests := map[string][]byte{
		"truncated prefix":                   entry[:59],
		"banner only":                        validBanner,
		"generic ARM code":                   append([]byte{0x00, 0x00, 0xa0, 0xe1}, validBanner...),
		"generic ARM branch":                 append([]byte{0x00, 0x00, 0x00, 0xeb}, validBanner...),
		"shifted startup sequence":           append(append([]byte{0x00, 0x00, 0xa0, 0xe1}, entry...), validBanner...),
		"partial startup sequence":           append(append([]byte(nil), entry[:40]...), validBanner...),
		"incorrect initial branch opcode":    append([]byte{0x1e, 0x23, 0x04, 0xea}, append(entry[4:], validBanner...)...),
		"incorrect initial branch condition": append([]byte{0x1e, 0x23, 0x04, 0x1b}, append(entry[4:], validBanner...)...),
		"incorrect lookup branch condition":  incorrectLookupBranchCondition,
		"unsupported endian or Thumb prefix": append([]byte{0x00, 0xbf, 0x00, 0xbf}, append(entry[4:], validBanner...)...),
		"big-endian startup prefix":          append([]byte{0xe1, 0x0f, 0x90, 0x00}, append(entry[8:], validBanner...)...),
	}
	for name, image := range tests {
		t.Run(name, func(t *testing.T) {
			metadata, recognized, err := parseARM32LinuxKernel(context.Background(), bytes.NewReader(image))
			require.NoError(t, err)
			require.False(t, recognized)
			require.Empty(t, metadata)
		})
	}
}

func TestParseARM32LinuxKernelFixedInstructionMutations(t *testing.T) {
	for _, offset := range []int{4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 60} {
		t.Run("offset-"+strconv.Itoa(offset), func(t *testing.T) {
			entry := testARM32KernelEntry(t)
			entry[offset] ^= 1
			entry = append(entry, []byte("Linux version "+testARM32KernelBanner+"\x00")...)
			_, recognized, err := parseARM32LinuxKernel(context.Background(), bytes.NewReader(entry))
			require.NoError(t, err)
			require.False(t, recognized)
		})
	}
}

type arm32BannerReadErrorReader struct {
	prefix []byte
}

func (reader arm32BannerReadErrorReader) ReadAt(buffer []byte, offset int64) (int, error) {
	if offset == 0 {
		return copy(buffer, reader.prefix), nil
	}
	return 0, errors.New("banner read failure")
}

func TestParseARM32LinuxKernelErrorsAndUnusableBanner(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := parseARM32LinuxKernel(ctx, failingKernelReader{})
	require.ErrorIs(t, err, context.Canceled)
	_, _, err = parseARM32LinuxKernel(context.Background(), failingKernelReader{})
	require.ErrorContains(t, err, "read failure")

	entry := testARM32KernelEntry(t)
	_, recognized, err := parseARM32LinuxKernel(context.Background(), arm32BannerReadErrorReader{prefix: entry})
	require.ErrorContains(t, err, "banner read failure")
	require.True(t, recognized)

	for _, banner := range []string{"", "Linux version %s (%s)\x00", "Linux version 5.10.240\x00"} {
		image := append(append([]byte(nil), entry...), []byte(banner)...)
		metadata, recognized, err := parseARM32LinuxKernel(context.Background(), bytes.NewReader(image))
		require.NoError(t, err)
		require.True(t, recognized)
		require.Empty(t, metadata.Version)
	}
}

func TestParseLinuxKernelFileARM32(t *testing.T) {
	entry := testARM32KernelEntry(t)
	image := append(entry, []byte(strings.Repeat("\x00", 0x7f80d8-len(entry))+"Linux version "+testARM32KernelBanner+"\n\x00")...)
	packages, relationships, err := parseLinuxKernelFile(context.Background(), nil, nil, file.LocationReadCloser{
		Location: file.NewLocation("/boot/decompressed.bin"), ReadCloser: io.NopCloser(bytes.NewReader(image)),
	})
	require.NoError(t, err)
	require.Empty(t, relationships)
	require.Len(t, packages, 1)
	require.Equal(t, pkg.LinuxKernel{Architecture: "arm", Format: "Image", Version: "5.10.240", ExtendedVersion: testARM32KernelBanner}, packages[0].Metadata)
}
