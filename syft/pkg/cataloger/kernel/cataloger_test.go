package kernel

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestKernelCatalogerARM64Image(t *testing.T) {
	for _, path := range []string{"Image.efi", "boot/Image.efi", "Image", "boot/Image-5.10.256", "decompressed.bin"} {
		for _, sourceType := range []string{"directory", "file"} {
			t.Run(sourceType+"/"+path, func(t *testing.T) {
				directory := t.TempDir()
				imagePath := filepath.Join(directory, path)
				require.NoError(t, os.MkdirAll(filepath.Dir(imagePath), 0755))
				image := arm64KernelImage("Linux version " + testKernelBanner + "\n\x00")
				copy(image, "MZ")
				require.NoError(t, os.WriteFile(imagePath, image, 0600))
				tester := pkgtest.NewCatalogTester()
				if sourceType == "directory" {
					tester.FromDirectory(t, directory)
				} else {
					tester.FromFileSource(t, imagePath)
				}
				tester.ExpectsAssertion(func(t *testing.T, packages []pkg.Package, relationships []artifact.Relationship) {
					require.Empty(t, relationships)
					require.Len(t, packages, 1)
					kernelPackage := packages[0]
					require.Equal(t, "linux-kernel", kernelPackage.Name)
					require.Equal(t, "5.10.256", kernelPackage.Version)
					require.Equal(t, "linux-kernel-cataloger", kernelPackage.FoundBy)
					require.Equal(t, pkg.LinuxKernelPkg, kernelPackage.Type)
					require.Equal(t, "pkg:generic/linux-kernel@5.10.256", kernelPackage.PURL)
					require.Equal(t, []cpe.CPE{cpe.Must("cpe:2.3:o:linux:linux_kernel:5.10.256:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource)}, kernelPackage.CPEs)
					require.Equal(t, pkg.LinuxKernel{Architecture: "arm64", Format: "Image", Version: "5.10.256", ExtendedVersion: testKernelBanner}, kernelPackage.Metadata)
					locations := kernelPackage.Locations.ToSlice()
					require.Len(t, locations, 1)
					expectedPath := path
					if sourceType == "file" {
						expectedPath = filepath.Base(path)
					}
					require.True(t, strings.HasSuffix(locations[0].RealPath, expectedPath))
					require.Equal(t, pkg.PrimaryEvidenceAnnotation, locations[0].Annotations[pkg.EvidenceAnnotationKey])
				}).TestCataloger(t, NewLinuxKernelCataloger(DefaultLinuxKernelCatalogerConfig()))
			})
		}
	}
}

func TestKernelCatalogerARM32Image(t *testing.T) {
	paths := []string{"vmlinux", "boot/vmlinux-5.10.240", "boot/Image", "decompressed.bin", "nested/extraction/decompressed.bin"}
	for _, path := range paths {
		for _, sourceType := range []string{"directory", "file"} {
			t.Run(sourceType+"/"+path, func(t *testing.T) {
				directory := t.TempDir()
				imagePath := filepath.Join(directory, path)
				require.NoError(t, os.MkdirAll(filepath.Dir(imagePath), 0755))
				image := append(testARM32KernelEntry(t), []byte("Linux version "+testARM32KernelBanner+"\n\x00")...)
				require.NoError(t, os.WriteFile(imagePath, image, 0600))
				tester := pkgtest.NewCatalogTester()
				if sourceType == "directory" {
					tester.FromDirectory(t, directory)
				} else {
					tester.FromFileSource(t, imagePath)
				}
				tester.ExpectsAssertion(func(t *testing.T, packages []pkg.Package, relationships []artifact.Relationship) {
					require.Empty(t, relationships)
					require.Len(t, packages, 1)
					kernelPackage := packages[0]
					require.Equal(t, "linux-kernel", kernelPackage.Name)
					require.Equal(t, "5.10.240", kernelPackage.Version)
					require.Equal(t, "linux-kernel-cataloger", kernelPackage.FoundBy)
					require.Equal(t, pkg.LinuxKernelPkg, kernelPackage.Type)
					require.Equal(t, "pkg:generic/linux-kernel@5.10.240", kernelPackage.PURL)
					require.Equal(t, []cpe.CPE{cpe.Must("cpe:2.3:o:linux:linux_kernel:5.10.240:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource)}, kernelPackage.CPEs)
					require.Equal(t, pkg.LinuxKernel{Architecture: "arm", Format: "Image", Version: "5.10.240", ExtendedVersion: testARM32KernelBanner}, kernelPackage.Metadata)
					locations := kernelPackage.Locations.ToSlice()
					require.Len(t, locations, 1)
					expectedPath := path
					if sourceType == "file" {
						expectedPath = filepath.Base(path)
					}
					require.True(t, strings.HasSuffix(locations[0].RealPath, expectedPath))
					require.Equal(t, pkg.PrimaryEvidenceAnnotation, locations[0].Annotations[pkg.EvidenceAnnotationKey])
				}).TestCataloger(t, NewLinuxKernelCataloger(DefaultLinuxKernelCatalogerConfig()))
			})
		}
	}
}

func TestKernelCatalogerARM32ImageRejectsUnrelatedAndBannerOnlyFiles(t *testing.T) {
	for _, test := range []struct {
		name string
		path string
		data []byte
	}{
		{name: "unrelated basename", path: "unrelated.bin", data: append(testARM32KernelEntry(t), []byte("Linux version "+testARM32KernelBanner+"\x00")...)},
		{name: "banner only", path: "decompressed.bin", data: []byte("Linux version " + testARM32KernelBanner + "\x00")},
		{name: "random data", path: "decompressed.bin", data: []byte("not a kernel")},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(directory, test.path), test.data, 0600))
			pkgtest.NewCatalogTester().FromDirectory(t, directory).
				Expects(nil, nil).
				TestCataloger(t, NewLinuxKernelCataloger(DefaultLinuxKernelCatalogerConfig()))
		})
	}
}

func TestKernelCatalogerX86ImageDecompressedBin(t *testing.T) {
	image := make([]byte, 0x800)
	binary.LittleEndian.PutUint16(image[510:512], 0xaa55)
	copy(image[514:518], "HdrS")
	binary.LittleEndian.PutUint16(image[518:520], 0x0206)
	binary.LittleEndian.PutUint16(image[526:528], 0x0200)
	image[529] = 1
	copy(image[0x400:], "5.10.121-linuxkit (builder@host) #1 SMP")
	directory := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(directory, "decompressed.bin"), image, 0600))
	pkgtest.NewCatalogTester().FromDirectory(t, directory).
		ExpectsAssertion(func(t *testing.T, packages []pkg.Package, relationships []artifact.Relationship) {
			require.Empty(t, relationships)
			require.Len(t, packages, 1)
			metadata, ok := packages[0].Metadata.(pkg.LinuxKernel)
			require.True(t, ok)
			require.Equal(t, "x86", metadata.Architecture)
			require.Equal(t, "bzImage", metadata.Format)
			require.Equal(t, "5.10.121-linuxkit", metadata.Version)
		}).TestCataloger(t, NewLinuxKernelCataloger(DefaultLinuxKernelCatalogerConfig()))
}

func TestKernelCatalogerARM64ImageRejectsNonKernel(t *testing.T) {
	directory := t.TempDir()
	image := append(make([]byte, 64), []byte("Linux version "+testKernelBanner+"\x00")...)
	copy(image, "MZ")
	require.NoError(t, os.WriteFile(filepath.Join(directory, "Image.efi"), image, 0600))
	pkgtest.NewCatalogTester().FromDirectory(t, directory).
		Expects(nil, nil).
		TestCataloger(t, NewLinuxKernelCataloger(DefaultLinuxKernelCatalogerConfig()))
}

func Test_KernelCataloger(t *testing.T) {
	ctx := context.TODO()
	kernelPkg := pkg.Package{
		Name:    "linux-kernel",
		Version: "6.0.7-301.fc37.x86_64",
		FoundBy: "linux-kernel-cataloger",
		Locations: file.NewLocationSet(
			file.NewVirtualLocation(
				"/lib/modules/6.0.7-301.fc37.x86_64/vmlinuz",
				"/lib/modules/6.0.7-301.fc37.x86_64/vmlinuz",
			),
		),
		Type: pkg.LinuxKernelPkg,
		PURL: "pkg:generic/linux-kernel@6.0.7-301.fc37.x86_64",
		CPEs: []cpe.CPE{cpe.Must("cpe:2.3:o:linux:linux_kernel:6.0.7-301.fc37.x86_64:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource)},
		Metadata: pkg.LinuxKernel{
			Name:            "",
			Architecture:    "x86",
			Version:         "6.0.7-301.fc37.x86_64",
			ExtendedVersion: "6.0.7-301.fc37.x86_64 (mockbuild@bkernel01.iad2.fedoraproject.org) #1 SMP PREEMPT_DYNAMIC Fri Nov 4 18:35:48 UTC 2022",
			BuildTime:       "",
			Author:          "",
			Format:          "bzImage",
			RWRootFS:        false,
			SwapDevice:      0,
			RootDevice:      0,
			VideoMode:       "Video mode 65535",
		},
	}

	kernelModulePkg := pkg.Package{
		Name:    "ttynull",
		Version: "",
		FoundBy: "linux-kernel-cataloger",
		Locations: file.NewLocationSet(
			file.NewVirtualLocation("/lib/modules/6.0.7-301.fc37.x86_64/kernel/drivers/tty/ttynull.ko",
				"/lib/modules/6.0.7-301.fc37.x86_64/kernel/drivers/tty/ttynull.ko",
			),
		),
		Licenses: pkg.NewLicenseSet(
			pkg.NewLicenseFromLocationsWithContext(ctx, "GPL v2",
				file.NewVirtualLocation(
					"/lib/modules/6.0.7-301.fc37.x86_64/kernel/drivers/tty/ttynull.ko",
					"/lib/modules/6.0.7-301.fc37.x86_64/kernel/drivers/tty/ttynull.ko",
				),
			),
		),
		Type: pkg.LinuxKernelModulePkg,
		PURL: "pkg:generic/ttynull",
		Metadata: pkg.LinuxKernelModule{
			Name:          "ttynull",
			Version:       "",
			SourceVersion: "",
			License:       "GPL v2",
			Path:          "/lib/modules/6.0.7-301.fc37.x86_64/kernel/drivers/tty/ttynull.ko",
			Description:   "",
			KernelVersion: "6.0.7-301.fc37.x86_64",
			VersionMagic:  "6.0.7-301.fc37.x86_64 SMP preempt mod_unload ",
			Parameters:    map[string]pkg.LinuxKernelModuleParameter{},
		},
	}

	expectedPkgs := []pkg.Package{
		kernelPkg,
		kernelModulePkg,
	}
	expectedRelationships := []artifact.Relationship{
		{
			From: kernelPkg,
			To:   kernelModulePkg,
			Type: artifact.DependencyOfRelationship,
		},
	}

	pkgtest.NewCatalogTester().
		WithImageResolver(t, "image-kernel-and-modules").
		IgnoreLocationLayer().
		Expects(expectedPkgs, expectedRelationships).
		TestCataloger(t,
			NewLinuxKernelCataloger(
				LinuxKernelCatalogerConfig{
					CatalogModules: true,
				},
			),
		)
}
