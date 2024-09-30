// DO NOT EDIT: generated by syft/internal/packagemetadata/generate/main.go

package packagemetadata

import "github.com/anchore/syft/syft/pkg"

// AllTypes returns a list of all pkg metadata types that syft supports (that are represented in the pkg.Package.Metadata field).
func AllTypes() []any {
	return []any{
		pkg.AlpmDBEntry{},
		pkg.ApkDBEntry{},
		pkg.BinarySignature{},
		pkg.CocoaPodfileLockEntry{},
		pkg.ConanV1LockEntry{},
		pkg.ConanV2LockEntry{},
		pkg.ConanfileEntry{},
		pkg.ConaninfoEntry{},
		pkg.DartPubspecEntry{},
		pkg.DartPubspecLockEntry{},
		pkg.DotnetDepsEntry{},
		pkg.DotnetPortableExecutableEntry{},
		pkg.DpkgDBEntry{},
		pkg.ELFBinaryPackageNoteJSONPayload{},
		pkg.ElixirMixLockEntry{},
		pkg.ErlangRebarLockEntry{},
		pkg.GolangBinaryBuildinfoEntry{},
		pkg.GolangModuleEntry{},
		pkg.HackageStackYamlEntry{},
		pkg.HackageStackYamlLockEntry{},
		pkg.JavaArchive{},
		pkg.JavaVMInstallation{},
		pkg.LinuxKernel{},
		pkg.LinuxKernelModule{},
		pkg.LuaRocksPackage{},
		pkg.MicrosoftKbPatch{},
		pkg.NixStoreEntry{},
		pkg.NpmPackage{},
		pkg.NpmPackageLockEntry{},
		pkg.OpamPackage{},
		pkg.PhpComposerInstalledEntry{},
		pkg.PhpComposerLockEntry{},
		pkg.PhpPeclEntry{},
		pkg.PortageEntry{},
		pkg.PythonPackage{},
		pkg.PythonPipfileLockEntry{},
		pkg.PythonPoetryLockEntry{},
		pkg.PythonRequirementsEntry{},
		pkg.RDescription{},
		pkg.RpmArchive{},
		pkg.RpmDBEntry{},
		pkg.RubyGemspec{},
		pkg.RustBinaryAuditEntry{},
		pkg.RustCargoLockEntry{},
		pkg.SwiftPackageManagerResolvedEntry{},
		pkg.SwiplPackEntry{},
		pkg.WordpressPluginEntry{},
		pkg.YarnLockEntry{},
	}
}
