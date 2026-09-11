# Verification helper used by the CI workflow (and runnable locally).
#
# AzerothCore's OpenSSLCrypto::SetupLibrariesForWindows() asserts that legacy.dll
# exists next to the executable, sets the OpenSSL default search path to that
# directory, then loads the "legacy" and "default" providers. A runtime where those
# loads fail is a runtime the server cannot use, but the server dies before it can
# report that, so this check is run against the STAGED runtime in CI and must pass
# before the artifact is published.
#
# Usage: powershell -File openssl_provider_check.ps1 -Dir <dir holding the runtime>

param(
    [string]$Dir = '.',
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'
$Dir = (Resolve-Path $Dir).Path

$sig = @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

public static class OsslCheck
{
    [DllImport("libcrypto-3-x64.dll", CallingConvention = CallingConvention.Cdecl,
               CharSet = CharSet.Ansi, EntryPoint = "OSSL_PROVIDER_load")]
    static extern IntPtr OSSL_PROVIDER_load(IntPtr libctx, string name);

    [DllImport("libcrypto-3-x64.dll", CallingConvention = CallingConvention.Cdecl,
               CharSet = CharSet.Ansi, EntryPoint = "OSSL_PROVIDER_available")]
    static extern int OSSL_PROVIDER_available(IntPtr libctx, string name);

    [DllImport("libcrypto-3-x64.dll", CallingConvention = CallingConvention.Cdecl,
               CharSet = CharSet.Ansi, EntryPoint = "OSSL_PROVIDER_set_default_search_path")]
    static extern int OSSL_PROVIDER_set_default_search_path(IntPtr libctx, string path);

    [DllImport("libcrypto-3-x64.dll", CallingConvention = CallingConvention.Cdecl,
               EntryPoint = "OpenSSL_version_num")]
    static extern ulong OpenSSL_version_num();

    [DllImport("libcrypto-3-x64.dll", CallingConvention = CallingConvention.Cdecl,
               CharSet = CharSet.Ansi, EntryPoint = "EVP_MD_fetch")]
    static extern IntPtr EVP_MD_fetch(IntPtr libctx, string algorithm, string properties);

    [DllImport("libcrypto-3-x64.dll", CallingConvention = CallingConvention.Cdecl,
               EntryPoint = "EVP_MD_free")]
    static extern void EVP_MD_free(IntPtr md);

    public static int Run(string dir, out string report)
    {
        var sb = new StringBuilder();
        int failures = 0;

        sb.AppendLine("libcrypto version_num      = 0x" + OpenSSL_version_num().ToString("X"));
        sb.AppendLine("legacy.dll file exists     = " + File.Exists(Path.Combine(dir, "legacy.dll")));
        sb.AppendLine("set_default_search_path rc = " + OSSL_PROVIDER_set_default_search_path(IntPtr.Zero, dir));
        sb.AppendLine();

        sb.AppendLine("available(default) before  = " + OSSL_PROVIDER_available(IntPtr.Zero, "default"));
        sb.AppendLine("available(legacy)  before  = " + OSSL_PROVIDER_available(IntPtr.Zero, "legacy"));
        sb.AppendLine();

        IntPtr def = OSSL_PROVIDER_load(IntPtr.Zero, "default");
        if (def == IntPtr.Zero) { failures++; }
        sb.AppendLine("load(default)              = " + (def == IntPtr.Zero ? "FAILED (NULL)" : "ok"));

        IntPtr leg = OSSL_PROVIDER_load(IntPtr.Zero, "legacy");
        if (leg == IntPtr.Zero) { failures++; }
        sb.AppendLine("load(legacy)               = " + (leg == IntPtr.Zero ? "FAILED (NULL)" : "ok"));
        sb.AppendLine();

        int availLegacy = OSSL_PROVIDER_available(IntPtr.Zero, "legacy");
        if (availLegacy != 1) { failures++; }
        sb.AppendLine("available(legacy) after    = " + availLegacy);
        sb.AppendLine();

        // Functional proof: MD4 and WHIRLPOOL are only supplied by the legacy provider.
        foreach (var alg in new[] { "MD5", "MD4", "WHIRLPOOL" })
        {
            IntPtr md = EVP_MD_fetch(IntPtr.Zero, alg, null);
            bool ok = md != IntPtr.Zero;
            if (!ok) { failures++; }
            sb.AppendLine("EVP_MD_fetch(" + alg.PadRight(9) + ")    = " + (ok ? "ok" : "NULL"));
            if (ok) EVP_MD_free(md);
        }

        report = sb.ToString();
        return failures;
    }
}
'@

Add-Type -TypeDefinition $sig -Language CSharp

# Run from $Dir so the loader resolves libcrypto-3-x64.dll out of the staged runtime.
Push-Location $Dir
try {
    $report = ''
    $failures = [OsslCheck]::Run($Dir, [ref]$report)
} finally {
    Pop-Location
}

Write-Host "=== OpenSSL provider check (dir = $Dir) ==="
Write-Host $report

Write-Host '=== OpenSSL binaries present ==='
foreach ($n in 'libcrypto-3-x64.dll', 'libssl-3-x64.dll', 'legacy.dll') {
    $p = Join-Path $Dir $n
    if (Test-Path $p) {
        Write-Host ("  {0,-24} {1,-10} {2,12:N0} B  sha256={3}" -f `
            $n, (Get-Item $p).VersionInfo.FileVersion, (Get-Item $p).Length, `
            (Get-FileHash $p -Algorithm SHA256).Hash.Substring(0, 16))
    } else {
        Write-Host ("  {0,-24} MISSING" -f $n)
        $failures++
    }
}

if ($failures -gt 0) {
    Write-Host ""
    Write-Host "OPENSSL PROVIDER CHECK FAILED ($failures problem(s))"
    exit 1
}

Write-Host ""
Write-Host 'OPENSSL PROVIDER CHECK PASSED'
exit 0
