$ErrorActionPreference = 'Continue'
$share = Split-Path -Parent $MyInvocation.MyCommand.Path
$work = 'C:\qnxfix'
$vhd = "$work\ntfs-known.vhd"
$log = "$share\results.txt"
function Say($m) { $m | Out-File -FilePath $log -Append -Encoding utf8; Write-Output $m }
Remove-Item $log -ErrorAction SilentlyContinue
Say ("started " + (Get-Date).ToUniversalTime().ToString('o'))
Say ((Get-CimInstance Win32_OperatingSystem | ForEach-Object { $_.Caption + ' ' + $_.Version + ' build ' + $_.BuildNumber }))
New-Item -ItemType Directory -Force $work | Out-Null
if (Test-Path $vhd) {
  "select vdisk file=`"$vhd`"`r`ndetach vdisk" | Set-Content "$work\dp0.txt" -Encoding ASCII
  diskpart /s "$work\dp0.txt" | Out-Null
  Remove-Item $vhd -Force
}
@"
create vdisk file="$vhd" maximum=40 type=fixed
select vdisk file="$vhd"
attach vdisk
create partition primary
format fs=ntfs quick label=KNOWN
assign letter=W
"@ | Set-Content "$work\dp1.txt" -Encoding ASCII
Say ((diskpart /s "$work\dp1.txt") -join "`n")
Start-Sleep -Seconds 2
if (-not (Test-Path 'W:\')) { Say 'FAILED: W: did not appear'; exit 1 }

# ---- source content, deterministic ----
$src = "$work\src"; Remove-Item $src -Recurse -Force -ErrorAction SilentlyContinue; New-Item -ItemType Directory -Force $src | Out-Null
function TextBytes([int]$size) {
  $sb = New-Object System.Text.StringBuilder
  $i = 0
  while ($sb.Length -lt $size) { [void]$sb.Append(('qnxprobe known data line {0:D6}: files Windows wrote, read back by another reader. ' -f $i)); if ($i % 3 -eq 0) { [void]$sb.Append("`r`n") }; $i++ }
  return ,([System.Text.Encoding]::ASCII.GetBytes($sb.ToString().Substring(0, $size)))
}
function RandomBytes([int]$size, [int]$seed) { $r = New-Object System.Random($seed); $b = New-Object byte[] $size; $r.NextBytes($b); return ,$b }
[IO.File]::WriteAllBytes("$src\text_100000.txt", (TextBytes 100000))
[IO.File]::WriteAllBytes("$src\text_32768.txt", (TextBytes 32768))
[IO.File]::WriteAllBytes("$src\text_5000.txt", (TextBytes 5000))
$mixed = New-Object System.IO.MemoryStream
$b = TextBytes 30000; $mixed.Write($b, 0, $b.Length)
$b = RandomBytes 20000 1234; $mixed.Write($b, 0, $b.Length)
$b = TextBytes 20000; $mixed.Write($b, 0, $b.Length)
[IO.File]::WriteAllBytes("$src\mixed_70000.bin", $mixed.ToArray())
$z = New-Object byte[] 150000; $t = TextBytes 3000; [Array]::Copy($t, 0, $z, 70000, 3000)
[IO.File]::WriteAllBytes("$src\zeros_150000.bin", $z)

# ---- WOF, one folder per algorithm ----
foreach ($algo in 'xpress4k', 'xpress8k', 'xpress16k', 'lzx') {
  New-Item -ItemType Directory -Force "W:\wof\$algo" | Out-Null
  Copy-Item "$src\*" "W:\wof\$algo\"
  Say ((compact /c /exe:$algo "W:\wof\$algo\*") -join "`n")
}
# ---- NTFS compression (LZNT1) ----
New-Item -ItemType Directory -Force 'W:\lznt1' | Out-Null
Copy-Item "$src\text_100000.txt" 'W:\lznt1\text_100000.txt'
Copy-Item "$src\mixed_70000.bin" 'W:\lznt1\mixed_70000.bin'
Say ((compact /c 'W:\lznt1\*') -join "`n")
# ---- plain files and hard links ----
New-Item -ItemType Directory -Force 'W:\Pictures' | Out-Null
$jpg = New-Object System.IO.MemoryStream
$jpg.Write([byte[]](0xFF, 0xD8, 0xFF, 0xE0), 0, 4); $b = RandomBytes 20000 77; $jpg.Write($b, 0, $b.Length)
[IO.File]::WriteAllBytes('W:\Pictures\plain.jpg', $jpg.ToArray())
cmd /c mklink /h W:\Pictures\hardlink.jpg W:\Pictures\plain.jpg | Out-Null
Copy-Item "$src\text_5000.txt" 'W:\plain_5000.txt'
[IO.File]::WriteAllBytes('W:\resident_300.txt', (TextBytes 300))
# ---- sparse files ----
New-Item -ItemType Directory -Force 'W:\sparse' | Out-Null
function Sparse($path, [long]$length, $writes) {
  [IO.File]::WriteAllBytes($path, (New-Object byte[] 0))
  fsutil sparse setflag $path | Out-Null
  $fs = [IO.File]::Open($path, 'Open', 'ReadWrite')
  foreach ($w in $writes) { $fs.Position = $w[0]; $fs.Write($w[1], 0, $w[1].Length) }
  $fs.SetLength($length); $fs.Close()
}
$blk = RandomBytes 8192 5
Sparse 'W:\sparse\both_ends.bin' 8388608 @(@(0, $blk), @(8380416, $blk))
Sparse 'W:\sparse\trailing_hole.bin' 6291456 @(, @(0, $blk))
Sparse 'W:\sparse\leading_hole.bin' 4202496 @(, @(4194304, $blk))
Sparse 'W:\sparse\all_hole.bin' 3145728 @()
$head = New-Object byte[] 8196; [Array]::Copy([byte[]](0xFF, 0xD8, 0xFF, 0xE0), 0, $head, 0, 4); [Array]::Copy($blk, 0, $head, 4, 8192)
Sparse 'W:\Pictures\sparse_photo.jpg' 5242880 @(, @(0, $head))

# ---- cloud placeholders through the Cloud Files API, written by Windows's own filter ----
$cf = @"
using System; using System.Runtime.InteropServices;
public static class Cf {
  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] public struct REG { public uint StructSize; [MarshalAs(UnmanagedType.LPWStr)] public string ProviderName; [MarshalAs(UnmanagedType.LPWStr)] public string ProviderVersion; public IntPtr SyncRootIdentity; public uint SyncRootIdentityLength; public IntPtr FileIdentity; public uint FileIdentityLength; public Guid ProviderId; }
  [StructLayout(LayoutKind.Sequential)] public struct POL { public uint StructSize; public ushort HydPrimary; public ushort HydModifier; public ushort PopPrimary; public ushort PopModifier; public uint InSync; public uint HardLink; public uint PlaceholderManagement; }
  [StructLayout(LayoutKind.Sequential)] public struct BASIC { public long CreationTime; public long LastAccessTime; public long LastWriteTime; public long ChangeTime; public uint FileAttributes; }
  [StructLayout(LayoutKind.Sequential)] public struct META { public BASIC BasicInfo; public long FileSize; }
  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] public struct PH { [MarshalAs(UnmanagedType.LPWStr)] public string RelativeFileName; public META FsMetadata; public IntPtr FileIdentity; public uint FileIdentityLength; public uint Flags; public int Result; public long CreateUsn; }
  [DllImport("cldapi.dll", CharSet = CharSet.Unicode)] public static extern int CfRegisterSyncRoot(string path, ref REG reg, ref POL pol, uint flags);
  [DllImport("cldapi.dll", CharSet = CharSet.Unicode)] public static extern int CfCreatePlaceholders(string dir, [In, Out] PH[] arr, uint count, uint flags, out uint processed);
  [DllImport("cldapi.dll")] public static extern int CfConvertToPlaceholder(IntPtr h, IntPtr identity, uint identityLength, uint flags, IntPtr usn, IntPtr overlapped);
  [DllImport("cldapi.dll")] public static extern int CfDehydratePlaceholder(IntPtr h, long offset, long length, uint flags, IntPtr overlapped);
  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] public static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr sec, uint disposition, uint flags, IntPtr template);
  [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] public static extern uint GetFileAttributesW(string name);
  public static string Convert(string path, long offset, long length) {
    var id = Marshal.StringToHGlobalUni("qnxprobe-known");
    IntPtr h = CreateFileW(path, 0xC0000000, 0, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero);
    if (h == new IntPtr(-1)) return path + ": open failed " + Marshal.GetLastWin32Error();
    int hr = CfConvertToPlaceholder(h, id, 28, 1, IntPtr.Zero, IntPtr.Zero);
    string s = path + ": CfConvertToPlaceholder hr=0x" + hr.ToString("X8");
    if (length != 0) { hr = CfDehydratePlaceholder(h, offset, length, 0, IntPtr.Zero); s += "; CfDehydratePlaceholder(" + offset + ", " + length + ") hr=0x" + hr.ToString("X8"); }
    CloseHandle(h); return s;
  }
  public static string Make(string root, string[] names, long[] sizes) {
    var id = Marshal.StringToHGlobalUni("qnxprobe-known");
    var reg = new REG(); reg.StructSize = (uint)Marshal.SizeOf(typeof(REG)); reg.ProviderName = "qnxprobeKnown"; reg.ProviderVersion = "1.0"; reg.SyncRootIdentity = id; reg.SyncRootIdentityLength = 28; reg.FileIdentity = IntPtr.Zero; reg.FileIdentityLength = 0; reg.ProviderId = new Guid("6f1e2d3c-4b5a-4978-8695-a4b3c2d1e0f1");
    var pol = new POL(); pol.StructSize = (uint)Marshal.SizeOf(typeof(POL)); pol.HydPrimary = 2; pol.HydModifier = 0; pol.PopPrimary = 3; pol.PopModifier = 0; pol.InSync = 0; pol.HardLink = 0; pol.PlaceholderManagement = 0;
    int hr = CfRegisterSyncRoot(root, ref reg, ref pol, 0);
    string s = "CfRegisterSyncRoot hr=0x" + hr.ToString("X8") + " (REG " + reg.StructSize + " bytes, POL " + pol.StructSize + ")";
    var arr = new PH[names.Length]; long now = DateTime.UtcNow.ToFileTimeUtc();
    for (int i = 0; i < names.Length; i++) { arr[i].RelativeFileName = names[i]; arr[i].FsMetadata.BasicInfo.CreationTime = now; arr[i].FsMetadata.BasicInfo.LastAccessTime = now; arr[i].FsMetadata.BasicInfo.LastWriteTime = now; arr[i].FsMetadata.BasicInfo.ChangeTime = now; arr[i].FsMetadata.BasicInfo.FileAttributes = 0x80; arr[i].FsMetadata.FileSize = sizes[i]; arr[i].FileIdentity = id; arr[i].FileIdentityLength = 28; arr[i].Flags = 2; }
    uint done; hr = CfCreatePlaceholders(root, arr, (uint)arr.Length, 0, out done);
    s += "; CfCreatePlaceholders hr=0x" + hr.ToString("X8") + " processed=" + done + " (PH " + Marshal.SizeOf(typeof(PH)) + " bytes)";
    for (int i = 0; i < arr.Length; i++) s += "; " + names[i] + " result=0x" + arr[i].Result.ToString("X8");
    return s;
  }
}
"@
try {
  Add-Type -TypeDefinition $cf
  New-Item -ItemType Directory -Force 'W:\CloudRoot' | Out-Null
  [IO.File]::WriteAllBytes('W:\CloudRoot\hydrated_100000.txt', (TextBytes 100000))
  Say ([Cf]::Make('W:\CloudRoot', @('online_only_video.mp4', 'online_only_photo.jpg', 'online_only_doc.pdf'), @(52428800, 3145728, 1151898)))
  Say ([Cf]::Convert('W:\CloudRoot\hydrated_100000.txt', 0, 0))
  # Dehydrating part of a file needs a running provider: CfDehydratePlaceholder answered 0x8007016A
  # (the cloud file provider is not running) when tried, so no partly hydrated file is made here.
} catch { Say ("cloud placeholders FAILED: " + $_.Exception.Message) }

# ---- what Windows itself says about each file ----
Add-Type -Namespace K -Name N -MemberDefinition '[DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] public static extern uint GetCompressedFileSizeW(string name, out uint high);'
Say "path`tlength`tattributes`tsize_on_disk`tsha256"
Get-ChildItem 'W:\' -Recurse -File -Force | Sort-Object FullName | ForEach-Object {
  [uint32]$hi = 0; $lo = [K.N]::GetCompressedFileSizeW($_.FullName, [ref]$hi); $disk = ([long]$hi * 4294967296) + [long]$lo
  $attr = '0x{0:X}' -f [int]$_.Attributes
  $hash = if ($_.FullName -like 'W:\CloudRoot\*') { 'not-read' } else { (Get-FileHash -Algorithm SHA256 $_.FullName).Hash.ToLower() }
  Say ("{0}`t{1}`t{2}`t{3}`t{4}" -f $_.FullName.Substring(3).Replace('\', '/'), $_.Length, $attr, $disk, $hash)
}
Say '--- cloud root, by name: length, attributes, size on disk, and what a read returns with no provider running'
foreach ($n in 'online_only_video.mp4', 'online_only_photo.jpg', 'online_only_doc.pdf', 'hydrated_100000.txt') {
  $p = "W:\CloudRoot\$n"
  [uint32]$hi = 0; $lo = [K.N]::GetCompressedFileSizeW($p, [ref]$hi); $disk = ([long]$hi * 4294967296) + [long]$lo
  $attr = '0x{0:X}' -f [Cf]::GetFileAttributesW($p)
  $len = try { (New-Object IO.FileInfo $p).Length } catch { 'length-failed' }
  $read = try { $fs = [IO.File]::Open($p, 'Open', 'Read', 'ReadWrite'); $buf = New-Object byte[] 16; $got = $fs.Read($buf, 0, 16); $fs.Close(); "read $got bytes at 0" } catch { 'read refused: ' + $_.Exception.Message.Replace("`r", ' ').Replace("`n", ' ') }
  $hash = if ($n -eq 'hydrated_100000.txt') { (Get-FileHash -Algorithm SHA256 $p).Hash.ToLower() } else { 'not-hashed' }
  Say ("CloudRoot/{0}`t{1}`t{2}`t{3}`t{4}`t{5}" -f $n, $len, $attr, $disk, $hash, $read)
}
Say ((cmd /c dir /a W:\CloudRoot) -join "`n")
Say '--- source hashes'
Get-ChildItem $src -File | Sort-Object Name | ForEach-Object { Say ("{0}`t{1}`t{2}" -f $_.Name, $_.Length, (Get-FileHash -Algorithm SHA256 $_.FullName).Hash.ToLower()) }
Say '--- compact /q'
Say ((compact /q /s:W:\wof) -join "`n")
Say ((fsutil fsinfo ntfsinfo W:) -join "`n")
"select vdisk file=`"$vhd`"`r`ndetach vdisk" | Set-Content "$work\dp2.txt" -Encoding ASCII
Say ((diskpart /s "$work\dp2.txt") -join "`n")
Copy-Item $vhd "$share\ntfs-known.vhd" -Force
Copy-Item $src "$share\src" -Recurse -Force
Say ("vhd sha256 " + (Get-FileHash -Algorithm SHA256 $vhd).Hash.ToLower())
Say ("finished " + (Get-Date).ToUniversalTime().ToString('o'))
