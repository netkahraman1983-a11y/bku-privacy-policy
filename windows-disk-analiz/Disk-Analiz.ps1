<#
.SYNOPSIS
    Windows 10 icin SALT OKUNUR disk alani ve gereksiz dosya analizi.

.DESCRIPTION
    - C: ve D: (veya -Suruculer ile verilen) suruculeri tarar.
    - Klasor boyutlarini, en buyuk dosyalari, gereksiz dosya kategorilerini bulur.
    - Bulgulari Temizlenebilir / Kontrol edilmeli / Silinmemeli olarak siniflandirir.
    - Masaustu\Disk_Analiz_Raporu klasorune Turkce HTML rapor + CSV dosyalari yazar.

    GUVENLIK: Bu betik HICBIR dosyayi silmez, tasimaz veya degistirmez.
    Kayit defterine yazmaz, Windows ayarlarini degistirmez, program kaldirmaz,
    yonetici yetkisi istemez, internete hicbir veri gondermez.
    Tek yazdigi yer rapor klasorudur (Masaustu\Disk_Analiz_Raporu).
    Dosya icerikleri okunmaz; yalnizca -TekrarHash verilirse olasi tekrar
    dosyalarin SHA256 ozeti yerel olarak hesaplanir.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Disk-Analiz.ps1

.EXAMPLE
    .\Disk-Analiz.ps1 -Suruculer C,D -TekrarHash
#>
[CmdletBinding()]
param(
    [string[]]$Suruculer = @('C', 'D'),
    [int]$EskiIndirmeGun = 180,
    [int]$EskiProjeGun = 365,
    [switch]$TekrarHash,
    [string]$CiktiKlasoru = '',
    [switch]$RaporuAcma
)

$ErrorActionPreference = 'Continue'
$baslangic = Get-Date
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

Write-Host ''
Write-Host '==============================================================' -ForegroundColor Cyan
Write-Host '  DİSK ANALİZİ (salt okunur) — hiçbir dosya silinmez/taşınmaz' -ForegroundColor Cyan
Write-Host '==============================================================' -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# 1) Hizli tarayici (C#, .NET Framework ile gelir; ek program kurulmaz)
# ---------------------------------------------------------------------------
$csKod = @'
using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Text;

namespace DiskAnaliz
{
    public class DirStat { public string Path; public long Size; public long Files; public DateTime LastWrite; public int Depth; public bool Denied; }
    public class FileStat { public string Path; public string Name; public string Ext; public long Size; public DateTime LastWrite; public DateTime Created; public string Tag; }
    public class ProjectStat { public string Path; public string Type; public long Size; public long Files; public DateTime LastWrite; }
    public class BuildStat { public string Path; public string Project; public string Type; public long Size; public long Files; public DateTime LastWrite; }
    public class DeniedStat { public string Path; public string Reason; }

    public static class PathUtil
    {
        public static string Norm(string p)
        {
            if (p == null) return "";
            return p.TrimEnd('\\');
        }

        public static bool IsUnder(string path, string root)
        {
            string a = Norm(path), r = Norm(root);
            if (r.Length == 0 || a.Length < r.Length) return false;
            if (a.Length == r.Length) return a.Equals(r, StringComparison.OrdinalIgnoreCase);
            return a[r.Length] == '\\' && a.StartsWith(r, StringComparison.OrdinalIgnoreCase);
        }

        public static int FindLongestRoot(string path, string[] roots)
        {
            if (roots == null || path == null) return -1;
            int best = -1, bestLen = -1;
            for (int i = 0; i < roots.Length; i++)
            {
                string r = roots[i];
                if (r == null) continue;
                if (r.Length > bestLen && IsUnder(path, r)) { best = i; bestLen = r.Length; }
            }
            return best;
        }

        // Ic ice yollari bir kez sayar (ust klasor listedeyse alt oge atlanir).
        public static long SumNonOverlap(string[] paths, long[] sizes)
        {
            if (paths == null || sizes == null) return 0;
            HashSet<string> set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < paths.Length; i++) if (paths[i] != null) set.Add(Norm(paths[i]));
            HashSet<string> counted = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            long total = 0;
            for (int i = 0; i < paths.Length && i < sizes.Length; i++)
            {
                if (paths[i] == null) continue;
                string p = Norm(paths[i]);
                if (counted.Contains(p)) continue;
                bool nested = false;
                string q = p;
                int idx;
                while ((idx = q.LastIndexOf('\\')) > 0)
                {
                    q = q.Substring(0, idx);
                    if (set.Contains(q)) { nested = true; break; }
                }
                if (!nested) { total += sizes[i]; counted.Add(p); }
            }
            return total;
        }
    }

    public class Scanner
    {
        public long MinDirStore = 1048576L;
        public long BigFileMin = 50L * 1048576L;
        public long DupMin = 20L * 1048576L;
        public bool ShowProgress = true;

        public Dictionary<string, DirStat> Dirs = new Dictionary<string, DirStat>(StringComparer.OrdinalIgnoreCase);
        public List<FileStat> BigFiles = new List<FileStat>();
        public List<FileStat> Tagged = new List<FileStat>();
        public List<FileStat> DupCandidates = new List<FileStat>();
        public List<FileStat> Sensitive = new List<FileStat>();
        public List<ProjectStat> Projects = new List<ProjectStat>();
        public List<BuildStat> Builds = new List<BuildStat>();
        public List<DeniedStat> Denied = new List<DeniedStat>();
        public HashSet<string> Exclude = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        public long FileCount, DirCount, ReparseSkipped, CloudOnlyBytes, CloudOnlyFiles, DeniedTotal;
        private DateTime lastProgress = DateTime.MinValue;

        static HashSet<string> S(params string[] a) { return new HashSet<string>(a, StringComparer.OrdinalIgnoreCase); }
        static readonly HashSet<string> ApkExt = S(".apk", ".aab", ".xapk", ".apks");
        static readonly HashSet<string> ArchiveExt = S(".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".cab");
        static readonly HashSet<string> ImageExt = S(".iso", ".img", ".vhd", ".vhdx", ".vmdk", ".wim", ".esd");
        static readonly HashSet<string> InstExt = S(".exe", ".msi", ".msix", ".msixbundle", ".appx", ".appxbundle");
        static readonly HashSet<string> LogExt = S(".log", ".etl");
        static readonly HashSet<string> DumpExt = S(".dmp", ".mdmp", ".hdmp");
        static readonly HashSet<string> BakExt = S(".bak", ".old", ".backup", ".bkp", ".bk");
        static readonly HashSet<string> VideoExt = S(".mp4", ".mkv", ".avi", ".mov", ".wmv", ".flv", ".webm", ".m4v", ".mpg", ".mpeg", ".m2ts", ".mts", ".3gp");
        static readonly HashSet<string> AudioExt = S(".wav", ".aif", ".aiff", ".flac", ".mp3", ".m4a", ".ogg", ".wma", ".opus", ".caf");
        static readonly HashSet<string> SensitiveNames = S("google-services.json", "googleservice-info.plist", "firebase.json", ".firebaserc",
            "firebase_options.dart", "key.properties", "keystore.properties", "signing.properties", "local.properties", "id_rsa", "id_ed25519",
            "id_ecdsa", ".git-credentials", ".npmrc", ".pypirc", "credentials.json", "credentials", "service-account.json", "secrets.json",
            "secrets.yaml", "login data", "logins.json", "key4.db", "key3.db");
        static readonly HashSet<string> SensitiveExt = S(".jks", ".keystore", ".pem", ".p12", ".pfx", ".kdbx", ".kdb", ".ppk", ".key", ".pepk", ".gpg");

        public static string ExtOf(string name)
        {
            if (name == null) return "";
            int i = name.LastIndexOf('.');
            if (i < 0) return "";
            return name.Substring(i).ToLowerInvariant();
        }

        public static bool IsSensitive(string name)
        {
            if (string.IsNullOrEmpty(name)) return false;
            string nl = name.ToLowerInvariant();
            if (SensitiveNames.Contains(nl)) return true;
            if (SensitiveExt.Contains(ExtOf(nl))) return true;
            if (nl.StartsWith(".env")) return true;
            if (nl.Contains("firebase-adminsdk") || nl.Contains("service-account") || nl.Contains("serviceaccount") ||
                nl.StartsWith("client_secret") || nl.Contains("upload-keystore") || nl.Contains("release-key")) return true;
            return false;
        }

        static bool IsCloudOnly(FileAttributes attr)
        {
            // OneDrive "Dosyalar Isteginde" yalnizca bulutta olan dosyalar diskte yer kaplamaz.
            return (((int)attr) & 0x400000) != 0 || (attr & FileAttributes.Offline) != 0;
        }

        static string ReasonOf(Exception ex)
        {
            if (ex is UnauthorizedAccessException) return "Erişim reddedildi";
            if (ex is PathTooLongException) return "Yol çok uzun";
            if (ex is DirectoryNotFoundException) return "Bulunamadı";
            if (ex is IOException) return "G/Ç hatası: " + ex.Message;
            return ex.GetType().Name + ": " + ex.Message;
        }

        static string TagFor(string nl, string ext, long len, string full)
        {
            const long MB = 1048576L;
            if (ApkExt.Contains(ext) && len >= MB) return "apk";
            if (ArchiveExt.Contains(ext) && len >= 10 * MB) return "arsiv";
            if (ImageExt.Contains(ext) && len >= 100 * MB) return "kalip";
            if (InstExt.Contains(ext) && len >= 10 * MB)
            {
                if (ext == ".exe")
                {
                    if (nl.Contains("setup") || nl.Contains("install") || nl.Contains("kurulum") ||
                        full.IndexOf("\\Downloads\\", StringComparison.OrdinalIgnoreCase) >= 0) return "kurulum";
                    return null;
                }
                return "kurulum";
            }
            if (LogExt.Contains(ext) && len >= 5 * MB) return "log";
            if (DumpExt.Contains(ext) && len >= MB) return "dump";
            if (BakExt.Contains(ext) && len >= 5 * MB) return "yedek";
            if (VideoExt.Contains(ext) && len >= 200 * MB) return "video";
            if (AudioExt.Contains(ext) && len >= 50 * MB) return "ses";
            return null;
        }

        static FileStat MakeFile(string full, string name, string ext, long len, DateTime lw, DateTime cr)
        {
            FileStat f = new FileStat();
            f.Path = full; f.Name = name; f.Ext = ext; f.Size = len; f.LastWrite = lw; f.Created = cr;
            return f;
        }

        private void Progress(string cur)
        {
            if (!ShowProgress) return;
            DateTime now = DateTime.Now;
            if ((now - lastProgress).TotalMilliseconds < 1000) return;
            lastProgress = now;
            try
            {
                string c = cur.Length > 58 ? "..." + cur.Substring(cur.Length - 55) : cur;
                Console.Write("\r  {0,12:N0} dosya | {1,10:N0} klasor | {2}", FileCount, DirCount, c.PadRight(58));
            }
            catch { }
        }

        public void Scan(string root)
        {
            DirectoryInfo di = new DirectoryInfo(root);
            Walk(di, 0, null, false);
            if (ShowProgress) { try { Console.WriteLine(); } catch { } }
        }

        private DirStat Walk(DirectoryInfo di, int depth, string projectRoot, bool inBuild)
        {
            DirStat st = new DirStat();
            st.Path = di.FullName; st.Depth = depth; st.LastWrite = DateTime.MinValue;
            DirCount++;
            Progress(st.Path);

            FileSystemInfo[] items;
            try { items = di.GetFileSystemInfos(); }
            catch (Exception ex)
            {
                st.Denied = true;
                DeniedTotal++;
                if (Denied.Count < 20000) { DeniedStat ds = new DeniedStat(); ds.Path = st.Path; ds.Reason = ReasonOf(ex); Denied.Add(ds); }
                if (depth <= 1) Dirs[st.Path] = st;
                return st;
            }

            bool hasPubspec = false, hasGradle = false, hasPackage = false, hasLock = false;
            bool hasAls = false, hasCsproj = false, hasSln = false, hasGit = false;
            List<DirectoryInfo> subdirs = new List<DirectoryInfo>();

            foreach (FileSystemInfo fsi in items)
            {
                FileAttributes attr;
                try { attr = fsi.Attributes; } catch { continue; }

                DirectoryInfo sd = fsi as DirectoryInfo;
                if (sd != null)
                {
                    // Junction / sembolik bag: dongu ve cift sayimi onlemek icin izlenmez.
                    if ((attr & FileAttributes.ReparsePoint) != 0) { ReparseSkipped++; continue; }
                    if (Exclude.Contains(sd.FullName)) continue;
                    if (string.Equals(sd.Name, ".git", StringComparison.OrdinalIgnoreCase)) hasGit = true;
                    subdirs.Add(sd);
                    continue;
                }

                FileInfo fi = fsi as FileInfo;
                if (fi == null) continue;
                string n = fi.Name;
                string nl = n.ToLowerInvariant();
                string ext = ExtOf(nl);
                switch (nl)
                {
                    case "pubspec.yaml": hasPubspec = true; break;
                    case "build.gradle": case "build.gradle.kts": case "settings.gradle": case "settings.gradle.kts": hasGradle = true; break;
                    case "package.json": hasPackage = true; break;
                    case "package-lock.json": case "yarn.lock": case "pnpm-lock.yaml": hasLock = true; break;
                }
                if (ext == ".als") hasAls = true;
                else if (ext == ".csproj") hasCsproj = true;
                else if (ext == ".sln") hasSln = true;

                long len; DateTime lw, cr;
                try { len = fi.Length; lw = fi.LastWriteTime; cr = fi.CreationTime; } catch { continue; }
                FileCount++;
                if (IsCloudOnly(attr)) { CloudOnlyBytes += len; CloudOnlyFiles++; continue; }

                st.Size += len; st.Files++;
                if (lw > st.LastWrite) st.LastWrite = lw;

                FileStat fs = null;
                if (len >= BigFileMin) { fs = MakeFile(fi.FullName, n, ext, len, lw, cr); BigFiles.Add(fs); }
                if (len >= DupMin) { if (fs == null) fs = MakeFile(fi.FullName, n, ext, len, lw, cr); DupCandidates.Add(fs); }
                string tag = TagFor(nl, ext, len, fi.FullName);
                if (tag != null) { if (fs == null) fs = MakeFile(fi.FullName, n, ext, len, lw, cr); fs.Tag = tag; Tagged.Add(fs); }
                if (Sensitive.Count < 5000 && IsSensitive(n)) { if (fs == null) fs = MakeFile(fi.FullName, n, ext, len, lw, cr); Sensitive.Add(fs); }
            }

            string myType = null;
            if (projectRoot == null && !inBuild)
            {
                if (hasPubspec) myType = "Flutter";
                else if (hasGradle) myType = "Android / Gradle";
                else if (hasAls) myType = "Ableton Live";
                else if (hasSln || hasCsproj) myType = ".NET";
                else if (hasPackage && hasLock) myType = "Node.js";
                else if (hasGit) myType = "Git deposu";
            }
            string childProject = projectRoot != null ? projectRoot : (myType != null ? st.Path : null);

            foreach (DirectoryInfo sd in subdirs)
            {
                string bt = null;
                if (!inBuild)
                {
                    string sn = sd.Name.ToLowerInvariant();
                    if (hasPubspec && (sn == "build" || sn == ".dart_tool")) bt = "Flutter";
                    else if (hasGradle && (sn == "build" || sn == ".gradle" || sn == ".cxx" || sn == ".externalnativebuild")) bt = "Gradle";
                    else if (hasPackage && hasLock && sn == "node_modules") bt = "Node.js";
                    else if (hasCsproj && (sn == "bin" || sn == "obj")) bt = ".NET";
                }
                DirStat c = Walk(sd, depth + 1, childProject, inBuild || bt != null);
                if (bt != null && c.Size >= MinDirStore)
                {
                    BuildStat b = new BuildStat();
                    b.Path = c.Path; b.Project = childProject != null ? childProject : st.Path; b.Type = bt;
                    b.Size = c.Size; b.Files = c.Files; b.LastWrite = c.LastWrite;
                    Builds.Add(b);
                }
                st.Size += c.Size; st.Files += c.Files;
                if (c.LastWrite > st.LastWrite) st.LastWrite = c.LastWrite;
            }

            if (myType != null)
            {
                ProjectStat p = new ProjectStat();
                p.Path = st.Path; p.Type = myType; p.Size = st.Size; p.Files = st.Files; p.LastWrite = st.LastWrite;
                Projects.Add(p);
            }
            if (st.Size >= MinDirStore || depth <= 1) Dirs[st.Path] = st;
            return st;
        }

        // Taramada saklanmamis (kucuk veya tarama disi) klasorleri olcer.
        public DirStat Get(string path)
        {
            if (string.IsNullOrEmpty(path)) return null;
            DirStat d;
            if (Dirs.TryGetValue(path, out d)) return d;
            if (Dirs.TryGetValue(path.TrimEnd('\\'), out d)) return d;
            DirectoryInfo di;
            try { di = new DirectoryInfo(path); if (!di.Exists) return null; } catch { return null; }
            if (Dirs.TryGetValue(di.FullName, out d)) return d;
            d = new DirStat(); d.Path = di.FullName; d.LastWrite = DateTime.MinValue;
            MeasureInto(di, d, true);
            return d;
        }

        private void MeasureInto(DirectoryInfo di, DirStat st, bool top)
        {
            FileSystemInfo[] items;
            try { items = di.GetFileSystemInfos(); }
            catch { if (top) st.Denied = true; return; }
            foreach (FileSystemInfo fsi in items)
            {
                try
                {
                    FileAttributes attr = fsi.Attributes;
                    DirectoryInfo sd = fsi as DirectoryInfo;
                    if (sd != null)
                    {
                        if ((attr & FileAttributes.ReparsePoint) == 0) MeasureInto(sd, st, false);
                        continue;
                    }
                    if (IsCloudOnly(attr)) continue;
                    FileInfo fi = fsi as FileInfo;
                    if (fi == null) continue;
                    st.Size += fi.Length; st.Files++;
                    DateTime lw = fi.LastWriteTime;
                    if (lw > st.LastWrite) st.LastWrite = lw;
                }
                catch { }
            }
        }

        public List<DirStat> SortedDirs(long minSize, int minDepth)
        {
            List<DirStat> l = new List<DirStat>();
            foreach (DirStat d in Dirs.Values) if (d.Size >= minSize && d.Depth >= minDepth) l.Add(d);
            l.Sort(delegate (DirStat x, DirStat y) { return y.Size.CompareTo(x.Size); });
            return l;
        }

        public List<FileStat> SortedBigFiles()
        {
            List<FileStat> l = new List<FileStat>(BigFiles);
            l.Sort(delegate (FileStat x, FileStat y) { return y.Size.CompareTo(x.Size); });
            return l;
        }
    }

    // PowerShell 5.1'deki ConvertTo-Json boyut sinirina takilmamak icin basit JSON yazici.
    public static class Json
    {
        public static string Write(object o)
        {
            StringBuilder sb = new StringBuilder(1 << 20);
            W(sb, o, 0);
            return sb.ToString();
        }

        static void W(StringBuilder sb, object o, int depth)
        {
            if (o == null || depth > 24) { sb.Append("null"); return; }
            Type t = o.GetType();
            if (t.FullName == "System.Management.Automation.PSObject")
            {
                PropertyInfo pi = t.GetProperty("BaseObject");
                object b = pi != null ? pi.GetValue(o, null) : null;
                if (b != null && !object.ReferenceEquals(b, o) && b.GetType().FullName != "System.Management.Automation.PSCustomObject")
                { W(sb, b, depth); return; }
                Str(sb, o.ToString()); return;
            }
            string s = o as string;
            if (s != null) { Str(sb, s); return; }
            if (o is bool) { sb.Append((bool)o ? "true" : "false"); return; }
            if (o is DateTime)
            {
                DateTime dt = (DateTime)o;
                Str(sb, dt.Year < 1981 ? "" : dt.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture)); return;
            }
            if (o is int || o is long || o is short || o is byte || o is uint || o is ulong || o is ushort || o is sbyte)
            { sb.Append(Convert.ToString(o, CultureInfo.InvariantCulture)); return; }
            if (o is double || o is float || o is decimal)
            {
                double d = Convert.ToDouble(o, CultureInfo.InvariantCulture);
                if (double.IsNaN(d) || double.IsInfinity(d)) sb.Append("null");
                else sb.Append(d.ToString("R", CultureInfo.InvariantCulture));
                return;
            }
            IDictionary dict = o as IDictionary;
            if (dict != null)
            {
                sb.Append('{');
                bool first = true;
                foreach (DictionaryEntry e in dict)
                {
                    if (!first) sb.Append(',');
                    first = false;
                    Str(sb, Convert.ToString(e.Key, CultureInfo.InvariantCulture));
                    sb.Append(':');
                    W(sb, e.Value, depth + 1);
                }
                sb.Append('}');
                return;
            }
            IEnumerable en = o as IEnumerable;
            if (en != null)
            {
                sb.Append('[');
                bool first = true;
                foreach (object x in en)
                {
                    if (!first) sb.Append(',');
                    first = false;
                    W(sb, x, depth + 1);
                }
                sb.Append(']');
                return;
            }
            Str(sb, o.ToString());
        }

        static void Str(StringBuilder sb, string s)
        {
            sb.Append('"');
            foreach (char c in s)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '<': sb.Append("\\u003c"); break;
                    case '>': sb.Append("\\u003e"); break;
                    case '&': sb.Append("\\u0026"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < 0x20 || c == '\u2028' || c == '\u2029') sb.AppendFormat("\\u{0:x4}", (int)c);
                        else sb.Append(c);
                        break;
                }
            }
            sb.Append('"');
        }
    }
}
'@

if (-not ('DiskAnaliz.Scanner' -as [type])) {
    try {
        Add-Type -TypeDefinition $csKod -Language CSharp -ErrorAction Stop
    }
    catch {
        Write-Host "Tarayıcı derlenemedi: $($_.Exception.Message)" -ForegroundColor Red
        return
    }
}

# ---------------------------------------------------------------------------
# 2) Yardimci fonksiyonlar ve sabitler
# ---------------------------------------------------------------------------
$GB = 1073741824.0
$MB = 1048576.0
$simdi = Get-Date

function Format-Tarih($d) {
    if ($null -eq $d) { return '' }
    try { $dt = [datetime]$d } catch { return '' }
    if ($dt.Year -lt 1981) { return '' }
    return $dt.ToString('yyyy-MM-dd HH:mm')
}
function Get-Gun($d) {
    if ($null -eq $d) { return $null }
    $dt = [datetime]$d
    if ($dt.Year -lt 1981) { return $null }
    return [int][math]::Floor(($simdi - $dt).TotalDays)
}
function Get-Surucu([string]$p) { if ($p -and $p.Length -ge 2 -and $p[1] -eq ':') { return $p.Substring(0, 1).ToUpper() } return '?' }
function To-GB([double]$b) { return [math]::Round($b / $GB, 2) }

# Kategoriler (raporda bu sirayla gosterilir)
$KategoriTanim = @(
    [ordered]@{ ad = 'Windows geçici dosyaları'; aciklama = 'Kullanıcı ve Windows Temp klasörleri, küçük resim önbelleği, hata raporları (WER) ve çökme dökümleri. Windows ve programlar bunları gerektiğinde yeniden oluşturur.' }
    [ordered]@{ ad = 'Uygulama önbellekleri'; aciklama = 'Tarayıcı (Chrome, Edge, Brave, Firefox), VS Code, Discord, ekran kartı gölgelendirici önbellekleri vb. Silinirse uygulama ilk açılışta biraz yavaş olabilir; veri kaybı olmaz.' }
    [ordered]@{ ad = 'Eski kurulum dosyaları'; aciklama = 'Setup/installer .exe, .msi, ISO kalıpları ve ayıklanmış sürücü kurulum klasörleri. Program kuruluysa çoğunlukla gerekmez; lisanslı veya artık indirilemeyen sürümler olabilir.' }
    [ordered]@{ ad = 'Kullanılmayan APK ve ZIP dosyaları'; aciklama = 'Proje dışındaki APK/AAB paketleri ve büyük ZIP/RAR/7z arşivleri. İçerik başka yerde açılmış olabilir ama tek kopya/yedek de olabilir.' }
    [ordered]@{ ad = 'Eski indirmeler'; aciklama = 'İndirilenler klasöründe uzun süredir değiştirilmemiş dosyalar.' }
    [ordered]@{ ad = 'Log dosyaları'; aciklama = 'Büyük .log/.etl günlükleri ve .dmp hata dökümleri. Genelde yalnızca hata ayıklamada gerekir.' }
    [ordered]@{ ad = 'Windows güncelleme kalıntıları'; aciklama = 'İndirilmiş güncelleme paketleri, Teslim İyileştirme önbelleği, Windows.old ve yükseltme klasörleri. Windows Disk Temizleme aracıyla temizlenmelidir.' }
    [ordered]@{ ad = 'Çöp kutusu'; aciklama = 'Silinmiş ama Geri Dönüşüm Kutusu''nda bekleyen dosyalar. Yanlışlıkla silinmiş önemli dosya olabilir; boşaltmadan önce göz atın.' }
    [ordered]@{ ad = 'Tekrarlanan dosyalar'; aciklama = 'Aynı ad ve aynı boyuttaki (veya -TekrarHash ile aynı içerikteki) 20 MB üzeri dosyalar. Hangi kopyanın kalacağına siz karar vermelisiniz.' }
    [ordered]@{ ad = 'Büyük video ve ses dosyaları'; aciklama = '200 MB üzeri video ve 50 MB üzeri ses dosyaları. Kişisel kayıt veya proje sesi olabilir; korunan müzik klasörlerindekiler silinmemeli olarak işaretlenir.' }
    [ordered]@{ ad = 'Kullanılmayan eski proje klasörleri'; aciklama = "Son $EskiProjeGun günde değişmemiş proje klasörleri. Projeleriniz korumalıdır; yalnızca bilgi amaçlı listelenir (arşivlemeyi düşünebilirsiniz)." }
    [ordered]@{ ad = 'Gereksiz olabilecek yedekler'; aciklama = 'Backup/Yedek adlı klasörler ve .bak/.old dosyaları. Asıl verinin tek yedeği olabilir.' }
    [ordered]@{ ad = 'Eski Android geliştirme çıktıları'; aciklama = 'Flutter/Gradle build klasörleri, eski Android Studio sürüm klasörleri, emülatör (AVD) ve sistem görüntüleri. Derleme çıktıları kaynak koddan yeniden üretilebilir.' }
    [ordered]@{ ad = 'Gradle ve diğer geliştirme önbellekleri'; aciklama = 'Gradle, Pub (Flutter), npm, Maven, NuGet, pip önbellekleri ve Android Studio önbellekleri. Silinirse sonraki derlemede internetten yeniden indirilir.' }
    [ordered]@{ ad = 'Diğer büyük dosyalar'; aciklama = 'Türü veya sahibi otomatik belirlenemeyen büyük dosyalar. Bir programa ait olabilir; emin değilseniz dokunmayın.' }
    [ordered]@{ ad = 'Sistem ve korunan alanlar'; aciklama = 'Windows bileşenleri, sayfa dosyası, hazırda bekletme dosyası, SDK''lar, kimlik bilgileri ve sizin korunmasını istediğiniz alanlar. Bilgi amaçlıdır; silinmemelidir.' }
)

# Korunan alanlar (klasor yolu + '\' uzerinde eslenir)
$Koruma = @(
    @{ Ad = 'Android Studio projeleri'; Rx = '\\(AndroidStudioProjects|StudioProjects)\\' }
    @{ Ad = 'Flutter projeleri / SDK'; Rx = '\\[^\\]*flutter[^\\]*\\' }
    @{ Ad = 'İSG Asist uygulaması'; Rx = '\\[^\\]*(is[gğ][ _.-]?asist|isg)[^\\]*\\' }
    @{ Ad = 'BKÜ uygulaması'; Rx = '\\[^\\]*bk[uü][^\\]*\\' }
    @{ Ad = 'Ableton Live projeleri'; Rx = '\\[^\\]*(Ableton|User Library)[^\\]*\\|\\[^\\]* Project\\' }
    @{ Ad = 'VST ve ses kütüphaneleri'; Rx = '\\[^\\]*(VST|Steinberg|Native Instruments|Kontakt|Spitfire|Arturia|Splice|iZotope|Waves|Xfer|Serum|Image-Line|FL Studio|Plugin|Plug-in|Sample|Loops|Soundbank|Sound Bank|Library|Libraries|K[uü]t[uü]phane|Presets|Expansions)[^\\]*\\' }
    @{ Ad = 'Müzik kayıtları'; Rx = '\\(Music|M[uü]zik)\\|\\[^\\]*(Kay[ıi]t|Record|Stems|Mixdown|Bounce|Vocal|Vokal|Beat|[ŞS]ark[ıi]|Song|Master)[^\\]*\\' }
    @{ Ad = 'Kişisel belgeler'; Rx = '\\(Documents|Belgeler|Belgelerim|Pictures|Resimler|Desktop|Masa[uü]st[uü]|OneDrive[^\\]*|Google Drive|Dropbox)\\' }
    @{ Ad = 'Kaynak kodları'; Rx = '\\(src|source|sources|repos|GitHub|GitLab|git|code|kod|kodlar|workspace|dev|Projects|Projeler|Proje|Projelerim)\\' }
    @{ Ad = 'Şifreler ve kimlik bilgileri'; Rx = '\\(\.ssh|\.gnupg|Keys|Anahtarlar|[ŞS]ifreler|Passwords|KeePass|Bitwarden|1Password)\\' }
)
$RxSistem = '^[A-Za-z]:\\(Windows|Program Files|Program Files \(x86\)|ProgramData|Recovery|Boot|EFI|System Volume Information|PerfLogs|Config\.Msi)\\|\\(Steam|SteamLibrary|steamapps|Epic Games|XboxGames|WindowsApps|Riot Games|GOG Games|EA Games|Ubisoft Game Launcher)\\'
$RxGelistirmeHaric = '\\(AppData|\.vscode|\.vscode-insiders|\.cursor|\.gradle|\.m2|\.nuget|\.pub-cache|\.android|\.dartServer|scoop|node_modules)\\|^[A-Za-z]:\\(Windows|Program Files|Program Files \(x86\)|ProgramData|\$Recycle\.Bin)\\'

$Bilinen = New-Object System.Collections.Generic.List[object]       # bilinen konumlar (siniflandirma icin)
$Rows = New-Object System.Collections.Generic.List[object]          # tum bulgular
$Gorulen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
$Notlar = New-Object System.Collections.Generic.List[string]
$Erisilemeyen = New-Object System.Collections.Generic.List[object]

$NasilVarsayilan = @{
    'Windows geçici dosyaları'                = 'Ayarlar > Sistem > Depolama > Geçici dosyalar veya "Disk Temizleme" (cleanmgr) aracını kullanın.'
    'Uygulama önbellekleri'                   = 'İlgili uygulamanın kendi ayarından önbelleği temizleyin (ör. tarayıcıda Ctrl+Shift+Del > Önbelleğe alınmış dosyalar).'
    'Eski kurulum dosyaları'                  = 'Programın kurulu olduğunu ve kurulum dosyasına ihtiyacınız olmadığını doğrulayıp kendiniz silin.'
    'Kullanılmayan APK ve ZIP dosyaları'      = 'İçeriğin başka yerde bulunduğunu doğrulayın; gerekirse harici diske arşivleyin.'
    'Eski indirmeler'                         = 'İndirilenler klasörünü tarihe göre sıralayıp tek tek gözden geçirin.'
    'Log dosyaları'                           = 'İlgili program kapalıyken eski günlükleri gözden geçirin; Windows günlükleri için Disk Temizleme kullanın.'
    'Windows güncelleme kalıntıları'          = 'Disk Temizleme > "Sistem dosyalarını temizle" > Windows Update Temizleme / Önceki Windows yüklemeleri.'
    'Çöp kutusu'                              = 'Geri Dönüşüm Kutusu''nu açıp içeriğe göz attıktan sonra boşaltın.'
    'Tekrarlanan dosyalar'                    = 'Sekmedeki gruplara bakıp hangi kopyanın kalacağına karar verin.'
    'Büyük video ve ses dosyaları'            = 'Gerekli olanları harici diske/buluta taşımayı değerlendirin.'
    'Kullanılmayan eski proje klasörleri'     = 'Korumalı: silmeyin; isterseniz harici diske arşivleyin.'
    'Gereksiz olabilecek yedekler'            = 'Yedeğin başka bir kopyası olduğunu doğrulamadan silmeyin.'
    'Eski Android geliştirme çıktıları'       = 'Android Studio > Build > Clean Project, "flutter clean" veya SDK Manager / Device Manager üzerinden kaldırın.'
    'Gradle ve diğer geliştirme önbellekleri' = 'Android Studio ve Gradle kapalıyken (gradlew --stop) önbelleği temizleyin; sonraki derleme yeniden indirir.'
    'Diğer büyük dosyalar'                    = 'Dosyanın hangi programa ait olduğunu belirleyin; emin değilseniz dokunmayın.'
    'Sistem ve korunan alanlar'               = 'Dokunmayın.'
}

function Add-Bulgu {
    param(
        [string]$Yol, [long]$Boyut, $Tarih, [string]$Durum, [string]$Kategori, [string]$Gerekce,
        [string]$Yeniden = '', [string]$Tur = 'Klasör', [string]$Oneri = '', [string]$Nasil = '', [long]$Adet = 0
    )
    if ([string]::IsNullOrEmpty($Yol)) { return }
    if (-not $script:Gorulen.Add($Yol)) { return }
    if (-not $Oneri) { $Oneri = $Kategori }
    if (-not $Nasil) { $Nasil = $script:NasilVarsayilan[$Kategori] }
    $script:Rows.Add([ordered]@{
            p = $Yol; s = [long]$Boyut; d = (Format-Tarih $Tarih); g = (Get-Gun $Tarih); st = $Durum; c = $Kategori; r = $Gerekce
            rg = $Yeniden; t = $Tur; dr = (Get-Surucu $Yol); o = $Oneri; n = $Nasil; a = [long]$Adet
        })
}

# Bilinen konum ekler. Joker (*) destekler. $Durum: G=Temizlenebilir, Y=Kontrol, K=Silinmemeli
function Add-Bilinen {
    param(
        [string]$Yol, [string]$Durum, [string]$Kategori, [string]$Gerekce, [string]$Yeniden = '',
        [string]$Oneri = '', [string]$Nasil = '', [switch]$SatirEkleme, [long]$MinBoyut = 1048576
    )
    if ([string]::IsNullOrEmpty($Yol)) { return }
    $yollar = @()
    if ($Yol.Contains('*')) {
        $yollar = @(Get-Item -Path $Yol -Force -ErrorAction SilentlyContinue | Where-Object { $_.PSIsContainer } | ForEach-Object { $_.FullName })
    }
    elseif (Test-Path -LiteralPath $Yol -PathType Container -ErrorAction SilentlyContinue) {
        $yollar = @((Get-Item -LiteralPath $Yol -Force -ErrorAction SilentlyContinue).FullName)
    }
    foreach ($p in $yollar) {
        if (-not $p) { continue }
        $st = $script:sc.Get($p)
        if ($null -eq $st) { continue }
        $script:Bilinen.Add([pscustomobject]@{ Yol = $p; Durum = $Durum; Kategori = $Kategori; Oneri = $(if ($Oneri) { $Oneri } else { $Kategori }) })
        if ($SatirEkleme) { continue }
        if ($st.Denied) {
            $script:Erisilemeyen.Add([ordered]@{ p = $p; r = 'Erişim reddedildi (bilinen temizlik konumu; boyut ölçülemedi — yönetici olarak çalıştırılırsa ölçülebilir)' })
            Add-Bulgu -Yol $p -Boyut 0 -Tarih $null -Durum $Durum -Kategori $Kategori -Gerekce ($Gerekce + ' [Erişilemedi: boyut ölçülemedi]') -Yeniden $Yeniden -Oneri $Oneri -Nasil $Nasil
            continue
        }
        if ($st.Size -lt $MinBoyut) { continue }
        Add-Bulgu -Yol $p -Boyut $st.Size -Tarih $st.LastWrite -Durum $Durum -Kategori $Kategori -Gerekce $Gerekce -Yeniden $Yeniden -Oneri $Oneri -Nasil $Nasil -Adet $st.Files
    }
}

$script:KokDizileri = @{ Bilinen = [string[]]@(); Build = [string[]]@(); Proje = [string[]]@() }
function Update-Kokler {
    $script:KokDizileri.Bilinen = [string[]]@($script:Bilinen | ForEach-Object { $_.Yol })
    $script:KokDizileri.Build = [string[]]@($script:BuildListe | ForEach-Object { $_.Path })
    $script:KokDizileri.Proje = [string[]]@($script:ProjeListe | ForEach-Object { $_.Path })
}

# Bir yolun silinebilirlik durumunu belirler. Emin olunamayan hicbir sey 'G' olmaz.
function Get-Sinif {
    param([string]$Yol, [bool]$Dosya, [string]$VarsayilanDurum = 'Y', [string]$VarsayilanGerekce = '', [string]$VarsayilanKategori = '')
    $ad = [System.IO.Path]::GetFileName($Yol)
    $klasor = if ($Dosya) { [System.IO.Path]::GetDirectoryName($Yol) } else { $Yol }
    if (-not $klasor) { $klasor = $Yol }
    $kx = $klasor.TrimEnd('\') + '\'

    if ($Dosya -and [DiskAnaliz.Scanner]::IsSensitive($ad)) {
        return @{ st = 'K'; k = 'Sistem ve korunan alanlar'; r = 'Kimlik bilgisi, imza anahtarı (keystore) veya Firebase/uygulama yapılandırması olabilir. Kesinlikle silinmemeli.'; alt = 'hassas' }
    }
    if ($Dosya -and $Yol -match '^[A-Za-z]:\\(pagefile|hiberfil|swapfile)\.sys$') {
        return @{ st = 'K'; k = 'Sistem ve korunan alanlar'; r = 'Windows sanal bellek / hazırda bekletme dosyası. Elle silinemez; boyutu yalnızca Windows ayarlarından değişir (bu analiz ayar değiştirmez).'; alt = 'sistem' }
    }
    $i = [DiskAnaliz.PathUtil]::FindLongestRoot($Yol, $script:KokDizileri.Bilinen)
    if ($i -ge 0) {
        $kb = $script:Bilinen[$i]
        return @{ st = $kb.Durum; k = $kb.Kategori; r = "Bilinen konumun içinde: $($kb.Yol)"; alt = 'bilinen'; kok = $kb.Yol }
    }
    $i = [DiskAnaliz.PathUtil]::FindLongestRoot($Yol, $script:KokDizileri.Build)
    if ($i -ge 0) {
        $b = $script:BuildListe[$i]
        return @{ st = 'Y'; k = 'Eski Android geliştirme çıktıları'; r = "Korumalı proje içindeki $($b.Type) derleme çıktısı ($($b.Path)); yeniden oluşturulabilir."; alt = 'build'; kok = $b.Path }
    }
    if ($kx -match '\\\$Recycle\.Bin\\') {
        return @{ st = 'Y'; k = 'Çöp kutusu'; r = 'Geri Dönüşüm Kutusu içeriği.'; alt = 'cop' }
    }
    $i = [DiskAnaliz.PathUtil]::FindLongestRoot($Yol, $script:KokDizileri.Proje)
    if ($i -ge 0) {
        $pj = $script:ProjeListe[$i]
        return @{ st = 'K'; k = 'Sistem ve korunan alanlar'; r = "Korumalı proje klasörü ($($pj.Type)): $($pj.Path). Otomatik silme önerilmez."; alt = 'proje' }
    }
    foreach ($kp in $script:Koruma) {
        if ($kx -match $kp.Rx) {
            return @{ st = 'K'; k = 'Sistem ve korunan alanlar'; r = "Korunan alan: $($kp.Ad). Analiz edildi, silme önerilmez."; alt = 'koruma' }
        }
    }
    if ($kx -match $script:RxSistem) {
        return @{ st = 'K'; k = 'Sistem ve korunan alanlar'; r = 'Windows sistem dosyası veya kurulu bir programın dosyası. Elle silinmemeli; gerekirse programı kendi kaldırıcısıyla yönetin.'; alt = 'sistem' }
    }
    if ($kx -match '\\AppData\\') {
        return @{ st = 'K'; k = 'Sistem ve korunan alanlar'; r = 'Uygulama verisi (AppData). Programın ayarları/verisi olabilir; yalnızca uygulamanın kendi ayarından temizleyin.'; alt = 'appdata' }
    }
    return @{ st = $VarsayilanDurum; k = $VarsayilanKategori; r = $VarsayilanGerekce; alt = $null }
}

# ---------------------------------------------------------------------------
# 3) Surucu bilgileri
# ---------------------------------------------------------------------------
function Get-DiskTuru([string]$h) {
    try {
        $part = Get-Partition -DriveLetter $h -ErrorAction Stop | Select-Object -First 1
        $pd = Get-PhysicalDisk -ErrorAction Stop | Where-Object { [string]$_.DeviceId -eq [string]$part.DiskNumber } | Select-Object -First 1
        if ($pd -and $pd.MediaType -and [string]$pd.MediaType -ne 'Unspecified') { return [string]$pd.MediaType }
    }
    catch { }
    switch ($h) { 'C' { return 'SSD' } 'D' { return 'HDD' } default { return 'Bilinmiyor' } }
}

$yonetici = $false
try {
    $yonetici = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
catch { }

$masaustu = [Environment]::GetFolderPath('Desktop')
if (-not $CiktiKlasoru) { $CiktiKlasoru = Join-Path $masaustu 'Disk_Analiz_Raporu' }
New-Item -ItemType Directory -Path $CiktiKlasoru -Force -ErrorAction Stop | Out-Null
$CiktiKlasoru = (Get-Item -LiteralPath $CiktiKlasoru).FullName

$sc = New-Object DiskAnaliz.Scanner
[void]$sc.Exclude.Add($CiktiKlasoru)

$SuruculerBilgi = @()
foreach ($hRaw in $Suruculer) {
    $h = ([string]$hRaw).Trim().TrimEnd(':', '\').ToUpper()
    if ($h.Length -ne 1) { continue }
    $kok = "$($h):\"
    if (-not (Test-Path -LiteralPath $kok)) {
        Write-Host "  $($h): sürücüsü bulunamadı, atlanıyor." -ForegroundColor Yellow
        $Notlar.Add("$($h): sürücüsü bulunamadı ve taranmadı.")
        continue
    }
    $toplam = 0; $bos = 0; $etiket = ''; $fs = ''
    try {
        $ld = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$($h):'" -ErrorAction Stop
        $toplam = [long]$ld.Size; $bos = [long]$ld.FreeSpace; $etiket = [string]$ld.VolumeName; $fs = [string]$ld.FileSystem
    }
    catch {
        $di = New-Object System.IO.DriveInfo $h
        $toplam = [long]$di.TotalSize; $bos = [long]$di.TotalFreeSpace; $etiket = [string]$di.VolumeLabel; $fs = [string]$di.DriveFormat
    }
    $SuruculerBilgi += [pscustomobject]@{ Harf = $h; Kok = $kok; Toplam = $toplam; Bos = $bos; Kullanilan = ($toplam - $bos); Etiket = $etiket; DosyaSistemi = $fs; Tur = (Get-DiskTuru $h) }
}
if ($SuruculerBilgi.Count -eq 0) { Write-Host 'Taranacak sürücü yok.' -ForegroundColor Red; return }

foreach ($d in $SuruculerBilgi) {
    Write-Host ''
    Write-Host ("[{0}:] {1}  Toplam {2:N2} GB | Kullanılan {3:N2} GB | Boş {4:N2} GB" -f $d.Harf, $d.Tur, ($d.Toplam / $GB), ($d.Kullanilan / $GB), ($d.Bos / $GB)) -ForegroundColor Green
    Write-Host "  Taranıyor (HDD'de uzun sürebilir)..."
    $t0 = Get-Date
    $sc.Scan($d.Kok)
    Write-Host ("  Bitti: {0:N0} sn" -f ((Get-Date) - $t0).TotalSeconds)
}

# ---------------------------------------------------------------------------
# 4) Bilinen konumlar
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host 'Bilinen geçici/önbellek konumları inceleniyor...' -ForegroundColor Cyan
$L = $env:LOCALAPPDATA; $R = $env:APPDATA; $U = $env:USERPROFILE; $W = $env:windir; $PD = $env:ProgramData
$SysDrv = $env:SystemDrive; if (-not $SysDrv) { $SysDrv = 'C:' }

# --- Windows gecici dosyalari (G)
$kWin = 'Windows geçici dosyaları'
Add-Bilinen "$L\Temp" G $kWin 'Kullanıcı geçici klasörü (%TEMP%). Programların kurulum/çalışma artıkları; açık programların kullandığı dosyalar silinemez, gerisi güvenle temizlenir.' 'Evet'
Add-Bilinen "$W\Temp" G $kWin 'Windows geçici klasörü. Disk Temizleme ile güvenle temizlenir.' 'Evet'
Add-Bilinen "$L\Microsoft\Windows\INetCache" G $kWin 'Internet Explorer/Edge eski motoru ve Windows bileşenlerinin web önbelleği.' 'Evet'
Add-Bilinen "$L\Microsoft\Windows\WER" G $kWin 'Windows Hata Bildirimi raporları. Yalnızca sorun bildirimi için gerekir.' 'Evet'
Add-Bilinen "$PD\Microsoft\Windows\WER" G $kWin 'Sistem geneli Windows Hata Bildirimi raporları.' 'Evet'
Add-Bilinen "$L\CrashDumps" G $kWin 'Uygulama çökme dökümleri; yalnızca hata ayıklamada gerekir.' 'Evet'
Add-Bilinen "$W\Minidump" G $kWin 'Mavi ekran mini dökümleri; yalnızca arıza teşhisinde gerekir.' 'Evet'
Add-Bilinen "$W\LiveKernelReports" Y $kWin 'Çekirdek canlı raporları; genelde gereksizdir ama donanım sorunu teşhisinde kullanılabilir.' 'Evet'
try {
    $exp = "$L\Microsoft\Windows\Explorer"
    $thumbs = @(Get-ChildItem -LiteralPath $exp -Force -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'thumbcache_*.db' -or $_.Name -like 'iconcache_*.db' })
    if ($thumbs.Count -gt 0) {
        $tb = ($thumbs | Measure-Object -Property Length -Sum).Sum
        $tl = ($thumbs | Sort-Object LastWriteTime -Descending | Select-Object -First 1).LastWriteTime
        $script:Bilinen.Add([pscustomobject]@{ Yol = "$exp\thumbcache_*.db"; Durum = 'G'; Kategori = $kWin; Oneri = $kWin })
        foreach ($tf in $thumbs) { $script:Bilinen.Add([pscustomobject]@{ Yol = $tf.FullName; Durum = 'G'; Kategori = $kWin; Oneri = $kWin }) }
        if ($tb -ge 1MB) {
            Add-Bulgu -Yol "$exp\thumbcache_*.db" -Boyut $tb -Tarih $tl -Durum G -Kategori $kWin -Gerekce 'Küçük resim ve simge önbelleği. Windows klasörleri açtıkça yeniden oluşturur.' -Yeniden 'Evet' -Tur 'Dosya grubu' -Adet $thumbs.Count -Nasil 'Disk Temizleme > "Küçük resimler" seçeneği.'
        }
    }
}
catch { }

# --- Uygulama onbellekleri (G)
$kApp = 'Uygulama önbellekleri'
$tarayicilar = @(
    @{ Ad = 'Google Chrome'; Yol = "$L\Google\Chrome\User Data" }
    @{ Ad = 'Microsoft Edge'; Yol = "$L\Microsoft\Edge\User Data" }
    @{ Ad = 'Brave'; Yol = "$L\BraveSoftware\Brave-Browser\User Data" }
    @{ Ad = 'Vivaldi'; Yol = "$L\Vivaldi\User Data" }
    @{ Ad = 'Opera'; Yol = "$L\Opera Software\Opera Stable" }
    @{ Ad = 'Opera GX'; Yol = "$L\Opera Software\Opera GX Stable" }
)
foreach ($b in $tarayicilar) {
    if (-not (Test-Path -LiteralPath $b.Yol)) { continue }
    $profiller = @(Get-ChildItem -LiteralPath $b.Yol -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'Default' -or $_.Name -like 'Profile *' -or $_.Name -eq 'Guest Profile' } | ForEach-Object { $_.FullName })
    $profiller += $b.Yol
    foreach ($pr in $profiller) {
        foreach ($alt in @('Cache', 'Code Cache', 'GPUCache', 'ShaderCache', 'GrShaderCache', 'GraphiteDawnCache', 'DawnCache')) {
            Add-Bilinen "$pr\$alt" G $kApp "$($b.Ad) önbelleği. Şifreler, yer imleri ve geçmiş bu klasörde DEĞİLDİR; tarayıcı yeniden oluşturur." 'Evet' "Tarayıcı önbellekleri" 'Tarayıcıda Ctrl+Shift+Del > "Önbelleğe alınmış resimler ve dosyalar".'
        }
    }
}
Add-Bilinen "$L\Mozilla\Firefox\Profiles\*\cache2" G $kApp 'Firefox önbelleği; şifre ve yer imleri burada değildir.' 'Evet' 'Tarayıcı önbellekleri' 'Firefox > Ayarlar > Gizlilik > Çerezler ve site verileri > Verileri temizle (yalnızca önbellek).'
Add-Bilinen "$L\Mozilla\Firefox\Profiles\*\startupCache" G $kApp 'Firefox başlangıç önbelleği.' 'Evet' 'Tarayıcı önbellekleri'
foreach ($alt in @('Cache', 'CachedData', 'CachedExtensionVSIXs', 'GPUCache', 'Code Cache', 'logs')) {
    Add-Bilinen "$R\Code\$alt" G $kApp 'Visual Studio Code önbelleği/günlükleri; ayarlar ve eklentiler etkilenmez.' 'Evet' 'VS Code / Discord / Slack önbellekleri' 'VS Code kapalıyken temizlenebilir.'
}
foreach ($app in @('discord', 'Slack', 'Microsoft\Teams')) {
    foreach ($alt in @('Cache', 'Code Cache', 'GPUCache')) {
        Add-Bilinen "$R\$app\$alt" G $kApp "$app uygulama önbelleği; mesajlar sunucudadır." 'Evet' 'VS Code / Discord / Slack önbellekleri' 'Uygulama kapalıyken temizlenebilir.'
    }
}
Add-Bilinen "$L\D3DSCache" G $kApp 'DirectX gölgelendirici önbelleği; oyun/uygulama açılınca yeniden oluşur.' 'Evet' 'Ekran kartı gölgelendirici önbellekleri' 'Disk Temizleme > "DirectX Gölgelendirici Önbelleği".'
Add-Bilinen "$L\NVIDIA\DXCache" G $kApp 'NVIDIA gölgelendirici önbelleği.' 'Evet' 'Ekran kartı gölgelendirici önbellekleri'
Add-Bilinen "$L\NVIDIA\GLCache" G $kApp 'NVIDIA OpenGL önbelleği.' 'Evet' 'Ekran kartı gölgelendirici önbellekleri'
Add-Bilinen "$L\AMD\DxCache" G $kApp 'AMD gölgelendirici önbelleği.' 'Evet' 'Ekran kartı gölgelendirici önbellekleri'
Add-Bilinen "$L\AMD\DxcCache" G $kApp 'AMD gölgelendirici önbelleği.' 'Evet' 'Ekran kartı gölgelendirici önbellekleri'
Add-Bilinen "$R\Adobe\Common\Media Cache Files" G $kApp 'Adobe medya önbelleği (Premiere/After Effects). Proje dosyaları etkilenmez.' 'Evet' 'Adobe medya önbelleği' 'Adobe uygulamasında Tercihler > Medya Önbelleği > Sil.'
Add-Bilinen "$R\Adobe\Common\Media Cache" G $kApp 'Adobe medya önbellek veritabanı.' 'Evet' 'Adobe medya önbelleği'
Add-Bilinen "$L\Spotify\Data" Y $kApp 'Spotify önbelleği; çevrimdışı indirilen şarkılar da burada olabilir.' 'Evet (yeniden indirilir)' '' 'Spotify > Ayarlar > Depolama > Önbelleği temizle.'
Add-Bilinen "$L\Steam\htmlcache" G $kApp 'Steam tarayıcı önbelleği; oyunlar etkilenmez.' 'Evet'
# Ableton onbellegi korumali yazilima ait oldugu icin G degil Y
foreach ($ab in @("$R\Ableton\Cache", "$L\Ableton\Cache", "$U\Documents\Ableton\Cache")) {
    Add-Bilinen $ab Y $kApp 'Ableton Live çözümleme (decoding) önbelleği. Yeniden oluşturulabilir; ancak Ableton korunan yazılımınız olduğu için onayınıza bırakıldı. Projeler ve örnekler bu klasörde değildir.' 'Evet' 'Ableton önbelleği (onaylı)' 'Ableton > Tercihler > File/Folder > Decoding Cache > Cleanup.'
}

# --- Windows guncelleme kalintilari
$kUpd = 'Windows güncelleme kalıntıları'
Add-Bilinen "$W\SoftwareDistribution\Download" G $kUpd 'Zaten kurulmuş güncellemelerin indirilmiş paketleri. Gerekirse Windows yeniden indirir.' 'Evet' 'Windows Update temizliği' 'Disk Temizleme > "Sistem dosyalarını temizle" > "Windows Update Temizleme" ve "Geçici dosyalar".'
Add-Bilinen "$W\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache" G $kUpd 'Teslim İyileştirme (Delivery Optimization) önbelleği.' 'Evet' 'Windows Update temizliği' 'Disk Temizleme > "Teslim İyileştirme Dosyaları".'
Add-Bilinen "$SysDrv\Windows.old" Y $kUpd 'Önceki Windows kurulumu. Geri dönmek isterseniz gereklidir; aksi halde büyük alan kazandırır.' 'Hayır' 'Önceki Windows yüklemeleri (Windows.old)' 'Disk Temizleme > "Sistem dosyalarını temizle" > "Önceki Windows yüklemeleri".'
Add-Bilinen "$SysDrv\`$Windows.~BT" Y $kUpd 'Windows yükseltme geçici klasörü. Yükseltme tamamlandıysa gereksizdir.' 'Hayır' 'Önceki Windows yüklemeleri (Windows.old)' 'Disk Temizleme > "Geçici Windows yükleme dosyaları".'
Add-Bilinen "$SysDrv\`$Windows.~WS" Y $kUpd 'Windows yükseltme (Media Creation Tool) klasörü.' 'Hayır' 'Önceki Windows yüklemeleri (Windows.old)' 'Disk Temizleme > "Geçici Windows yükleme dosyaları".'
Add-Bilinen "$SysDrv\`$WinREAgent" Y $kUpd 'Kurtarma ortamı güncelleme artığı.' 'Hayır'
Add-Bilinen "$SysDrv\`$GetCurrent" Y $kUpd 'Windows yükseltme yardımcısı artığı.' 'Hayır'
Add-Bilinen "$SysDrv\ESD" Y $kUpd 'Windows kurulum görüntüsü (ESD) klasörü.' 'Hayır'
Add-Bilinen "$W\Logs\CBS" Y 'Log dosyaları' 'Windows bileşen (CBS) günlükleri; çoğunlukla gereksizdir.' 'Evet'
Add-Bilinen "$W\WinSxS" K 'Sistem ve korunan alanlar' 'Windows bileşen deposu. Boyutu sabit bağlantılar (hard link) nedeniyle olduğundan büyük görünür. ASLA elle silinmez; yalnızca DISM /StartComponentCleanup ile küçültülebilir.' 'Hayır' '' 'Dokunmayın.'
Add-Bilinen "$W\Installer" K 'Sistem ve korunan alanlar' 'Kurulu programların onarım/kaldırma için gereken MSI önbelleği. Silinirse programlar güncellenemez/kaldırılamaz.' 'Hayır' '' 'Dokunmayın.'
Add-Bilinen "$W\System32\DriverStore" K 'Sistem ve korunan alanlar' 'Sürücü deposu. Elle silinmez.' 'Hayır' '' 'Dokunmayın.'
Add-Bilinen "$PD\Package Cache" K 'Sistem ve korunan alanlar' 'Visual Studio ve diğer programların kurulum önbelleği; güncelleme/onarım için gerekir.' 'Hayır' '' 'Dokunmayın.'

# --- Eski kurulum dosyalari
$kKur = 'Eski kurulum dosyaları'
foreach ($drv in @('Intel', 'AMD', 'NVIDIA', 'Drivers', 'Realtek')) {
    Add-Bilinen "$SysDrv\$drv" Y $kKur "Ayıklanmış sürücü kurulum dosyaları ($drv). Sürücü kuruluysa çoğunlukla gereksizdir; içinde başka şey olmadığını kontrol edin." 'Evet (üretici sitesinden)'
}

# --- Cop kutusu
foreach ($d in $SuruculerBilgi) {
    $cop = '{0}:\$Recycle.Bin' -f $d.Harf
    Add-Bilinen $cop Y 'Çöp kutusu' 'Geri Dönüşüm Kutusu. Siz zaten silmişsiniz ama yanlışlıkla silinmiş önemli bir dosya olabilir; boşaltmadan önce göz atın. (Diğer kullanıcıların çöp kutuları ölçülemez.)' 'Hayır' 'Geri Dönüşüm Kutusunu boşaltma'
}

# --- Gelistirme onbellekleri
$kDev = 'Gradle ve diğer geliştirme önbellekleri'
$kAnd = 'Eski Android geliştirme çıktıları'
$gradleHome = if ($env:GRADLE_USER_HOME) { $env:GRADLE_USER_HOME } else { "$U\.gradle" }
Add-Bilinen "$gradleHome\caches" G $kDev 'Gradle bağımlılık ve derleme önbelleği. Proje dosyası içermez; sonraki derlemede internetten yeniden indirilir (ilk derleme uzun sürer).' 'Evet (internet gerekir)' 'Gradle önbelleği' 'Android Studio''yu kapatın, proje klasöründe "gradlew --stop" çalıştırın, sonra .gradle\caches klasörünü kendiniz silin.'
Add-Bilinen "$gradleHome\daemon" G $kDev 'Gradle arka plan süreci günlükleri.' 'Evet' 'Gradle önbelleği'
Add-Bilinen "$gradleHome\wrapper\dists" Y $kDev 'İndirilmiş Gradle sürümleri. Kullanılmayan eski sürümler gereksizdir; kullanılan sürüm silinirse yeniden indirilir.' 'Evet (internet gerekir)' 'Gradle önbelleği'
Add-Bilinen "$gradleHome\.tmp" G $kDev 'Gradle geçici dosyaları.' 'Evet' 'Gradle önbelleği'
Add-Bilinen "$U\.android\cache" G $kDev 'Android araçları önbelleği.' 'Evet' 'Gradle önbelleği'
Add-Bilinen "$U\.android\build-cache" G $kDev 'Eski Android Gradle Plugin derleme önbelleği.' 'Evet' 'Gradle önbelleği'
Add-Bilinen "$L\Pub\Cache" G $kDev 'Flutter/Dart paket önbelleği (pub cache). "flutter pub get" ile yeniden indirilir. Kendi projeleriniz burada değildir.' 'Evet (internet gerekir)' 'Flutter Pub önbelleği' 'Terminalde "flutter pub cache clean" veya klasörü elle silin; ardından projelerde "flutter pub get".'
Add-Bilinen "$R\Pub\Cache" G $kDev 'Flutter/Dart paket önbelleği (eski konum).' 'Evet (internet gerekir)' 'Flutter Pub önbelleği'
Add-Bilinen "$U\.dartServer" G $kDev 'Dart analiz sunucusu önbelleği.' 'Evet' 'Flutter Pub önbelleği'
Add-Bilinen "$L\.dartServer" G $kDev 'Dart analiz sunucusu önbelleği.' 'Evet' 'Flutter Pub önbelleği'
Add-Bilinen "$L\npm-cache" G $kDev 'npm paket önbelleği.' 'Evet (internet gerekir)' 'npm / Yarn / pip / Maven / NuGet önbellekleri' '"npm cache clean --force".'
Add-Bilinen "$R\npm-cache" G $kDev 'npm paket önbelleği.' 'Evet (internet gerekir)' 'npm / Yarn / pip / Maven / NuGet önbellekleri'
Add-Bilinen "$L\Yarn\Cache" G $kDev 'Yarn paket önbelleği.' 'Evet (internet gerekir)' 'npm / Yarn / pip / Maven / NuGet önbellekleri' '"yarn cache clean".'
Add-Bilinen "$L\pip\Cache" G $kDev 'Python pip önbelleği.' 'Evet (internet gerekir)' 'npm / Yarn / pip / Maven / NuGet önbellekleri' '"pip cache purge".'
Add-Bilinen "$U\.m2\repository" G $kDev 'Maven yerel deposu (önbellek).' 'Evet (internet gerekir)' 'npm / Yarn / pip / Maven / NuGet önbellekleri'
Add-Bilinen "$U\.nuget\packages" G $kDev 'NuGet paket önbelleği.' 'Evet (internet gerekir)' 'npm / Yarn / pip / Maven / NuGet önbellekleri' '"dotnet nuget locals all --clear".'
Add-Bilinen "$L\NuGet\v3-cache" G $kDev 'NuGet HTTP önbelleği.' 'Evet' 'npm / Yarn / pip / Maven / NuGet önbellekleri'
Add-Bilinen "$L\Docker\wsl" Y $kDev 'Docker sanal diski; imajlar ve konteynerler içindedir.' 'Kısmen' '' 'Docker Desktop > Troubleshoot > Clean / "docker system prune".'
Add-Bilinen "$L\Packages\CanonicalGroupLimited*" K 'Sistem ve korunan alanlar' 'WSL Linux dağıtımı sanal diski; içindeki dosyalarınız kaybolur.' 'Hayır' '' 'Dokunmayın.'

# Android Studio surum klasorleri
foreach ($kokAS in @("$L\Google", "$R\Google")) {
    $asDirs = @(Get-ChildItem -LiteralPath $kokAS -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'AndroidStudio*' })
    if ($asDirs.Count -eq 0) { continue }
    $sirali = @($asDirs | Sort-Object { $v = ($_.Name -replace '^AndroidStudio(Preview)?', ''); try { [version]$v } catch { [version]'0.0' } })
    $enYeni = $sirali[-1]
    foreach ($a in $sirali) {
        if ($a.FullName -eq $enYeni.FullName) {
            if ($kokAS -eq "$L\Google") {
                foreach ($alt in @('caches', 'index', 'log', 'tmp')) {
                    Add-Bilinen (Join-Path $a.FullName $alt) G $kDev "Güncel Android Studio ($($a.Name)) önbelleği/dizini. 'File > Invalidate Caches' ile aynı etki; projeler etkilenmez." 'Evet' 'Android Studio önbelleği' 'Android Studio > File > Invalidate Caches... > Invalidate and Restart.'
                }
            }
        }
        else {
            $ne = if ($kokAS -eq "$R\Google") { 'ayarları' } else { 'önbelleği/dizini' }
            Add-Bilinen $a.FullName Y $kAnd "Eski Android Studio sürümü $ne ($($a.Name)). Güncel sürüm: $($enYeni.Name). Ayarlar zaten taşındıysa gereksizdir." 'Hayır (eski sürüm)' 'Eski Android Studio sürüm klasörleri'
        }
    }
}
Get-ChildItem -LiteralPath $U -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -like '.AndroidStudio*' } | ForEach-Object {
    Add-Bilinen $_.FullName Y $kAnd 'Android Studio 4.0 ve öncesine ait eski ayar/önbellek klasörü.' 'Hayır (eski sürüm)' 'Eski Android Studio sürüm klasörleri'
}

# AVD (emulatorler)
$avdKok = if ($env:ANDROID_AVD_HOME) { $env:ANDROID_AVD_HOME } else { "$U\.android\avd" }
Get-ChildItem -LiteralPath $avdKok -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -like '*.avd' } | ForEach-Object {
    Add-Bilinen $_.FullName Y $kAnd "Android emülatörü ($($_.BaseName)). Emülatördeki uygulama verileri kaybolur; Device Manager'dan yeniden oluşturulabilir." 'Kısmen' 'Android emülatörleri ve sistem görüntüleri' 'Android Studio > Device Manager > emülatör > Delete.'
}

# Android SDK
$sdkAdaylar = @($env:ANDROID_HOME, $env:ANDROID_SDK_ROOT, "$L\Android\Sdk", 'D:\Android\Sdk', 'D:\Android\sdk', 'D:\AndroidSDK', 'D:\Sdk', 'C:\Android\Sdk') | Where-Object { $_ }
$sdkler = @($sdkAdaylar | Where-Object { Test-Path -LiteralPath $_ -PathType Container } | ForEach-Object { (Get-Item -LiteralPath $_ -Force).FullName } | Sort-Object -Unique)
foreach ($sdk in $sdkler) {
    Get-ChildItem -LiteralPath "$sdk\system-images" -Directory -Force -ErrorAction SilentlyContinue | ForEach-Object {
        Add-Bilinen $_.FullName Y $kAnd "Emülatör sistem görüntüsü ($($_.Name)). Bu sürümü kullanan emülatör yoksa gereksizdir; SDK Manager'dan yeniden indirilebilir." 'Evet (internet gerekir)' 'Android emülatörleri ve sistem görüntüleri' 'Android Studio > SDK Manager > SDK Platforms > "Show Package Details" > işareti kaldırın.'
    }
    Add-Bilinen "$sdk\.temp" G $kDev 'Android SDK Manager geçici indirme klasörü.' 'Evet' 'Android Studio önbelleği'
    Add-Bilinen "$sdk\temp" G $kDev 'Android SDK Manager geçici indirme klasörü.' 'Evet' 'Android Studio önbelleği'
    Add-Bilinen $sdk K 'Sistem ve korunan alanlar' 'Android SDK. Derleme için gereklidir; yalnızca SDK Manager üzerinden yönetin.' 'Evet (SDK Manager)' '' 'Dokunmayın; gerekirse SDK Manager kullanın.'
}

# Flutter SDK
try {
    $fl = Get-Command flutter -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($fl -and $fl.Source) {
        $flSdk = Split-Path (Split-Path $fl.Source -Parent) -Parent
        Add-Bilinen "$flSdk\bin\cache" Y $kDev 'Flutter SDK araç önbelleği (Dart SDK, motor dosyaları). Flutter çalışmak için buna ihtiyaç duyar; silinirse ilk komutta yeniden indirilir.' 'Evet (internet gerekir)'
        Add-Bilinen $flSdk K 'Sistem ve korunan alanlar' 'Flutter SDK. Projelerinizin derlenmesi için gereklidir.' 'Hayır' '' 'Dokunmayın.'
    }
}
catch { }

# Sistem dosyalari (bilgi)
foreach ($sf in @('pagefile.sys', 'hiberfil.sys', 'swapfile.sys')) {
    $it = Get-Item -LiteralPath "$SysDrv\$sf" -Force -ErrorAction SilentlyContinue
    if ($it) {
        $ac = switch ($sf) { 'pagefile.sys' { 'Sanal bellek (sayfa) dosyası.' } 'hiberfil.sys' { 'Hazırda bekletme / Hızlı Başlangıç dosyası.' } default { 'Modern uygulama takas dosyası.' } }
        Add-Bulgu -Yol $it.FullName -Boyut $it.Length -Tarih $it.LastWriteTime -Durum K -Kategori 'Sistem ve korunan alanlar' -Gerekce "$ac Windows tarafından kullanılır; elle silinemez. Küçültmek ayar değişikliği gerektirir (bu analiz ayar değiştirmez)." -Yeniden 'Hayır' -Tur 'Dosya'
    }
}

# Bilinen K/Y kokleri satir olarak eklenmis olabilir; siniflandirma koklerini guncelle
$BuildListe = @(); $ProjeListe = @()
Update-Kokler

# ---------------------------------------------------------------------------
# 5) Projeler ve derleme ciktilari
# ---------------------------------------------------------------------------
Write-Host 'Projeler ve derleme çıktıları değerlendiriliyor...' -ForegroundColor Cyan
$ProjeListe = @($sc.Projects | Where-Object {
        $_.Path -notmatch $RxGelistirmeHaric -and ([DiskAnaliz.PathUtil]::FindLongestRoot($_.Path, $KokDizileri.Bilinen) -lt 0)
    })
$BuildListe = @($sc.Builds | Where-Object {
        ($_.Project -notmatch $RxGelistirmeHaric) -and ($_.Path -notmatch '\\(AppData|\.pub-cache|\.gradle\\caches)\\') -and
        ([DiskAnaliz.PathUtil]::FindLongestRoot($_.Path, $KokDizileri.Bilinen) -lt 0)
    })
Update-Kokler

$buildToplamProje = @{}
foreach ($b in $BuildListe) {
    if (-not $buildToplamProje.ContainsKey($b.Project)) { $buildToplamProje[$b.Project] = [long]0 }
    $buildToplamProje[$b.Project] += $b.Size
    $yas = Get-Gun $b.LastWrite
    $komut = switch ($b.Type) {
        'Flutter' { 'Proje klasöründe "flutter clean" çalıştırın.' }
        'Gradle' { 'Android Studio > Build > Clean Project veya "gradlew clean".' }
        'Node.js' { 'node_modules klasörü "npm install" ile yeniden oluşturulur.' }
        '.NET' { 'Visual Studio > Build > Clean Solution / "dotnet clean".' }
        default { '' }
    }
    $kat = if ($b.Type -in @('Flutter', 'Gradle')) { $kAnd } else { $kDev }
    $eskiNot = if ($yas -ne $null -and $yas -gt 180) { " Son derleme yaklaşık $yas gün önce." } else { '' }
    $projeAd = Split-Path $b.Project -Leaf
    Add-Bulgu -Yol $b.Path -Boyut $b.Size -Tarih $b.LastWrite -Durum Y -Kategori $kat `
        -Gerekce ("Korumalı proje '$projeAd' içindeki $($b.Type) derleme çıktısı. Kaynak kod değildir ve yeniden oluşturulabilir; ancak projeleriniz korumalı olduğu için otomatik silme önerilmez.$eskiNot") `
        -Yeniden 'Evet (yeniden derlenir)' -Oneri 'Proje derleme çıktıları (clean)' -Nasil $komut -Adet $b.Files
}

$ProjelerJson = New-Object System.Collections.Generic.List[object]
foreach ($pj in $ProjeListe) {
    $yas = Get-Gun $pj.LastWrite
    $bt = if ($buildToplamProje.ContainsKey($pj.Path)) { [long]$buildToplamProje[$pj.Path] } else { [long]0 }
    $eski = ($yas -ne $null -and $yas -gt $EskiProjeGun)
    $ProjelerJson.Add([ordered]@{ p = $pj.Path; t = $pj.Type; s = [long]$pj.Size; f = [long]$pj.Files; d = (Format-Tarih $pj.LastWrite); g = $yas; b = $bt; eski = $eski; dr = (Get-Surucu $pj.Path); st = 'K' })
    if ($eski) {
        Add-Bulgu -Yol $pj.Path -Boyut $pj.Size -Tarih $pj.LastWrite -Durum K -Kategori 'Kullanılmayan eski proje klasörleri' `
            -Gerekce ("Korumalı proje ($($pj.Type)); yaklaşık $yas gündür değişmemiş. Silme önerilmez; arşivleme (harici diske kopyalama) düşünülebilir. İçindeki yeniden oluşturulabilir derleme çıktısı: {0:N2} GB." -f ($bt / $GB)) `
            -Yeniden 'Hayır (kaynak kod)' -Oneri 'Eski projeleri arşivleme (korumalı)' -Adet $pj.Files
    }
}

# ---------------------------------------------------------------------------
# 6) Etiketli dosyalar (APK, ZIP, kurulum, log, yedek, video, ses...)
# ---------------------------------------------------------------------------
Write-Host 'Dosya kategorileri sınıflandırılıyor...' -ForegroundColor Cyan
$etiketBilgi = @{
    apk   = @{ k = 'Kullanılmayan APK ve ZIP dosyaları'; r = 'Derlenmiş Android paketi (APK/AAB). Proje dışında genelde eski test/indirme kopyasıdır; ama yayınlanmış bir sürümün tek kopyası olabilir.'; o = 'APK / AAB dosyaları' }
    arsiv = @{ k = 'Kullanılmayan APK ve ZIP dosyaları'; r = 'Arşiv dosyası. İçeriği başka yerde açılmış olabilir; tek yedek de olabilir.'; o = 'ZIP / RAR / 7z arşivleri' }
    kalip = @{ k = 'Eski kurulum dosyaları'; r = 'Disk kalıbı (ISO/IMG) veya sanal disk (VHD/VMDK). Kurulum medyası ya da sanal makine diski olabilir.'; o = 'ISO / disk kalıpları' }
    kurulum = @{ k = 'Eski kurulum dosyaları'; r = 'Kurulum dosyası. Program kurulduysa genelde gerekmez; lisanslı veya artık indirilemeyen sürüm olabilir.'; o = 'Kurulum dosyaları (setup/msi)' }
    log   = @{ k = 'Log dosyaları'; r = 'Büyük günlük dosyası. Çoğunlukla gereksizdir; çalışan bir programın aktif günlüğü olabilir.'; o = 'Log dosyaları' }
    dump  = @{ k = 'Log dosyaları'; r = 'Hata dökümü (crash dump). Yalnızca hata ayıklamada gerekir.'; o = 'Log dosyaları' }
    yedek = @{ k = 'Gereksiz olabilecek yedekler'; r = 'Yedek dosyası (.bak/.old). Asıl dosyanın tek yedeği olabilir.'; o = 'Yedek dosya ve klasörleri' }
    video = @{ k = 'Büyük video ve ses dosyaları'; r = 'Büyük video dosyası. Kişisel içerik olabilir.'; o = 'Büyük video dosyaları' }
    ses   = @{ k = 'Büyük video ve ses dosyaları'; r = 'Büyük ses dosyası. Kayıt veya proje sesi olabilir.'; o = 'Büyük ses dosyaları' }
}
foreach ($f in $sc.Tagged) {
    $eb = $etiketBilgi[$f.Tag]
    if (-not $eb) { continue }
    $s = Get-Sinif -Yol $f.Path -Dosya $true -VarsayilanDurum 'Y' -VarsayilanGerekce $eb.r -VarsayilanKategori $eb.k
    if ($s.alt -in @('bilinen', 'build')) { continue }   # zaten ust klasor olarak sayildi
    $kat = $eb.k; $ger = $eb.r
    if ($s.st -eq 'K') { $ger = "$($eb.r) $($s.r)" }
    elseif ($s.alt -eq 'cop') { $kat = 'Çöp kutusu'; $ger = $s.r }
    $yas = Get-Gun $f.LastWrite
    if ($yas -ne $null -and $s.st -ne 'K') { $ger += " Son değişiklik $yas gün önce." }
    $rg = switch ($f.Tag) { 'apk' { 'Kaynak koddan yeniden derlenebilir' } 'kurulum' { 'Genelde yeniden indirilebilir' } 'kalip' { 'Genelde yeniden indirilebilir' } 'log' { 'Gerek yok' } 'dump' { 'Gerek yok' } default { 'Hayır' } }
    Add-Bulgu -Yol $f.Path -Boyut $f.Size -Tarih $f.LastWrite -Durum $s.st -Kategori $kat -Gerekce $ger -Yeniden $rg -Tur 'Dosya' -Oneri $(if ($s.st -eq 'K') { 'Korunan dosyalar (bilgi)' } else { $eb.o })
}

# Hassas dosyalar (kimlik bilgileri) — yalnizca bilgi; icerik okunmaz
$HassasJson = New-Object System.Collections.Generic.List[object]
foreach ($f in ($sc.Sensitive | Select-Object -First 2000)) {
    if ($f.Path -match '^[A-Za-z]:\\(Windows|Program Files|Program Files \(x86\))\\') { continue }
    $HassasJson.Add([ordered]@{ p = $f.Path; s = [long]$f.Size; d = (Format-Tarih $f.LastWrite); dr = (Get-Surucu $f.Path); st = 'K' })
}

# ---------------------------------------------------------------------------
# 7) Eski indirmeler
# ---------------------------------------------------------------------------
Write-Host 'İndirilenler klasörü inceleniyor...' -ForegroundColor Cyan
$indirmeKlasorleri = @()
try { $sp = (New-Object -ComObject Shell.Application).NameSpace('shell:Downloads').Self.Path; if ($sp) { $indirmeKlasorleri += $sp } } catch { }
$indirmeKlasorleri += "$U\Downloads"
foreach ($d in $SuruculerBilgi) { foreach ($n in @('Downloads', 'İndirilenler', 'Indirilenler', 'Download')) { $indirmeKlasorleri += "$($d.Harf):\$n" } }
$indirmeKlasorleri = @($indirmeKlasorleri | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Container) } | ForEach-Object { (Get-Item -LiteralPath $_ -Force).FullName } | Sort-Object -Unique)
$sinir = $simdi.AddDays(-$EskiIndirmeGun)
$kucukEskiToplam = [long]0; $kucukEskiAdet = 0
foreach ($ik in $indirmeKlasorleri) {
    Get-ChildItem -LiteralPath $ik -File -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
        if ((([int]$_.Attributes) -band 0x400000) -ne 0) { return }
        if ($_.LastWriteTime -gt $sinir -or $_.CreationTime -gt $sinir) { return }
        if ($Gorulen.Contains($_.FullName)) { return }
        if ($_.Length -lt 1MB) { $kucukEskiToplam += $_.Length; $kucukEskiAdet++; return }
        $s = Get-Sinif -Yol $_.FullName -Dosya $true -VarsayilanDurum 'Y' -VarsayilanKategori 'Eski indirmeler' -VarsayilanGerekce ''
        $yas = Get-Gun $_.LastWriteTime
        $ger = if ($s.st -eq 'K') { "İndirilenler'de $yas gündür duran dosya. $($s.r)" } else { "İndirilenler'de yaklaşık $yas gündür değişmemiş dosya. İhtiyacınız olup olmadığını kontrol edin." }
        Add-Bulgu -Yol $_.FullName -Boyut $_.Length -Tarih $_.LastWriteTime -Durum $s.st -Kategori 'Eski indirmeler' -Gerekce $ger -Yeniden 'Genelde yeniden indirilebilir' -Tur 'Dosya' -Oneri 'Eski indirmeler'
    }
}
if ($kucukEskiAdet -gt 0) { $Notlar.Add(("İndirilenler'de 1 MB altındaki {0:N0} eski dosya ({1:N1} MB) tek tek listelenmedi." -f $kucukEskiAdet, ($kucukEskiToplam / $MB))) }

# ---------------------------------------------------------------------------
# 8) Yedek klasorleri
# ---------------------------------------------------------------------------
$yedekAdaylar = @($sc.SortedDirs(100MB, 1) | Where-Object { (Split-Path $_.Path -Leaf) -match '(?i)^(backup|backups|yedek|yedekler|yedekleme|bak|_old|old|eski|\.old)$|backup|yedek' })
$yedekSecilen = New-Object System.Collections.Generic.List[string]
foreach ($yd in ($yedekAdaylar | Sort-Object { $_.Path.Length })) {
    if ([DiskAnaliz.PathUtil]::FindLongestRoot($yd.Path, [string[]]$yedekSecilen.ToArray()) -ge 0) { continue }
    $s = Get-Sinif -Yol $yd.Path -Dosya $false -VarsayilanDurum 'Y' -VarsayilanKategori 'Gereksiz olabilecek yedekler' -VarsayilanGerekce 'Yedek adlı klasör. Asıl verinin tek yedeği olabilir; başka kopyası olduğunu doğrulayın.'
    if ($s.alt -in @('bilinen', 'build', 'sistem', 'appdata')) { continue }
    $yedekSecilen.Add($yd.Path)
    $ger = if ($s.st -eq 'K') { "Yedek klasörü korunan bir alanda. $($s.r)" } else { $s.r }
    Add-Bulgu -Yol $yd.Path -Boyut $yd.Size -Tarih $yd.LastWrite -Durum $s.st -Kategori 'Gereksiz olabilecek yedekler' -Gerekce $ger -Yeniden 'Hayır' -Oneri $(if ($s.st -eq 'K') { 'Korunan dosyalar (bilgi)' } else { 'Yedek dosya ve klasörleri' }) -Adet $yd.Files
}

# ---------------------------------------------------------------------------
# 9) Tekrarlanan dosyalar
# ---------------------------------------------------------------------------
Write-Host 'Tekrarlanan dosyalar aranıyor...' -ForegroundColor Cyan
$TekrarJson = New-Object System.Collections.Generic.List[object]
$dupAdaylar = @($sc.DupCandidates | Where-Object {
        $_.Path -notmatch '^[A-Za-z]:\\(Windows|Program Files|Program Files \(x86\)|ProgramData|\$Recycle\.Bin)\\' -and
        $_.Path -notmatch '\\(AppData|\.gradle|\.m2|\.nuget|node_modules)\\' -and
        ([DiskAnaliz.PathUtil]::FindLongestRoot($_.Path, $KokDizileri.Build) -lt 0)
    })
$gruplar = @()
if ($TekrarHash) {
    Write-Host '  -TekrarHash: aynı boyuttaki dosyaların SHA256 özeti yerel olarak hesaplanıyor (uzun sürebilir)...'
    foreach ($bg in ($dupAdaylar | Group-Object Size | Where-Object { $_.Count -gt 1 })) {
        $hashli = foreach ($f in $bg.Group) {
            $h = $null
            try { $h = (Get-FileHash -LiteralPath $f.Path -Algorithm SHA256 -ErrorAction Stop).Hash } catch { }
            if ($h) { [pscustomobject]@{ F = $f; H = $h } }
        }
        foreach ($hg in (@($hashli) | Group-Object H | Where-Object { $_.Count -gt 1 })) {
            $gruplar += , @{ Yontem = 'Aynı içerik (SHA256)'; Dosyalar = @($hg.Group | ForEach-Object { $_.F }) }
        }
    }
}
else {
    foreach ($g in ($dupAdaylar | Group-Object { '{0}|{1}' -f $_.Size, $_.Name.ToLowerInvariant() } | Where-Object { $_.Count -gt 1 })) {
        $gruplar += , @{ Yontem = 'Aynı ad + aynı boyut (olası)'; Dosyalar = @($g.Group) }
    }
}
foreach ($g in $gruplar) {
    $dosyalar = @($g.Dosyalar | Sort-Object LastWrite)
    $boyut = [long]$dosyalar[0].Size
    $kopyalar = @()
    $korunanSayi = 0
    foreach ($f in $dosyalar) {
        $s = Get-Sinif -Yol $f.Path -Dosya $true -VarsayilanDurum 'Y'
        if ($s.st -eq 'K') { $korunanSayi++ }
        $kopyalar += [ordered]@{ p = $f.Path; d = (Format-Tarih $f.LastWrite); st = $s.st; dr = (Get-Surucu $f.Path) }
    }
    $israf = $boyut * ($dosyalar.Count - 1)
    $gst = if ($korunanSayi -eq $dosyalar.Count) { 'K' } else { 'Y' }
    $TekrarJson.Add([ordered]@{ ad = $dosyalar[0].Name; s = $boyut; n = $dosyalar.Count; w = [long]$israf; st = $gst; y = $g.Yontem; k = $kopyalar })
    $ger = "{0} kopya ({1}). Kazanç, bir kopya bırakılırsa hesaplanmıştır. Diğer kopyalar: {2}" -f $dosyalar.Count, $g.Yontem, (($dosyalar | Select-Object -Skip 1 | ForEach-Object { $_.Path }) -join ' | ')
    if ($gst -eq 'K') { $ger = "Tüm kopyalar korunan alanlarda (ör. ses kütüphanesi/proje). " + $ger }
    Add-Bulgu -Yol $dosyalar[0].Path -Boyut $israf -Tarih $dosyalar[0].LastWrite -Durum $gst -Kategori 'Tekrarlanan dosyalar' -Gerekce $ger -Yeniden 'Diğer kopya mevcut' -Tur 'Dosya' -Oneri 'Tekrarlanan dosyalar' -Adet $dosyalar.Count
}

# ---------------------------------------------------------------------------
# 10) Klasor ve buyuk dosya tablolari
# ---------------------------------------------------------------------------
Write-Host 'Klasör ve dosya tabloları hazırlanıyor...' -ForegroundColor Cyan
$tumKlasorler = $sc.SortedDirs(100MB, 1)
$KlasorJson = New-Object System.Collections.Generic.List[object]
$i = 0
foreach ($d in $tumKlasorler) {
    if ($i -ge 4000) { break }
    $i++
    $s = Get-Sinif -Yol $d.Path -Dosya $false -VarsayilanDurum 'N' -VarsayilanKategori '' -VarsayilanGerekce 'Karışık içerik: alt klasörlerine bakın.'
    if ($d.Denied) { $s.r = 'Erişilemedi; boyut eksik olabilir. ' + $s.r }
    $KlasorJson.Add([ordered]@{ p = $d.Path; s = [long]$d.Size; f = [long]$d.Files; d = (Format-Tarih $d.LastWrite); g = (Get-Gun $d.LastWrite); dp = $d.Depth; st = $s.st; c = $s.k; r = $s.r; dr = (Get-Surucu $d.Path) })
}
$Top50Json = @($KlasorJson | Select-Object -First 50)

$DosyaJson = New-Object System.Collections.Generic.List[object]
foreach ($f in ($sc.SortedBigFiles() | Select-Object -First 1000)) {
    $s = Get-Sinif -Yol $f.Path -Dosya $true -VarsayilanDurum 'Y' -VarsayilanKategori 'Diğer büyük dosyalar' -VarsayilanGerekce 'Türü/sahibi otomatik belirlenemedi. Bir programa ait olabilir; ne olduğunu bilmiyorsanız dokunmayın.'
    $kat = $s.k
    if ($f.Tag -and $etiketBilgi[$f.Tag] -and $s.st -ne 'K' -and $s.alt -notin @('bilinen', 'build', 'cop')) { $kat = $etiketBilgi[$f.Tag].k }
    $DosyaJson.Add([ordered]@{ p = $f.Path; s = [long]$f.Size; d = (Format-Tarih $f.LastWrite); g = (Get-Gun $f.LastWrite); e = $f.Ext; st = $s.st; c = $kat; r = $s.r; dr = (Get-Surucu $f.Path) })
    if ($f.Size -ge 100MB -and $s.alt -notin @('bilinen', 'build') -and -not $Gorulen.Contains($f.Path)) {
        Add-Bulgu -Yol $f.Path -Boyut $f.Size -Tarih $f.LastWrite -Durum $s.st -Kategori $kat -Gerekce $s.r -Yeniden $(if ($s.st -eq 'K') { 'Hayır' } else { 'Bilinmiyor' }) -Tur 'Dosya' -Oneri $(if ($s.st -eq 'K') { 'Korunan dosyalar (bilgi)' } else { 'Diğer büyük dosyalar' })
    }
}
$Top100Json = @($DosyaJson | Select-Object -First 100)

# Erisilemeyen klasorler
foreach ($dn in $sc.Denied) { $Erisilemeyen.Add([ordered]@{ p = $dn.Path; r = $dn.Reason }) }

# ---------------------------------------------------------------------------
# 11) Ozetler
# ---------------------------------------------------------------------------
function Get-Toplam($liste) {
    $l = @($liste)
    if ($l.Count -eq 0) { return [long]0 }
    $p = [string[]]@($l | ForEach-Object { $_.p })
    $s = [long[]]@($l | ForEach-Object { [long]$_.s })
    return [long][DiskAnaliz.PathUtil]::SumNonOverlap($p, $s)
}

$tumBulgular = @($Rows | Sort-Object { $_.s } -Descending)
$SurucuJson = New-Object System.Collections.Generic.List[object]
foreach ($d in $SuruculerBilgi) {
    $dr = @($tumBulgular | Where-Object { $_.dr -eq $d.Harf })
    $g = Get-Toplam @($dr | Where-Object { $_.st -eq 'G' })
    $y = Get-Toplam @($dr | Where-Object { $_.st -eq 'Y' })
    $SurucuJson.Add([ordered]@{ h = $d.Harf; tur = $d.Tur; etiket = $d.Etiket; fs = $d.DosyaSistemi; toplam = [long]$d.Toplam; kullanilan = [long]$d.Kullanilan; bos = [long]$d.Bos; g = [long]$g; y = [long]$y })
}

$KategoriJson = New-Object System.Collections.Generic.List[object]
foreach ($kt in $KategoriTanim) {
    $kr = @($tumBulgular | Where-Object { $_.c -eq $kt.ad })
    $KategoriJson.Add([ordered]@{
            ad = $kt.ad; aciklama = $kt.aciklama; adet = $kr.Count
            G = (Get-Toplam @($kr | Where-Object { $_.st -eq 'G' })); Y = (Get-Toplam @($kr | Where-Object { $_.st -eq 'Y' })); K = (Get-Toplam @($kr | Where-Object { $_.st -eq 'K' }))
        })
}

$OneriJson = New-Object System.Collections.Generic.List[object]
foreach ($og in (@($tumBulgular | Where-Object { $_.st -in @('G', 'Y') -and $_.s -gt 0 }) | Group-Object { $_.o })) {
    $grp = @($og.Group)
    $toplam = Get-Toplam $grp
    $gT = Get-Toplam @($grp | Where-Object { $_.st -eq 'G' })
    $durum = if ($gT -eq $toplam) { 'G' } elseif ($gT -gt 0) { 'GY' } else { 'Y' }
    $OneriJson.Add([ordered]@{
            ad = $og.Name; s = [long]$toplam; gs = [long]$gT; st = $durum; adet = $grp.Count
            n = ($grp | Where-Object { $_.n } | Select-Object -First 1).n
            c = ($grp | Group-Object { $_.c } | Sort-Object Count -Descending | Select-Object -First 1).Name
            drs = (($grp | ForEach-Object { $_.dr } | Sort-Object -Unique) -join ', ')
            ornek = (($grp | Select-Object -First 3 | ForEach-Object { $_.p }) -join ' | ')
        })
}
$OneriJson = @($OneriJson | Sort-Object { $_.s } -Descending | Select-Object -First 10)

$bulguCikti = @($tumBulgular | Select-Object -First 8000)
if ($tumBulgular.Count -gt 8000) { $Notlar.Add(("Bulgu sayısı {0:N0}; raporda en büyük 8000 tanesi gösterildi (CSV'de tamamı var)." -f $tumBulgular.Count)) }

if (-not $yonetici) { $Notlar.Add('Betik yönetici yetkisi olmadan çalıştırıldı (istenmedi). Bazı sistem klasörleri (ör. C:\Windows\Temp, System Volume Information) ölçülemedi ve "Erişilemeyen" sekmesinde listelendi.') }
if ($sc.CloudOnlyFiles -gt 0) { $Notlar.Add(("OneDrive vb. yalnızca bulutta duran {0:N0} dosya ({1:N2} GB) diskte yer kaplamadığı için hesaba katılmadı." -f $sc.CloudOnlyFiles, ($sc.CloudOnlyBytes / $GB))) }
if ($sc.ReparseSkipped -gt 0) { $Notlar.Add(("{0:N0} bağlantı noktası (junction/symlink) çift sayımı önlemek için izlenmedi." -f $sc.ReparseSkipped)) }
$Notlar.Add('Klasör boyutları dosyaların gerçek boyutudur ("diskteki boyut" sıkıştırma/küme boyutu nedeniyle biraz farklı olabilir). WinSxS gibi sabit bağlantı içeren klasörler olduğundan büyük görünebilir.')
$Notlar.Add('Kullanılan alan ile taranan dosyaların toplamı arasındaki fark; erişilemeyen sistem klasörleri, gölge kopyalar (Sistem Geri Yükleme) ve dosya sistemi meta verisinden kaynaklanır.')
if (-not $TekrarHash) { $Notlar.Add('Tekrarlanan dosyalar ad + boyut eşleşmesiyle bulundu (dosya içerikleri okunmadı). Kesin sonuç için betiği -TekrarHash ile çalıştırabilirsiniz (içerik yalnızca yerelde özetlenir).') }

$sure = (Get-Date) - $baslangic
$Data = [ordered]@{
    meta        = [ordered]@{
        tarih = $simdi.ToString('yyyy-MM-dd HH:mm'); bilgisayar = $env:COMPUTERNAME; kullanici = $env:USERNAME; yonetici = $yonetici
        sure = [math]::Round($sure.TotalMinutes, 1); dosya = [long]$sc.FileCount; klasor = [long]$sc.DirCount; erisilemeyen = [long]$sc.DeniedTotal
        cikti = $CiktiKlasoru; eskiIndirmeGun = $EskiIndirmeGun; eskiProjeGun = $EskiProjeGun; hash = [bool]$TekrarHash
        ps = $PSVersionTable.PSVersion.ToString()
    }
    suruculer   = $SurucuJson
    oneriler    = $OneriJson
    kategoriler = $KategoriJson
    top50       = $Top50Json
    klasorler   = $KlasorJson
    top100      = $Top100Json
    dosyalar    = $DosyaJson
    bulgular    = $bulguCikti
    tekrarlar   = @($TekrarJson | Sort-Object { $_.w } -Descending | Select-Object -First 1000)
    projeler    = @($ProjelerJson | Sort-Object { $_.s } -Descending)
    hassas      = $HassasJson
    erisilemeyen = @($Erisilemeyen | Select-Object -First 3000)
    notlar      = $Notlar
}

# ---------------------------------------------------------------------------
# 12) CSV dosyalari
# ---------------------------------------------------------------------------
Write-Host 'CSV dosyaları yazılıyor...' -ForegroundColor Cyan
$csvEnc = if ($PSVersionTable.PSVersion.Major -ge 6) { 'utf8BOM' } else { 'UTF8' }
$durumAd = @{ G = 'Temizlenebilir'; Y = 'Kontrol edilmeli'; K = 'Silinmemeli'; N = 'Sınıflandırılmadı'; GY = 'Kısmen temizlenebilir' }
function Save-Csv($nesneler, [string]$ad) {
    $yol = Join-Path $CiktiKlasoru $ad
    @($nesneler) | Export-Csv -LiteralPath $yol -NoTypeInformation -Encoding $csvEnc -UseCulture
}
Save-Csv ($SurucuJson | ForEach-Object { [pscustomobject][ordered]@{ Surucu = "$($_.h):"; Tur = $_.tur; Etiket = $_.etiket; Toplam_GB = (To-GB $_.toplam); Kullanilan_GB = (To-GB $_.kullanilan); Bos_GB = (To-GB $_.bos); Guvenle_Temizlenebilir_GB = (To-GB $_.g); Kontrol_Sonrasi_Ek_GB = (To-GB $_.y) } }) 'Disk_Ozeti.csv'
Save-Csv ($Top50Json | ForEach-Object { [pscustomobject][ordered]@{ Yol = $_.p; Boyut_GB = (To-GB $_.s); Boyut_Bayt = $_.s; Dosya_Sayisi = $_.f; Son_Degisiklik = $_.d; Derinlik = $_.dp; Durum = $durumAd[$_.st]; Kategori = $_.c; Gerekce = $_.r } }) 'En_Buyuk_50_Klasor.csv'
Save-Csv ($KlasorJson | ForEach-Object { [pscustomobject][ordered]@{ Yol = $_.p; Boyut_GB = (To-GB $_.s); Boyut_Bayt = $_.s; Dosya_Sayisi = $_.f; Son_Degisiklik = $_.d; Derinlik = $_.dp; Durum = $durumAd[$_.st]; Kategori = $_.c; Gerekce = $_.r } }) 'Klasorler_100MB_Ustu.csv'
Save-Csv ($Top100Json | ForEach-Object { [pscustomobject][ordered]@{ Yol = $_.p; Boyut_GB = (To-GB $_.s); Boyut_Bayt = $_.s; Uzanti = $_.e; Son_Degisiklik = $_.d; Durum = $durumAd[$_.st]; Kategori = $_.c; Gerekce = $_.r } }) 'En_Buyuk_100_Dosya.csv'
Save-Csv ($tumBulgular | ForEach-Object { [pscustomobject][ordered]@{ Durum = $durumAd[$_.st]; Kategori = $_.c; Tur = $_.t; Yol = $_.p; Boyut_GB = (To-GB $_.s); Boyut_Bayt = $_.s; Son_Degisiklik = $_.d; Gun_Once = $_.g; Yeniden_Olusturulabilir = $_.rg; Gerekce = $_.r; Oneri = $_.o; Nasil = $_.n } }) 'Bulgular_Tumu.csv'
Save-Csv ($KategoriJson | ForEach-Object { [pscustomobject][ordered]@{ Kategori = $_.ad; Oge_Sayisi = $_.adet; Temizlenebilir_GB = (To-GB $_.G); Kontrol_Edilmeli_GB = (To-GB $_.Y); Silinmemeli_GB = (To-GB $_.K); Aciklama = $_.aciklama } }) 'Kategori_Ozeti.csv'
Save-Csv ($OneriJson | ForEach-Object { $sira = 0 } { $sira++; [pscustomobject][ordered]@{ Sira = $sira; Oneri = $_.ad; Kazanc_GB = (To-GB $_.s); Guvenli_Kisim_GB = (To-GB $_.gs); Durum = $durumAd[$_.st]; Suruculer = $_.drs; Nasil = $_.n; Ornek_Yollar = $_.ornek } }) 'En_Iyi_10_Oneri.csv'
Save-Csv ($TekrarJson | ForEach-Object { $g = $_; $g.k | ForEach-Object { [pscustomobject][ordered]@{ Dosya_Adi = $g.ad; Kopya_Sayisi = $g.n; Tek_Kopya_MB = [math]::Round($g.s / $MB, 1); Bosa_Harcanan_GB = (To-GB $g.w); Yontem = $g.y; Yol = $_.p; Son_Degisiklik = $_.d; Durum = $durumAd[$_.st] } } }) 'Tekrarlanan_Dosyalar.csv'
Save-Csv ($ProjelerJson | ForEach-Object { [pscustomobject][ordered]@{ Yol = $_.p; Tur = $_.t; Boyut_GB = (To-GB $_.s); Derleme_Ciktisi_GB = (To-GB $_.b); Son_Degisiklik = $_.d; Gun_Once = $_.g; Eski = $(if ($_.eski) { 'Evet' } else { 'Hayır' }); Durum = 'Silinmemeli (korumalı)' } }) 'Projeler.csv'
Save-Csv ($Erisilemeyen | ForEach-Object { [pscustomobject][ordered]@{ Yol = $_.p; Neden = $_.r } }) 'Erisilemeyen_Klasorler.csv'
Save-Csv ($HassasJson | ForEach-Object { [pscustomobject][ordered]@{ Yol = $_.p; Boyut_Bayt = $_.s; Son_Degisiklik = $_.d; Durum = 'Silinmemeli (kimlik bilgisi/yapılandırma)' } }) 'Korunan_Hassas_Dosyalar.csv'

# ---------------------------------------------------------------------------
# 13) HTML rapor
# ---------------------------------------------------------------------------
Write-Host 'HTML rapor oluşturuluyor...' -ForegroundColor Cyan
$sablon = @'
<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Disk Analiz Raporu</title>
<style>
:root{
  --bg:#f4f6f9;--card:#ffffff;--fg:#1c2330;--mut:#5d6878;--line:#e2e6ec;--soft:#eef1f5;
  --g:#1e9b57;--y:#d39200;--k:#d14343;--n:#98a2b0;--used:#7a8697;--acc:#2f6fdf;
  --gbg:#e5f6ec;--ybg:#fcf3dc;--kbg:#fbe7e7;--nbg:#eef0f3;
}
@media (prefers-color-scheme:dark){
  :root{--bg:#11151b;--card:#1a2029;--fg:#e5e9ef;--mut:#98a3b3;--line:#2a313c;--soft:#222935;
  --used:#5a6576;--acc:#6f9cff;--gbg:#123a26;--ybg:#3b3014;--kbg:#3f1c1c;--nbg:#262c36}
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 "Segoe UI",system-ui,-apple-system,Roboto,Arial,sans-serif}
header{padding:22px 24px 8px;max-width:1500px;margin:auto}
h1{margin:0 0 4px;font-size:24px}
h2{font-size:18px;margin:22px 0 10px}
h3{font-size:15px;margin:0 0 8px}
.mut{color:var(--mut)}
a{color:var(--acc)}
.meta{color:var(--mut);font-size:13px}
.safe{display:inline-block;margin-top:8px;padding:6px 10px;border-radius:8px;background:var(--gbg);color:var(--fg);font-size:13px}
nav{position:sticky;top:0;z-index:5;background:var(--bg);border-bottom:1px solid var(--line)}
nav .in{max-width:1500px;margin:auto;padding:0 16px;display:flex;gap:4px;overflow-x:auto}
nav button{border:0;background:none;color:var(--mut);padding:12px 12px;font:inherit;cursor:pointer;border-bottom:3px solid transparent;white-space:nowrap}
nav button.on{color:var(--fg);border-bottom-color:var(--acc);font-weight:600}
main{max-width:1500px;margin:auto;padding:8px 24px 60px}
section{display:none}
section.on{display:block}
.grid{display:grid;gap:14px;grid-template-columns:repeat(auto-fit,minmax(320px,1fr))}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px}
.drive{display:flex;gap:16px;align-items:center}
.donut{width:130px;height:130px;flex:none}
.donut .dp{font-size:22px;font-weight:700;fill:var(--fg)}
.donut .dl{font-size:11px;fill:var(--mut)}
.kv{display:grid;grid-template-columns:auto auto;gap:2px 14px;font-size:13px}
.kv b{font-variant-numeric:tabular-nums;text-align:right}
.bar{height:12px;border-radius:6px;background:var(--soft);overflow:hidden;display:flex;margin:10px 0 4px}
.bar i{display:block;height:100%}
.legend{display:flex;flex-wrap:wrap;gap:10px;font-size:12px;color:var(--mut)}
.legend span::before{content:"";display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:5px;vertical-align:-1px;background:var(--c)}
.big{font-size:30px;font-weight:700;font-variant-numeric:tabular-nums}
.tot{display:grid;gap:14px;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));margin-top:14px}
.badge{display:inline-flex;align-items:center;gap:4px;padding:1px 8px;border-radius:999px;font-size:12px;white-space:nowrap}
.badge.g{background:var(--gbg)}.badge.y{background:var(--ybg)}.badge.k{background:var(--kbg)}.badge.n{background:var(--nbg)}
.badge.gy{background:linear-gradient(90deg,var(--gbg),var(--ybg))}
ol.rec{margin:0;padding:0;list-style:none;counter-reset:r}
ol.rec li{counter-increment:r;display:grid;grid-template-columns:34px 1fr auto;gap:10px;padding:10px 0;border-top:1px solid var(--line);align-items:start}
ol.rec li:first-child{border-top:0}
ol.rec li::before{content:counter(r);width:28px;height:28px;border-radius:50%;background:var(--soft);display:grid;place-items:center;font-weight:700}
ol.rec .sz{font-weight:700;font-variant-numeric:tabular-nums;white-space:nowrap;text-align:right}
.cat{display:grid;grid-template-columns:minmax(150px,260px) 1fr 110px;gap:10px;align-items:center;padding:5px 0;font-size:13px}
.cat .bar{margin:0}
.cat .v{text-align:right;font-variant-numeric:tabular-nums}
.ctrl{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:8px 0}
.ctrl input[type=search]{flex:1 1 240px;min-width:180px}
.ctrl input,.ctrl select{font:inherit;padding:6px 8px;border-radius:8px;border:1px solid var(--line);background:var(--card);color:var(--fg)}
.ctrl .mn{width:80px}
.ctrl .sum{color:var(--mut);font-size:12px;margin-left:auto}
.scroll{overflow-x:auto;border:1px solid var(--line);border-radius:10px;background:var(--card)}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{padding:7px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{position:sticky;top:0;background:var(--soft);cursor:pointer;user-select:none;white-space:nowrap;font-weight:600}
th .ar{color:var(--mut);font-size:10px;margin-left:4px}
tr:hover td{background:var(--soft)}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
td.r{min-width:260px;color:var(--mut)}
.pc{display:flex;gap:6px;align-items:flex-start;min-width:280px}
.pc code{font:12px/1.4 Consolas,"Cascadia Mono",monospace;word-break:break-all;flex:1}
.acts{display:flex;gap:2px;flex:none}
.ib{border:1px solid var(--line);background:var(--card);color:var(--fg);border-radius:6px;padding:0 5px;cursor:pointer;font-size:13px;line-height:22px;text-decoration:none}
.ib:hover{border-color:var(--acc)}
.more{text-align:center;margin:10px 0}
.more button,.btn{font:inherit;padding:6px 14px;border-radius:8px;border:1px solid var(--line);background:var(--card);color:var(--fg);cursor:pointer}
.sbar{height:6px;border-radius:3px;background:var(--acc);opacity:.55;margin-top:3px}
.toast{position:fixed;bottom:20px;left:50%;transform:translateX(-50%);background:var(--fg);color:var(--bg);padding:8px 14px;border-radius:8px;opacity:0;transition:opacity .2s;pointer-events:none;max-width:90vw;font-size:13px;z-index:9}
.toast.on{opacity:.95}
.catcard p{margin:4px 0 10px;color:var(--mut);font-size:13px}
.catcard .nums{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px}
.note li{margin:4px 0;color:var(--mut)}
.dup{border-top:1px solid var(--line);padding:10px 0}
.dup:first-child{border-top:0}
.dup .h{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.dup ul{margin:6px 0 0;padding-left:0;list-style:none}
.dup li{padding:3px 0}
.help dt{font-weight:600;margin-top:10px}
.help dd{margin:2px 0 0 0;color:var(--mut)}
@media (max-width:640px){header,main{padding-left:16px;padding-right:16px}.drive{flex-direction:column;align-items:flex-start}.cat{grid-template-columns:1fr;gap:2px}}
</style>
</head>
<body>
<header>
  <h1>Disk Analiz Raporu</h1>
  <div class="meta" id="meta"></div>
  <div class="safe">🔒 Salt okunur analiz: hiçbir dosya silinmedi, taşınmadı veya değiştirilmedi. Temizlik kararı tamamen sizindir.</div>
</header>
<nav><div class="in" id="tabs"></div></nav>
<main>
  <section id="t-ozet"></section>
  <section id="t-klasor"></section>
  <section id="t-dosya"></section>
  <section id="t-kategori"></section>
  <section id="t-bulgu"></section>
  <section id="t-tekrar"></section>
  <section id="t-proje"></section>
  <section id="t-erisim"></section>
  <section id="t-yardim"></section>
</main>
<div class="toast" id="toast"></div>
<script>window.RAPOR_VERI = /*__VERI__*/null;</script>
<script>
(function(){
'use strict';
var D = window.RAPOR_VERI;
if(!D){document.querySelector('main').innerHTML='<p>Rapor verisi bulunamadı.</p>';return;}
var ST={G:{ad:'Temizlenebilir',ik:'🟢',c:'g'},Y:{ad:'Kontrol edilmeli',ik:'🟡',c:'y'},K:{ad:'Silinmemeli',ik:'🔴',c:'k'},N:{ad:'Sınıflandırılmadı',ik:'⚪',c:'n'},GY:{ad:'Kısmen temizlenebilir',ik:'🟢🟡',c:'gy'}};
var STORD={G:1,GY:2,Y:3,K:4,N:0};
var FL={st:'Durum',c:'Kategori',dr:'Sürücü',t:'Tür',e:'Uzantı'};
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
var nf1=new Intl.NumberFormat('tr-TR',{maximumFractionDigits:1}),nf2=new Intl.NumberFormat('tr-TR',{minimumFractionDigits:2,maximumFractionDigits:2}),nf0=new Intl.NumberFormat('tr-TR');
function fb(b){if(b==null||isNaN(b))return '—';var u=['B','KB','MB','GB','TB'],i=0,v=+b;while(v>=1024&&i<4){v/=1024;i++;}return (i>=3?nf2:nf1).format(v)+' '+u[i];}
function gb(b){return nf2.format((b||0)/1073741824)+' GB';}
function badge(st){var s=ST[st]||ST.N;return '<span class="badge '+s.c+'">'+s.ik+' '+esc(s.ad)+'</span>';}
function parentOf(p){var i=p.lastIndexOf('\\');if(i<=2)return p.slice(0,3);return p.slice(0,i);}
function fileUrl(p){var d=p.replace(/\*.*$/,'');d=d.replace(/\\+$/,'');var parts=d.split('\\');return 'file:///'+parts.map(function(x,i){return i===0?x:encodeURIComponent(x);}).join('/')+'/';}
function pathCell(p,isFile){
  var folder=isFile?parentOf(p):p.replace(/\\[^\\]*\*.*$/,'');
  var cmd=isFile&&p.indexOf('*')<0?'explorer.exe /select,"'+p+'"':'explorer.exe "'+folder+'"';
  return '<div class="pc"><code>'+esc(p)+'</code><span class="acts">'+
    '<button class="ib" data-copy="'+esc(p)+'" title="Tam yolu kopyala">📋</button>'+
    '<button class="ib" data-copy="'+esc(cmd)+'" title="Dosya Gezgini komutunu kopyala — Win+R tuşlarına basıp yapıştırın">🗔</button>'+
    '<a class="ib" href="'+esc(fileUrl(folder))+'" target="_blank" rel="noopener" title="Klasörü aç (tarayıcı izin verirse)">📂</a></span></div>';
}
// Kopyalama
var toastEl=document.getElementById('toast'),tt;
function toast(m){toastEl.textContent=m;toastEl.classList.add('on');clearTimeout(tt);tt=setTimeout(function(){toastEl.classList.remove('on');},1800);}
function fallbackCopy(t){var ta=document.createElement('textarea');ta.value=t;ta.style.position='fixed';ta.style.opacity='0';document.body.appendChild(ta);ta.select();var ok=false;try{ok=document.execCommand('copy');}catch(e){}document.body.removeChild(ta);return ok;}
function copy(t){
  if(navigator.clipboard&&window.isSecureContext){return navigator.clipboard.writeText(t).then(function(){return true;},function(){return fallbackCopy(t);});}
  return Promise.resolve(fallbackCopy(t));
}
document.addEventListener('click',function(e){
  var b=e.target.closest('[data-copy]');if(!b)return;e.preventDefault();
  var t=b.getAttribute('data-copy');
  copy(t).then(function(ok){toast(ok?('Kopyalandı: '+(t.length>80?t.slice(0,77)+'…':t)):'Kopyalanamadı — yolu seçip Ctrl+C ile kopyalayın');});
});

// Genel tablo
function makeTable(host,o){
  var st={q:'',f:{},min:0,sk:o.sort||'s',sd:o.sortDir||-1,lim:o.page||200};
  var rows=o.rows||[];
  var w=document.createElement('div');
  var h='<div class="ctrl"><input type="search" class="q" placeholder="Yolda, kategoride veya gerekçede ara…">';
  (o.filters||[]).forEach(function(k){
    var vals=[];var seen={};rows.forEach(function(r){var v=r[k];if(v!==''&&v!=null&&!seen[v]){seen[v]=1;vals.push(v);}});
    if(k==='st')vals.sort(function(a,b){return STORD[a]-STORD[b];});else vals.sort(function(a,b){return String(a).localeCompare(String(b),'tr');});
    h+='<select data-f="'+k+'"><option value="">'+FL[k]+': tümü</option>'+vals.map(function(v){return '<option value="'+esc(v)+'">'+esc(k==='st'?(ST[v]||ST.N).ik+' '+(ST[v]||ST.N).ad:(k==='dr'?v+':':v))+'</option>';}).join('')+'</select>';
  });
  if(o.extraFilter)h+=o.extraFilter.html;
  h+='<label class="mut">En az <input type="number" min="0" step="10" class="mn" value="0"> MB</label><span class="sum"></span></div>';
  h+='<div class="scroll"><table><thead><tr>'+o.cols.map(function(c){return '<th data-k="'+c.k+'" class="'+(c.cls||'')+'">'+c.ad+'<span class="ar"></span></th>';}).join('')+'</tr></thead><tbody></tbody></table></div><div class="more"></div>';
  w.innerHTML=h;host.appendChild(w);
  var tb=w.querySelector('tbody'),sum=w.querySelector('.sum'),more=w.querySelector('.more');
  var maxS=1;rows.forEach(function(r){if((r.s||0)>maxS)maxS=r.s;});
  w.querySelector('.q').addEventListener('input',function(e){st.q=e.target.value.trim().toLocaleLowerCase('tr');st.lim=o.page||200;render();});
  w.querySelector('.mn').addEventListener('input',function(e){st.min=parseFloat(e.target.value)||0;render();});
  w.querySelectorAll('select[data-f]').forEach(function(s){s.addEventListener('change',function(){st.f[s.getAttribute('data-f')]=s.value;st.lim=o.page||200;render();});});
  if(o.extraFilter)o.extraFilter.bind(w,st,render);
  w.querySelectorAll('th').forEach(function(th){th.addEventListener('click',function(){var k=th.getAttribute('data-k');if(st.sk===k)st.sd=-st.sd;else{st.sk=k;var c=colOf(k);st.sd=(c&&(c.type==='size'||c.type==='num'||c.type==='date'||c.type==='st'))?-1:1;}render();});});
  function colOf(k){for(var i=0;i<o.cols.length;i++)if(o.cols[i].k===k)return o.cols[i];return null;}
  function cmp(a,b,c){
    if(c&&c.type==='st'){return (STORD[a]||0)-(STORD[b]||0);}
    if(typeof a==='number'||typeof b==='number'){return (a==null?-Infinity:a)-(b==null?-Infinity:b);}
    return String(a==null?'':a).localeCompare(String(b==null?'':b),'tr');
  }
  function cell(r,c){
    var v=r[c.k];
    switch(c.type){
      case 'path':return pathCell(v,o.isFile||r.t==='Dosya');
      case 'size':return '<span title="'+nf0.format(v||0)+' bayt">'+fb(v)+'</span>'+(o.sizeBar?'<div class="sbar" style="width:'+Math.max(2,Math.round((v||0)/maxS*100))+'%"></div>':'');
      case 'st':return badge(v);
      case 'num':return v==null?'':nf0.format(v);
      case 'dr':return v?esc(v)+':':'';
      case 'age':return v==null?'':nf0.format(v)+' gün';
      default:return esc(v);
    }
  }
  function filtered(){
    var q=st.q,mn=st.min*1048576;
    return rows.filter(function(r){
      for(var k in st.f){if(st.f[k]&&String(r[k])!==st.f[k])return false;}
      if(mn&&(r.s||0)<mn)return false;
      if(o.extraFilter&&!o.extraFilter.test(r,st))return false;
      if(q){var hay=((r.p||'')+' '+(r.c||'')+' '+(r.r||'')+' '+(r.t||'')+' '+(r.e||'')).toLocaleLowerCase('tr');if(hay.indexOf(q)<0)return false;}
      return true;
    });
  }
  function render(){
    var f=filtered(),c=colOf(st.sk);
    f.sort(function(a,b){return cmp(a[st.sk],b[st.sk],c)*st.sd;});
    var tot=0;f.forEach(function(r){tot+=r.s||0;});
    w.querySelectorAll('th').forEach(function(th){th.querySelector('.ar').textContent=th.getAttribute('data-k')===st.sk?(st.sd<0?'▼':'▲'):'';});
    var view=f.slice(0,st.lim);
    tb.innerHTML=view.length?view.map(function(r){return '<tr>'+o.cols.map(function(c){return '<td class="'+(c.cls||'')+'">'+cell(r,c)+'</td>';}).join('')+'</tr>';}).join(''):'<tr><td colspan="'+o.cols.length+'" class="mut">Eşleşen kayıt yok.</td></tr>';
    sum.textContent=nf0.format(f.length)+' kayıt · boyut toplamı '+fb(tot)+(o.nestedNote?' (iç içe klasörler birden fazla sayılır)':'');
    more.innerHTML=f.length>st.lim?'<button>'+nf0.format(Math.min(st.lim,f.length))+' / '+nf0.format(f.length)+' gösteriliyor — daha fazla göster</button>':'';
    var mb=more.querySelector('button');if(mb)mb.onclick=function(){st.lim+=o.page||200;render();};
  }
  render();
  return {setFilter:function(k,v){var s=w.querySelector('select[data-f="'+k+'"]');if(s){s.value=v;st.f[k]=v;}st.lim=o.page||200;render();},el:w};
}

// Sekmeler
var TABS=[['ozet','Özet'],['klasor','Klasörler'],['dosya','En büyük dosyalar'],['kategori','Kategoriler'],['bulgu','Tüm bulgular'],['tekrar','Tekrarlanan dosyalar'],['proje','Projeler'],['erisim','Erişilemeyenler'],['yardim','Açıklamalar']];
var tabsEl=document.getElementById('tabs');
TABS.forEach(function(t){var b=document.createElement('button');b.textContent=t[1];b.setAttribute('data-t',t[0]);b.onclick=function(){show(t[0]);};tabsEl.appendChild(b);});
function show(id){
  TABS.forEach(function(t){document.getElementById('t-'+t[0]).classList.toggle('on',t[0]===id);});
  tabsEl.querySelectorAll('button').forEach(function(b){b.classList.toggle('on',b.getAttribute('data-t')===id);});
  try{history.replaceState(null,'','#'+id);}catch(e){}
  window.scrollTo(0,0);
}

var M=D.meta||{};
document.getElementById('meta').textContent='Bilgisayar: '+(M.bilgisayar||'?')+' · Kullanıcı: '+(M.kullanici||'?')+' · Tarih: '+(M.tarih||'?')+' · Süre: '+nf1.format(M.sure||0)+' dk · Taranan: '+nf0.format(M.dosya||0)+' dosya, '+nf0.format(M.klasor||0)+' klasör · Yönetici: '+(M.yonetici?'evet':'hayır');

// ---------- ÖZET ----------
(function(){
  var s=document.getElementById('t-ozet');
  var tg=0,ty=0,h='<h2>Disk doluluk durumu</h2><div class="grid">';
  (D.suruculer||[]).forEach(function(d){
    tg+=d.g;ty+=d.y;
    var T=d.toplam||1,usedPct=Math.round(d.kullanilan/T*100),afterPct=Math.round(Math.max(0,d.kullanilan-d.g)/T*100);
    var other=Math.max(0,d.kullanilan-d.g-d.y);
    var R=50,C=2*Math.PI*R,off=0,svg='<svg class="donut" viewBox="0 0 120 120" role="img" aria-label="'+d.h+': yüzde '+usedPct+' dolu"><circle cx="60" cy="60" r="'+R+'" fill="none" stroke="var(--soft)" stroke-width="14"/>';
    [[other,'var(--used)'],[d.y,'var(--y)'],[d.g,'var(--g)']].forEach(function(sg){var len=Math.max(0,sg[0]/T*C);if(len<=0)return;svg+='<circle cx="60" cy="60" r="'+R+'" fill="none" stroke="'+sg[1]+'" stroke-width="14" stroke-dasharray="'+len+' '+(C-len)+'" stroke-dashoffset="'+(-off)+'" transform="rotate(-90 60 60)"/>';off+=len;});
    svg+='<text x="60" y="62" text-anchor="middle" class="dp">%'+usedPct+'</text><text x="60" y="80" text-anchor="middle" class="dl">dolu</text></svg>';
    h+='<div class="card"><h3>'+esc(d.h)+': sürücü <span class="mut">· '+esc(d.tur||'')+(d.etiket?' · '+esc(d.etiket):'')+(d.fs?' · '+esc(d.fs):'')+'</span></h3><div class="drive">'+svg+
      '<div class="kv"><span>Toplam kapasite</span><b>'+gb(d.toplam)+'</b><span>Kullanılan</span><b>'+gb(d.kullanilan)+'</b><span>Boş</span><b>'+gb(d.bos)+'</b>'+
      '<span>🟢 Güvenle temizlenebilir</span><b style="color:var(--g)">'+gb(d.g)+'</b><span>🟡 Onayınızla ek</span><b style="color:var(--y)">'+gb(d.y)+'</b>'+
      '<span>Temizlik sonrası doluluk</span><b>%'+afterPct+'</b></div></div>'+
      '<div class="bar"><i style="width:'+(other/T*100)+'%;background:var(--used)"></i><i style="width:'+(d.y/T*100)+'%;background:var(--y)"></i><i style="width:'+(d.g/T*100)+'%;background:var(--g)"></i></div>'+
      '<div class="legend"><span style="--c:var(--used)">Diğer kullanılan</span><span style="--c:var(--y)">Kontrol edilmeli</span><span style="--c:var(--g)">Temizlenebilir</span><span style="--c:var(--soft)">Boş</span></div></div>';
  });
  h+='</div><div class="tot"><div class="card"><div class="mut">🟢 Toplam güvenle kazanılabilir</div><div class="big" style="color:var(--g)">'+gb(tg)+'</div><div class="mut">Geçici dosyalar ve yeniden oluşturulabilen önbellekler</div></div>'+
     '<div class="card"><div class="mut">🟡 Onayınızla ek olarak</div><div class="big" style="color:var(--y)">'+gb(ty)+'</div><div class="mut">Kontrol etmeniz gereken dosyalar (tahmini üst sınır)</div></div>'+
     '<div class="card"><div class="mut">Toplam potansiyel</div><div class="big">'+gb(tg+ty)+'</div><div class="mut">🔴 Silinmemeli olanlar dahil edilmedi</div></div></div>';
  h+='<h2>En fazla alan kazandırabilecek 10 öneri</h2><div class="card"><ol class="rec">';
  (D.oneriler||[]).forEach(function(o){
    h+='<li><div><b>'+esc(o.ad)+'</b> '+badge(o.st)+'<div class="mut" style="font-size:13px">'+esc(o.n||'')+'</div><div class="mut" style="font-size:12px">'+nf0.format(o.adet)+' öğe · Sürücü: '+esc(o.drs)+(o.st==='GY'?' · güvenli kısım '+gb(o.gs):'')+'</div></div><div class="sz">'+gb(o.s)+'</div></li>';
  });
  if(!(D.oneriler||[]).length)h+='<li><div>Öneri bulunamadı.</div></li>';
  h+='</ol></div>';
  h+='<h2>Kategorilere göre dağılım</h2><div class="card">';
  var mx=1;(D.kategoriler||[]).forEach(function(c){var t=c.G+c.Y+c.K;if(t>mx)mx=t;});
  (D.kategoriler||[]).forEach(function(c){var t=c.G+c.Y+c.K;
    h+='<div class="cat"><a href="#" data-cat="'+esc(c.ad)+'">'+esc(c.ad)+'</a><div class="bar" title="🟢 '+fb(c.G)+' · 🟡 '+fb(c.Y)+' · 🔴 '+fb(c.K)+'"><i style="width:'+(c.G/mx*100)+'%;background:var(--g)"></i><i style="width:'+(c.Y/mx*100)+'%;background:var(--y)"></i><i style="width:'+(c.K/mx*100)+'%;background:var(--k)"></i></div><div class="v">'+(t?fb(t):'<span class="mut">bulunamadı</span>')+'</div></div>';});
  h+='<div class="legend" style="margin-top:8px"><span style="--c:var(--g)">Temizlenebilir</span><span style="--c:var(--y)">Kontrol edilmeli</span><span style="--c:var(--k)">Silinmemeli (bilgi)</span></div></div>';
  if((D.notlar||[]).length){h+='<h2>Notlar</h2><div class="card"><ul class="note">'+D.notlar.map(function(n){return '<li>'+esc(n)+'</li>';}).join('')+'</ul></div>';}
  s.innerHTML=h;
  s.addEventListener('click',function(e){var a=e.target.closest('[data-cat]');if(!a)return;e.preventDefault();openCat(a.getAttribute('data-cat'));});
})();

// ---------- KLASÖRLER ----------
(function(){
  var s=document.getElementById('t-klasor');
  s.innerHTML='<h2>En fazla yer kaplayan 50 klasör</h2><p class="mut">Klasör boyutu, içindeki tüm alt klasörleri kapsar; bu yüzden üst ve alt klasörler birlikte listelenir. "Derinlik" sütunu klasörün sürücü köküne uzaklığıdır.</p><div id="k50"></div><h2>100 MB üzerindeki tüm klasörler</h2><div id="kall"></div>';
  var cols=[{k:'p',ad:'Tam yol',type:'path'},{k:'s',ad:'Boyut',type:'size',cls:'num'},{k:'f',ad:'Dosya',type:'num',cls:'num'},{k:'d',ad:'Son değişiklik'},{k:'dp',ad:'Derinlik',type:'num',cls:'num'},{k:'st',ad:'Durum',type:'st'},{k:'c',ad:'Kategori'},{k:'r',ad:'Gerekçe',cls:'r'}];
  makeTable(s.querySelector('#k50'),{rows:D.top50||[],cols:cols,filters:['dr','st'],sizeBar:true,nestedNote:true,page:50});
  var depth={html:'<select class="dep"><option value="">Derinlik: tümü</option><option value="1">1 (kök altı)</option><option value="2">≤ 2</option><option value="3">≤ 3</option><option value="4">≤ 4</option></select>',
    bind:function(w,st,render){w.querySelector('.dep').addEventListener('change',function(e){st.dep=parseInt(e.target.value,10)||0;render();});},
    test:function(r,st){return !st.dep||r.dp<=st.dep;}};
  makeTable(s.querySelector('#kall'),{rows:D.klasorler||[],cols:cols,filters:['dr','st','c'],sizeBar:true,nestedNote:true,extraFilter:depth});
})();

// ---------- DOSYALAR ----------
(function(){
  var s=document.getElementById('t-dosya');
  s.innerHTML='<h2>En büyük 100 dosya</h2><div id="d100"></div><h2>50 MB üzerindeki dosyalar (en büyük 1000)</h2><div id="dall"></div>';
  var cols=[{k:'p',ad:'Tam yol',type:'path'},{k:'s',ad:'Boyut',type:'size',cls:'num'},{k:'e',ad:'Uzantı'},{k:'d',ad:'Son değişiklik'},{k:'g',ad:'Yaş',type:'age',cls:'num'},{k:'st',ad:'Durum',type:'st'},{k:'c',ad:'Kategori'},{k:'r',ad:'Gerekçe',cls:'r'}];
  makeTable(s.querySelector('#d100'),{rows:D.top100||[],cols:cols,filters:['dr','st','c','e'],isFile:true,sizeBar:true,page:100});
  makeTable(s.querySelector('#dall'),{rows:D.dosyalar||[],cols:cols,filters:['dr','st','c','e'],isFile:true,sizeBar:true});
})();

// ---------- BULGULAR ----------
var bulguTable;
(function(){
  var s=document.getElementById('t-bulgu');
  s.innerHTML='<h2>Tüm bulgular</h2><p class="mut">Her satır bir klasör, dosya veya dosya grubudur. Durum, kategori ve sürücüye göre filtreleyebilir; sütun başlığına tıklayarak sıralayabilirsiniz.</p><div id="ball"></div>';
  bulguTable=makeTable(s.querySelector('#ball'),{rows:D.bulgular||[],cols:[{k:'st',ad:'Durum',type:'st'},{k:'c',ad:'Kategori'},{k:'p',ad:'Tam yol',type:'path'},{k:'s',ad:'Boyut',type:'size',cls:'num'},{k:'d',ad:'Son değişiklik'},{k:'g',ad:'Yaş',type:'age',cls:'num'},{k:'rg',ad:'Yeniden oluşturulabilir mi?'},{k:'r',ad:'Gerekçe',cls:'r'},{k:'n',ad:'Nasıl temizlenir?',cls:'r'}],filters:['st','c','dr','t'],sizeBar:true});
})();

// ---------- KATEGORİLER ----------
function openCat(ad){show('bulgu');bulguTable.setFilter('st','');bulguTable.setFilter('c',ad);}
(function(){
  var s=document.getElementById('t-kategori');
  var h='<h2>Gereksiz dosya kategorileri</h2><div class="grid">';
  (D.kategoriler||[]).forEach(function(c){
    h+='<div class="card catcard"><h3>'+esc(c.ad)+'</h3><p>'+esc(c.aciklama)+'</p><div class="nums"><span class="badge g">🟢 '+fb(c.G)+'</span><span class="badge y">🟡 '+fb(c.Y)+'</span><span class="badge k">🔴 '+fb(c.K)+'</span><span class="badge n">'+nf0.format(c.adet)+' öğe</span></div>'+(c.adet?'<button class="btn" data-cat="'+esc(c.ad)+'">Bulguları göster →</button>':'<span class="mut">Bu kategoride kayda değer öğe bulunamadı.</span>')+'</div>';
  });
  s.innerHTML=h+'</div>';
  s.addEventListener('click',function(e){var b=e.target.closest('[data-cat]');if(b)openCat(b.getAttribute('data-cat'));});
})();

// ---------- TEKRARLAR ----------
(function(){
  var s=document.getElementById('t-tekrar');
  var list=D.tekrarlar||[],tot=0;list.forEach(function(g){if(g.st!=='K')tot+=g.w;});
  var h='<h2>Tekrarlanan dosyalar</h2><p class="mut">'+nf0.format(list.length)+' grup · korunmayan gruplarda bir kopya bırakılırsa en fazla '+gb(tot)+' kazanılabilir. Hangi kopyanın kalacağına siz karar verin. '+(M.hash?'Eşleşme: SHA256 içerik özeti.':'Eşleşme: aynı ad + aynı boyut (içerik karşılaştırılmadı).')+'</p>';
  h+='<div class="ctrl"><input type="search" class="q" placeholder="Dosya adı veya yol ara…"><select class="fs"><option value="">Durum: tümü</option><option value="Y">🟡 Kontrol edilmeli</option><option value="K">🔴 Silinmemeli</option></select></div><div class="card" id="dl"></div>';
  s.innerHTML=h;
  var dl=s.querySelector('#dl'),q='',fs='';
  function render(){
    var f=list.filter(function(g){if(fs&&g.st!==fs)return false;if(!q)return true;var hay=(g.ad+' '+g.k.map(function(x){return x.p;}).join(' ')).toLocaleLowerCase('tr');return hay.indexOf(q)>=0;});
    dl.innerHTML=f.length?f.slice(0,300).map(function(g){return '<div class="dup"><div class="h"><b>'+esc(g.ad)+'</b>'+badge(g.st)+'<span class="mut">'+g.n+' kopya × '+fb(g.s)+' · olası kazanç <b>'+fb(g.w)+'</b> · '+esc(g.y)+'</span></div><ul>'+g.k.map(function(x){return '<li>'+badge(x.st)+' <span class="mut">'+esc(x.d)+'</span>'+pathCell(x.p,true)+'</li>';}).join('')+'</ul></div>';}).join('')+(f.length>300?'<p class="mut">İlk 300 grup gösterildi; tamamı CSV dosyasında.</p>':''):'<p class="mut">Tekrarlanan dosya bulunamadı.</p>';
  }
  s.querySelector('.q').addEventListener('input',function(e){q=e.target.value.trim().toLocaleLowerCase('tr');render();});
  s.querySelector('.fs').addEventListener('change',function(e){fs=e.target.value;render();});
  render();
})();

// ---------- PROJELER ----------
(function(){
  var s=document.getElementById('t-proje');
  s.innerHTML='<h2>Bulunan projeler (korumalı)</h2><p class="mut">Android Studio, Flutter, Ableton Live, Node.js, .NET ve Git projeleri otomatik bulundu. Projeler 🔴 korumalıdır; yalnızca içlerindeki derleme çıktılarının yeniden oluşturulabilir alanı ayrıca gösterilir ("Tüm bulgular" sekmesinde 🟡 olarak).</p><div id="pl"></div><h2>Korunan hassas dosyalar</h2><p class="mut">Firebase yapılandırmaları, imza anahtarları (keystore), .env ve benzeri kimlik bilgisi dosyaları. İçerikleri okunmadı; yalnızca konumları listelendi.</p><div id="hl"></div>';
  var ex={html:'<select class="old"><option value="">Tümü</option><option value="1">Yalnızca eski projeler</option><option value="0">Yalnızca aktif projeler</option></select>',
    bind:function(w,st,render){w.querySelector('.old').addEventListener('change',function(e){st.old=e.target.value;render();});},
    test:function(r,st){return !st.old||(st.old==='1')===!!r.eski;}};
  makeTable(s.querySelector('#pl'),{rows:D.projeler||[],cols:[{k:'p',ad:'Proje klasörü',type:'path'},{k:'t',ad:'Tür'},{k:'s',ad:'Toplam boyut',type:'size',cls:'num'},{k:'b',ad:'Yeniden oluşturulabilir (build)',type:'size',cls:'num'},{k:'d',ad:'Son değişiklik'},{k:'g',ad:'Yaş',type:'age',cls:'num'},{k:'st',ad:'Durum',type:'st'}],filters:['dr','t'],extraFilter:ex,sizeBar:true});
  makeTable(s.querySelector('#hl'),{rows:D.hassas||[],cols:[{k:'p',ad:'Dosya',type:'path'},{k:'s',ad:'Boyut',type:'size',cls:'num'},{k:'d',ad:'Son değişiklik'},{k:'st',ad:'Durum',type:'st'}],filters:['dr'],isFile:true,page:100});
})();

// ---------- ERİŞİLEMEYENLER ----------
(function(){
  var s=document.getElementById('t-erisim');
  s.innerHTML='<h2>Erişilemeyen klasörler</h2><p class="mut">İzin olmadığı için atlanan klasörler (toplam '+nf0.format(M.erisilemeyen||0)+'). Betik bilerek yönetici yetkisi istemedi; bu klasörlerin çoğu Windows sistem klasörüdür ve zaten temizlenmemelidir.</p><div id="el"></div>';
  makeTable(s.querySelector('#el'),{rows:(D.erisilemeyen||[]).map(function(x){return {p:x.p,r:x.r,dr:x.p.charAt(0).toUpperCase()};}),cols:[{k:'p',ad:'Klasör',type:'path'},{k:'r',ad:'Neden',cls:'r'}],filters:['dr'],sort:'p',sortDir:1,page:200});
})();

// ---------- AÇIKLAMALAR ----------
(function(){
  var s=document.getElementById('t-yardim');
  s.innerHTML='<h2>Durumlar ve kullanım</h2><div class="card help"><dl>'+
  '<dt>🟢 Temizlenebilir</dt><dd>Geçici dosyalar ve yeniden oluşturulabilen önbellekler. Silindiğinde veri kaybı olmaz; ilgili program bunları gerektiğinde yeniden oluşturur. Yine de Windows Disk Temizleme veya programın kendi temizleme seçeneğini kullanmanız önerilir.</dd>'+
  '<dt>🟡 Kontrol edilmeli</dt><dd>Kullanılmıyor olabilecek ama onayınızı gerektiren dosyalar: eski indirmeler, kurulum dosyaları, arşivler, yedekler, tekrarlar, çöp kutusu, korumalı projelerdeki derleme çıktıları, eski Android Studio sürümleri ve emülatörler.</dd>'+
  '<dt>🔴 Silinmemeli</dt><dd>Windows sistem dosyaları, kurulu programlar, uygulama verileri, kişisel belgeler, müzik kayıtları, VST ve ses kütüphaneleri, Ableton/Flutter/Android projeleri, kaynak kodları, Firebase yapılandırmaları ve kimlik bilgileri. Bilgi amaçlı listelenir.</dd>'+
  '<dt>⚪ Sınıflandırılmadı</dt><dd>Karışık içerikli üst klasörler (ör. C:\\Users). Alt klasörlerine bakarak karar verin.</dd>'+
  '<dt>Yol düğmeleri</dt><dd>📋 tam yolu kopyalar. 🗔 <code>explorer.exe /select,"…"</code> komutunu kopyalar: <b>Win+R</b> tuşlarına basıp yapıştırın ve Enter\'a basın; Dosya Gezgini o konumda açılır. 📂 klasörü tarayıcıda açmayı dener (bazı tarayıcılar güvenlik nedeniyle engeller).</dd>'+
  '<dt>Tahmini alan</dt><dd>İç içe klasörler bir kez sayılır. Çalışan programların kilitlediği dosyalar silinemeyebileceği için gerçek kazanç biraz daha az olabilir.</dd>'+
  '<dt>CSV dosyaları</dt><dd>Aynı klasördeki CSV dosyaları Excel ile açılabilir (Türkçe karakterler için UTF-8 BOM, ayırıcı olarak sistem liste ayırıcısı kullanıldı).</dd>'+
  '<dt>Rapor konumu</dt><dd><code>'+esc(M.cikti||'')+'</code></dd>'+
  '</dl></div>';
})();

var h0=(location.hash||'').replace('#','');
show(TABS.some(function(t){return t[0]===h0;})?h0:'ozet');
})();
</script>
</body>
</html>
'@
$json = [DiskAnaliz.Json]::Write($Data)
$html = $sablon.Replace('/*__VERI__*/null', $json)
$htmlYol = Join-Path $CiktiKlasoru 'Disk_Analiz_Raporu.html'
[System.IO.File]::WriteAllText($htmlYol, $html, (New-Object System.Text.UTF8Encoding $true))

# ---------------------------------------------------------------------------
# 14) Konsol ozeti
# ---------------------------------------------------------------------------
Write-Host ''
Write-Host '==============================================================' -ForegroundColor Cyan
Write-Host '  SONUÇ ÖZETİ (hiçbir dosya silinmedi)' -ForegroundColor Cyan
Write-Host '==============================================================' -ForegroundColor Cyan
$topG = [long]0; $topY = [long]0
foreach ($d in $SurucuJson) {
    $topG += $d.g; $topY += $d.y
    Write-Host ("{0}: ({1})" -f $d.h, $d.tur) -ForegroundColor Green
    Write-Host ("   Kullanılan alan              : {0,9:N2} GB" -f ($d.kullanilan / $GB))
    Write-Host ("   Boş alan                     : {0,9:N2} GB" -f ($d.bos / $GB))
    Write-Host ("   Güvenle temizlenebilir (tah.): {0,9:N2} GB" -f ($d.g / $GB)) -ForegroundColor Green
    Write-Host ("   Kontrol sonrası ek potansiyel: {0,9:N2} GB" -f ($d.y / $GB)) -ForegroundColor Yellow
}
Write-Host ''
Write-Host ("TOPLAM güvenle kazanılabilecek alan : {0:N2} GB" -f ($topG / $GB)) -ForegroundColor Green
Write-Host ("Onayınızla ek olarak kazanılabilecek: {0:N2} GB" -f ($topY / $GB)) -ForegroundColor Yellow
Write-Host ''
Write-Host 'En fazla alan kazandırabilecek 10 öneri:' -ForegroundColor Cyan
$sira = 0
foreach ($o in $OneriJson) {
    $sira++
    $ik = switch ($o.st) { 'G' { '[Temizlenebilir]' } 'GY' { '[Kısmen]' } default { '[Kontrol]' } }
    Write-Host ("{0,2}. {1,9:N2} GB  {2,-16} {3}" -f $sira, ($o.s / $GB), $ik, $o.ad)
}
Write-Host ''
Write-Host "Rapor klasörü: $CiktiKlasoru" -ForegroundColor Cyan
Write-Host "HTML rapor   : $htmlYol"
Write-Host ("Süre         : {0:N1} dakika" -f $sure.TotalMinutes)
Write-Host ''
if (-not $RaporuAcma) { try { Start-Process -FilePath $htmlYol } catch { } }
