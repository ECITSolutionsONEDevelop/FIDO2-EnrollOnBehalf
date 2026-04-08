#Requires -Version 5.1

<#
.SYNOPSIS
    FIDO2 Bulk Enrollment Tool for Microsoft Entra ID (GUI)
.DESCRIPTION
    GUI tool for bulk enrolling FIDO2 security keys on behalf of users.
    Uses direct credential creation (fido2-cred) for fast enrollment,
    bypassing Windows Hello for minimal user interaction.
    Supports random PIN generation with forced PIN change.
    Supports both USB and NFC FIDO2 keys.
.NOTES
    Based on Token2 FIDO2 bulk enrollment scripts.
    Requires: Microsoft.Graph, DSInternals.PassKeys PowerShell modules
    Requires: fido2-cred2.exe, fido2-manage.exe, read_serial_t2.exe, libfido2-ui.exe in script directory
#>

# ============================================================
# Assembly Loading
# ============================================================

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# ============================================================
# Module Management
# ============================================================

function Ensure-Module {
    param (
        [string]$ModuleName,
        [string]$InstallCommand = $ModuleName
    )
    if (-not (Get-Module -ListAvailable -Name $ModuleName)) {
        Write-Host "Module '$ModuleName' is not installed. Installing..."
        try {
            Install-Module -Name $InstallCommand -Scope CurrentUser -Force -AllowClobber
            Write-Host "Module '$ModuleName' installed successfully."
        } catch {
            Write-Error "Failed to install module '$ModuleName': $_"
        }
    } else {
        Write-Host "Module '$ModuleName' is already installed."
    }
}

Ensure-Module -ModuleName "Microsoft.Graph" -InstallCommand "Microsoft.Graph"
Ensure-Module -ModuleName "DSInternals.PassKeys"

# Explicitly import modules so .NET types are available for function definitions below
Import-Module Microsoft.Graph.Authentication -ErrorAction SilentlyContinue
Import-Module DSInternals.PassKeys -ErrorAction SilentlyContinue

# ============================================================
# Configuration Management (JSON in AppData)
# ============================================================

$script:ConfigDir  = Join-Path $env:APPDATA "FIDO2BulkEnroll"
$script:ConfigPath = Join-Path $script:ConfigDir "config.json"

function Get-DefaultConfig {
    return @{
        TenantId        = ""
        LogFilePath     = (Join-Path $PSScriptRoot "provisioning.log")
        RandomPin       = $true
        PinLength       = 6
        ForcePinChange  = $true
        CopyToClipboard = $true
        SamplePin       = "123457"
        EnableLog       = $true
    }
}

function Import-AppConfig {
    if (Test-Path $script:ConfigPath) {
        try {
            $json = Get-Content $script:ConfigPath -Raw | ConvertFrom-Json
            $defaults = Get-DefaultConfig
            $config = @{}
            foreach ($key in $defaults.Keys) {
                if ($null -ne $json.$key) {
                    $config[$key] = $json.$key
                } else {
                    $config[$key] = $defaults[$key]
                }
            }
            return $config
        } catch {
            Write-Host "Warning: Could not read config, using defaults."
            return (Get-DefaultConfig)
        }
    }
    return (Get-DefaultConfig)
}

function Export-AppConfig {
    param([hashtable]$Config)
    if (-not (Test-Path $script:ConfigDir)) {
        New-Item -Path $script:ConfigDir -ItemType Directory -Force | Out-Null
    }
    $Config | ConvertTo-Json -Depth 3 | Out-File $script:ConfigPath -Encoding UTF8 -Force
}

# ============================================================
# Utility Functions
# ============================================================

# From Posh-ACME (MIT, rmbolger) - https://github.com/rmbolger/Posh-ACME
function ConvertTo-Base64Url {
    [CmdletBinding()]
    [OutputType('System.String')]
    param(
        [Parameter(ParameterSetName='String',Mandatory,Position=0,ValueFromPipeline)]
        [AllowEmptyString()]
        [string]$Text,
        [Parameter(ParameterSetName='String')]
        [switch]$FromBase64,
        [Parameter(ParameterSetName='Bytes',Mandatory,Position=0)]
        [AllowEmptyCollection()]
        [byte[]]$Bytes
    )
    Process {
        if (-not $FromBase64) {
            if ($PSCmdlet.ParameterSetName -eq 'String') {
                $Bytes = [Text.Encoding]::UTF8.GetBytes($Text)
            }
            $s = [Convert]::ToBase64String($Bytes)
        } else {
            $s = $Text
        }
        $s = $s.Split('=')[0]
        $s = $s.Replace('+','-').Replace('/','_')
        return $s
    }
}

function Is-Numeric ($Value) {
    return $Value -match "^[\d]+$"
}

# From DSInternals.PassKeys v1.0.3 (MIT) - https://github.com/MichaelGrafnetter/webauthn-interop
function Get-MgGraphEndpoint {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    [Microsoft.Graph.PowerShell.Authentication.AuthContext] $context = Get-MgContext -ErrorAction Stop
    if ($null -ne $context) {
        return (Get-MgEnvironment -Name $context.Environment -ErrorAction Stop).GraphEndpoint
    } else {
        throw 'Not connected to Microsoft Graph.'
    }
}

# ============================================================
# CBOR Handling
# ============================================================

function cbor-build-len($type, $len) {
    if ($len -lt 24) {
        return (@($type + $len))
    }
    elseif ($len -lt 256) {
        $full = @()
        $full += @($type + 24)
        $full += @($len)
        return $full
    }
    elseif ($len -lt 65536) {
        $full = @()
        $full += @($type + 25)
        $full += @([int][Math]::Floor($len / 256))
        $full += @($len % 256)
        return $full
    }
    else {
        exit
    }
}

function str-to-bytes($str) {
    return ([System.Text.Encoding]::UTF8.GetBytes($str))
}

function cbor-build-text($str) {
    $typetxt = 96
    $strarray = str-to-bytes($str)
    $cborlen = cbor-build-len $typetxt $strarray.Count
    $full = @()
    $full += $cborlen
    $full += $strarray
    return $full
}

function cbor-build-bytes($b64) {
    $typebytes = 64
    $bytearray = [System.Convert]::FromBase64String($b64)
    $cborlen = cbor-build-len $typebytes $bytearray.Count
    $full = @()
    $full += $cborlen
    $full += $bytearray
    return $full
}

function build-att-object($sig, $authdata, $x5c, $alg = "es256") {
    $map = 160
    $array = 128

    if ($alg -ne "es256") { Exit }

    $cbor = @()
    Write-Host "Preparing CBOR attestation object..."
    $cbor += cbor-build-len $map 3
    $cbor += cbor-build-text("fmt")
    $cbor += cbor-build-text("packed")
    $cbor += cbor-build-text("attStmt")
    $cbor += cbor-build-len $map 3
    $cbor += cbor-build-text("alg")
    $cbor += @(38)
    $cbor += cbor-build-text("sig")
    $cbor += cbor-build-bytes($sig)
    $cbor += cbor-build-text("x5c")
    $cbor += cbor-build-len $array 1
    $cbor += cbor-build-bytes($x5c)
    $cbor += cbor-build-text("authData")
    $cbor += [System.Convert]::FromBase64String($authdata)
    $cborb64 = [System.Convert]::ToBase64String($cbor)
    return $cborb64
}

# ============================================================
# Passkey Registration Functions
# ============================================================

# Adapted from DSInternals.PassKeys v1.0.3 (MIT)
function Graph-Register-Custom-Passkey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Alias('User')]
        [string] $UserId,
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [String] $Passkey
    )
    process {
        [string] $endpoint = Get-MgGraphEndpoint
        [string] $registrationUrl = '{0}/beta/users/{1}/authentication/fido2Methods' -f $endpoint, [uri]::EscapeDataString($UserId)
        Write-Host "[Graph] POST $registrationUrl"
        Write-Host "[Graph] Payload size: $($Passkey.Length) chars"
        try {
            [string] $response = Invoke-MgGraphRequest `
                                    -Method POST `
                                    -Uri $registrationUrl `
                                    -OutputType Json `
                                    -ContentType 'application/json' `
                                    -Body $Passkey
            Write-Host "[Graph] Registration successful."
            return $response
        } catch {
            Write-Host "[Graph] Registration FAILED: $($_.Exception.Message)" -ForegroundColor Red
            if ($_.ErrorDetails.Message) {
                Write-Host "[Graph] Error details: $($_.ErrorDetails.Message)" -ForegroundColor Red
            }
            throw
        }
    }
}

# Adapted from DSInternals.PassKeys v1.0.3 (MIT) - bypasses Windows Hello
function CTAP-Create-Custom-Passkey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        $Options,
        [Parameter(Mandatory = $true)]
        [string] $DisplayName,
        [Parameter(Mandatory = $true)]
        [string] $pin
    )
    process {
        try {
            $rpid  = $Options.PublicKeyOptions.RelyingParty.id
            $uid   = [Convert]::ToBase64String($Options.PublicKeyOptions.User.Id)
            $uname = $Options.PublicKeyOptions.User.Name

            # Build ClientDataJSON
            $samplejson = '{"type":"webauthn.create","challenge":"TZxCee-4fMYIDJz_PbvmdfW82WarB4vaevgJpBK_F2w","origin":"https://site.tld","crossOrigin":false}'
            $clientdata = ConvertFrom-Json -InputObject $samplejson
            $clientdata.origin = "https://" + $rpid
            $chlb64url = ConvertTo-Base64Url $Options.PublicKeyOptions.challenge
            $clientdata.challenge = $chlb64url
            $clientDataJSON = ConvertTo-Json -InputObject $clientdata -Compress

            # Create clientDataHash
            $hasher = [System.Security.Cryptography.HashAlgorithm]::Create('sha256')
            $clientdatahashraw = $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($clientDataJSON))
            $clientdatahash = [Convert]::ToBase64String($clientdatahashraw)

            # Build CLI arguments
            $cli = "-w $pin -M"

            $uv = $Options.PublicKeyOptions.AuthenticatorSelection.UserVerificationRequirement
            if ($uv) { $cli = $cli + " -v" }

            $rk = $Options.PublicKeyOptions.AuthenticatorSelection.RequireResidentKey
            if ($rk) { $cli = $cli + " -r" }

            $hmac = $Options.PublicKeyOptions.Extensions.HmacCreateSecret
            if ($hmac) { $cli = $cli + " -h" }

            $cp = $Options.PublicKeyOptions.Extensions.CredProtect.value__
            if (Is-Numeric($cp)) { $cli = $cli + " -c " + $cp }

            # Find FIDO device (skip Windows Hello)
            Write-Host "[CTAP] Enumerating FIDO2 devices..."
            $devicelist = (& "$PSScriptRoot\libfido2-ui.exe" -L).Split([Environment]::NewLine)
            $devicepath = $null
            foreach ($fidodevice in $devicelist) {
                Write-Host "[CTAP]   Device: $fidodevice"
                $devPath = ($fidodevice -Split ": ")[0]
                if ($devPath -ne "windows://hello" -and -not [string]::IsNullOrWhiteSpace($devPath)) {
                    $devicepath = $devPath
                    Break
                }
            }
            if ([string]::IsNullOrWhiteSpace($devicepath)) {
                throw "No FIDO2 device found. Insert USB key or place NFC key on reader."
            }
            $cli = $cli + " $devicepath"
            Write-Host "[CTAP] Using device: $devicepath"
            Write-Host "[CTAP] CLI args: $cli"

            # Pipe input to fido2-cred2.exe
            $input = $clientdatahash + "`n" + $rpid + "`n" + $uname + "`n" + $uid + "`n"

            $oldEncoding = [console]::OutputEncoding
            [console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false

            Write-Host "[CTAP] Running fido2-cred2.exe..."
            $cred = $input | & "$PSScriptRoot\fido2-cred2.exe" $cli.split() 2>&1

            [console]::OutputEncoding = $oldEncoding

            # Check for errors
            $credStr = $cred | Out-String
            Write-Host "[CTAP] fido2-cred2 exit code: $LASTEXITCODE"
            if ([string]::IsNullOrWhiteSpace($credStr)) {
                throw "fido2-cred2.exe returned no output. The key may not be present or not responding."
            }
            if ($credStr -match "ERR|error" -and $LASTEXITCODE -ne 0) {
                Write-Host "[CTAP] fido2-cred2 output:`n$credStr"
                throw "fido2-cred2.exe failed: $($credStr.Trim()). If NFC: ensure key is on reader AND has a PIN already set (set PIN via USB first for new keys)."
            }

            # Parse output
            $credarray = $credStr.Trim() -Split "`n"
            Write-Host "[CTAP] fido2-cred2 returned $($credarray.Count) lines."
            if ($credarray.Count -lt 7) {
                Write-Host "[CTAP] Raw output:`n$credStr"
                throw "fido2-cred2.exe returned incomplete data ($($credarray.Count) lines, expected 7+). Credential creation may have failed on the key."
            }

            $authdata = $credarray[3].Trim()
            $sig      = $credarray[5].Trim()
            $x5c      = $credarray[6].Trim()

            Write-Host "[CTAP] Credential ID line: $($credarray[4].Trim().Substring(0, [Math]::Min(20, $credarray[4].Trim().Length)))..."
            Write-Host "[CTAP] Building attestation object..."
            $attobj = build-att-object $sig $authdata $x5c "es256"
            $credid = ConvertTo-Base64Url -FromBase64 $credarray[4].Trim()

            # Build credential JSON for Graph API
            $samplejson2 = @"
{
  "displayName": "Sample",
  "publicKeyCredential": {
    "id": "pgI",
    "response": {
      "clientDataJSON": "VGhpcy",
      "attestationObject": "VGhpcy"
    }
  }
}
"@
            $send = ConvertFrom-Json -InputObject $samplejson2
            $send.displayName = $DisplayName
            $send.publicKeyCredential.response.clientDataJSON = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($clientDataJSON))
            $send.publicKeyCredential.response.attestationObject = $attobj
            $send.publicKeyCredential.id = $credid
            $sendjson = ConvertTo-Json -InputObject $send
            Write-Host "[CTAP] Credential JSON built. ID: $($credid.Substring(0, [Math]::Min(20, $credid.Length)))..."
            return $sendjson
        }
        catch {
            throw
        }
    }
}

# ============================================================
# PIN Generation (6-digit with complexity checks)
# ============================================================

function Generate-RandomPin {
    param([int]$Length = 6)
    do {
        $pin = -join ((48..57) | Get-Random -Count $Length | ForEach-Object { [char]$_ })

        # Check for sequential numbers (6+ ascending/descending)
        $isSequential = $false
        for ($i = 0; $i -le ($pin.Length - 6); $i++) {
            $slice = $pin.Substring($i, 6)
            if ('0123456789'.Contains($slice) -or '9876543210'.Contains($slice)) {
                $isSequential = $true
                break
            }
        }

        # Check for repeated digits (4+ in a row)
        $hasRepeatedDigits = $pin -match '(\d)\1{3,}'

        # Check for palindrome
        $charArray = $pin.ToCharArray()
        [Array]::Reverse($charArray)
        $reversedPin = -join $charArray
        $isPalindrome = ($pin -eq $reversedPin)

    } while ($isSequential -or $hasRepeatedDigits -or $isPalindrome)

    return $pin
}

# ============================================================
# UI Helper
# ============================================================

function Update-UI {
    [System.Windows.Forms.Application]::DoEvents()
}

# Run an external exe with a timeout (avoids hangs when device is not present)
function Run-ExeWithTimeout {
    param(
        [string]$Path,
        [string]$Arguments = "",
        [int]$TimeoutMs = 3000
    )
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Path
    $psi.Arguments = $Arguments
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true

    $process = [System.Diagnostics.Process]::Start($psi)
    $stdoutTask = $process.StandardOutput.ReadToEndAsync()

    if (-not $process.WaitForExit($TimeoutMs)) {
        try { $process.Kill() } catch {}
        try { $process.WaitForExit(1000) } catch {}
        return $null
    }

    return $stdoutTask.GetAwaiter().GetResult().Trim()
}

# ============================================================
# Entra ID User Search
# ============================================================

function Search-EntraUsers {
    param([string]$SearchTerm)

    if ([string]::IsNullOrWhiteSpace($SearchTerm)) { return @() }

    $escaped = $SearchTerm.Replace("'", "''")
    $endpoint = Get-MgGraphEndpoint

    # Try combined displayName + UPN search (requires ConsistencyLevel=eventual)
    try {
        $filter = "startswith(displayName,'$escaped') or startswith(userPrincipalName,'$escaped') or startswith(mail,'$escaped')"
        $url = "$endpoint/v1.0/users?`$filter=$filter&`$top=25&`$select=displayName,userPrincipalName&`$orderby=displayName&`$count=true"
        $response = Invoke-MgGraphRequest -Method GET -Uri $url -Headers @{ 'ConsistencyLevel' = 'eventual' } -OutputType PSObject
        return $response.value
    } catch {
        # Fallback: search displayName only (no ConsistencyLevel needed)
        try {
            $filter = "startswith(displayName,'$escaped')"
            $url = "$endpoint/v1.0/users?`$filter=$filter&`$top=25&`$select=displayName,userPrincipalName&`$orderby=displayName"
            $response = Invoke-MgGraphRequest -Method GET -Uri $url -OutputType PSObject
            return $response.value
        } catch {
            throw
        }
    }
}

# ============================================================
# Device Code Authentication (GUI-based)
# ============================================================

function Connect-GraphDeviceCode {
    param(
        [string]$TenantId,
        [string[]]$Scopes
    )

    # Microsoft Graph PowerShell SDK public client ID
    $clientId = "14d82eec-204b-4c2f-b7e8-296a70dab67e"

    # Build fully qualified scope string
    $scopeString = ($Scopes | ForEach-Object { "https://graph.microsoft.com/$_" }) -join " "
    $scopeString += " offline_access openid profile"

    # Step 1: Request device code from Azure AD
    $deviceCodeResponse = Invoke-RestMethod -Method Post `
        -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/devicecode" `
        -Body @{ client_id = $clientId; scope = $scopeString }

    $userCode       = $deviceCodeResponse.user_code
    $verificationUri = $deviceCodeResponse.verification_uri
    $deviceCode     = $deviceCodeResponse.device_code
    $pollInterval   = [Math]::Max($deviceCodeResponse.interval, 5)

    # Step 2: Build the sign-in dialog
    $codeDlg = New-Object System.Windows.Forms.Form
    $codeDlg.Text = "Sign In with Device Code"
    $codeDlg.Size = New-Object System.Drawing.Size(440, 300)
    $codeDlg.StartPosition = "CenterScreen"
    $codeDlg.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $codeDlg.MaximizeBox = $false
    $codeDlg.MinimizeBox = $false
    $codeDlg.TopMost = $true
    $codeDlg.Font = New-Object System.Drawing.Font("Segoe UI", 9)

    $lblStep1 = New-Object System.Windows.Forms.Label
    $lblStep1.Text = "1. Open this URL in your browser:"
    $lblStep1.Location = New-Object System.Drawing.Point(20, 15)
    $lblStep1.AutoSize = $true
    $codeDlg.Controls.Add($lblStep1)

    $txtUrl = New-Object System.Windows.Forms.TextBox
    $txtUrl.Text = $verificationUri
    $txtUrl.ReadOnly = $true
    $txtUrl.Location = New-Object System.Drawing.Point(30, 38)
    $txtUrl.Width = 280
    $txtUrl.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $txtUrl.BackColor = [System.Drawing.Color]::White
    $codeDlg.Controls.Add($txtUrl)

    $btnCopyUrl = New-Object System.Windows.Forms.Button
    $btnCopyUrl.Text = "Copy URL"
    $btnCopyUrl.Location = New-Object System.Drawing.Point(320, 37)
    $btnCopyUrl.Size = New-Object System.Drawing.Size(80, 26)
    $btnCopyUrl.Add_Click({
        Set-Clipboard -Value $verificationUri
        $btnCopyUrl.Text = "Copied!"
    })
    $codeDlg.Controls.Add($btnCopyUrl)

    $lblStep2 = New-Object System.Windows.Forms.Label
    $lblStep2.Text = "2. Enter this code:"
    $lblStep2.Location = New-Object System.Drawing.Point(20, 72)
    $lblStep2.AutoSize = $true
    $codeDlg.Controls.Add($lblStep2)

    $txtCode = New-Object System.Windows.Forms.TextBox
    $txtCode.Text = $userCode
    $txtCode.ReadOnly = $true
    $txtCode.Location = New-Object System.Drawing.Point(30, 96)
    $txtCode.Size = New-Object System.Drawing.Size(200, 35)
    $txtCode.Font = New-Object System.Drawing.Font("Consolas", 18, [System.Drawing.FontStyle]::Bold)
    $txtCode.TextAlign = [System.Windows.Forms.HorizontalAlignment]::Center
    $txtCode.BackColor = [System.Drawing.Color]::White
    $codeDlg.Controls.Add($txtCode)

    $btnCopy = New-Object System.Windows.Forms.Button
    $btnCopy.Text = "Copy Code"
    $btnCopy.Location = New-Object System.Drawing.Point(240, 98)
    $btnCopy.Size = New-Object System.Drawing.Size(90, 30)
    $codeDlg.Controls.Add($btnCopy)

    $btnCopy.Add_Click({
        Set-Clipboard -Value $userCode
        $btnCopy.Text = "Copied!"
    })

    $lblStep3 = New-Object System.Windows.Forms.Label
    $lblStep3.Text = "3. Sign in with your admin account in the browser."
    $lblStep3.Location = New-Object System.Drawing.Point(20, 145)
    $lblStep3.AutoSize = $true
    $codeDlg.Controls.Add($lblStep3)

    $lblWaiting = New-Object System.Windows.Forms.Label
    $lblWaiting.Text = "Waiting for sign-in..."
    $lblWaiting.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $lblWaiting.ForeColor = [System.Drawing.Color]::DarkBlue
    $lblWaiting.Location = New-Object System.Drawing.Point(20, 180)
    $lblWaiting.AutoSize = $true
    $codeDlg.Controls.Add($lblWaiting)

    $btnCancel = New-Object System.Windows.Forms.Button
    $btnCancel.Text = "Cancel"
    $btnCancel.Location = New-Object System.Drawing.Point(20, 218)
    $btnCancel.Size = New-Object System.Drawing.Size(80, 30)
    $codeDlg.Controls.Add($btnCancel)
    $btnCancel.Add_Click({
        $codeDlg.Tag = "cancelled"
        $codeDlg.Close()
    })

    # Step 3: Poll for token using a WinForms Timer (fires on UI thread)
    $pollTimer = New-Object System.Windows.Forms.Timer
    $pollTimer.Interval = $pollInterval * 1000

    $pollTimer.Add_Tick({
        try {
            $tokenBody = @{
                grant_type  = "urn:ietf:params:oauth:grant-type:device_code"
                client_id   = $clientId
                device_code = $deviceCode
            }
            $tokenResponse = Invoke-RestMethod -Method Post `
                -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
                -Body $tokenBody

            # Auth succeeded - store token and close dialog
            $codeDlg.Tag = $tokenResponse.access_token
            $pollTimer.Stop()
            $lblWaiting.Text = "Sign-in successful!"
            $lblWaiting.ForeColor = [System.Drawing.Color]::DarkGreen
            Update-UI
            $codeDlg.Close()
        } catch {
            $errJson = $null
            try { $errJson = $_.ErrorDetails.Message | ConvertFrom-Json } catch {}

            if ($null -ne $errJson -and $errJson.error -eq "authorization_pending") {
                return  # still waiting, keep polling
            }
            elseif ($null -ne $errJson -and $errJson.error -eq "expired_token") {
                $pollTimer.Stop()
                $lblWaiting.Text = "Code expired. Close and try again."
                $lblWaiting.ForeColor = [System.Drawing.Color]::Red
            }
            else {
                $pollTimer.Stop()
                $lblWaiting.Text = "Error: $($_.Exception.Message)"
                $lblWaiting.ForeColor = [System.Drawing.Color]::Red
            }
        }
    })

    # Copy code to clipboard (don't auto-open browser - user may need a specific profile)
    Set-Clipboard -Value $userCode

    $pollTimer.Start()
    $codeDlg.ShowDialog() | Out-Null
    $pollTimer.Stop()
    $pollTimer.Dispose()

    # Check result
    $accessToken = $codeDlg.Tag
    $codeDlg.Dispose()

    if ($null -eq $accessToken -or $accessToken -eq "cancelled") {
        throw "Authentication was cancelled."
    }

    # Step 4: Connect to Graph with the obtained token
    $secureToken = ConvertTo-SecureString $accessToken -AsPlainText -Force
    Connect-MgGraph -AccessToken $secureToken -NoWelcome
}

# ============================================================
# Enrollment Dialog (single user)
# ============================================================

function Show-EnrollmentDialog {
    param(
        [string]$Upn,
        [bool]$UseRandomPin,
        [int]$PinLength = 6,
        [bool]$ForcePinChange,
        [bool]$CopyToClipboard,
        [string]$SamplePin,
        [string]$LogPath
    )

    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = "Enroll Key - $Upn"
    $dlg.Size = New-Object System.Drawing.Size(500, 410)
    $dlg.StartPosition = "CenterScreen"
    $dlg.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $dlg.MaximizeBox = $false
    $dlg.MinimizeBox = $false

    $fontNormal = New-Object System.Drawing.Font("Segoe UI", 9)
    $fontBold   = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $fontTitle  = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
    $fontPin    = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
    $dlg.Font = $fontNormal

    # --- Title ---
    $lblTitle = New-Object System.Windows.Forms.Label
    $lblTitle.Text = "Enroll FIDO2 Key"
    $lblTitle.Font = $fontTitle
    $lblTitle.Location = New-Object System.Drawing.Point(15, 12)
    $lblTitle.AutoSize = $true
    $dlg.Controls.Add($lblTitle)

    # --- Device detection banner ---
    $pnlDevice = New-Object System.Windows.Forms.Panel
    $pnlDevice.Location = New-Object System.Drawing.Point(15, 42)
    $pnlDevice.Size = New-Object System.Drawing.Size(455, 30)
    $pnlDevice.BackColor = [System.Drawing.Color]::FromArgb(232, 244, 253)
    $dlg.Controls.Add($pnlDevice)

    $lblDevice = New-Object System.Windows.Forms.Label
    $lblDevice.Text = "Detecting FIDO2 device..."
    $lblDevice.Location = New-Object System.Drawing.Point(8, 6)
    $lblDevice.AutoSize = $true
    $lblDevice.Font = $fontNormal
    $pnlDevice.Controls.Add($lblDevice)

    # --- User ---
    $lblUserLabel = New-Object System.Windows.Forms.Label
    $lblUserLabel.Text = "User:"
    $lblUserLabel.Font = $fontBold
    $lblUserLabel.Location = New-Object System.Drawing.Point(15, 84)
    $lblUserLabel.AutoSize = $true
    $dlg.Controls.Add($lblUserLabel)

    $lblUserValue = New-Object System.Windows.Forms.Label
    $lblUserValue.Text = $Upn
    $lblUserValue.Location = New-Object System.Drawing.Point(120, 84)
    $lblUserValue.AutoSize = $true
    $dlg.Controls.Add($lblUserValue)

    # --- Serial Number (editable + Read Key button) ---
    $lblSerialLabel = New-Object System.Windows.Forms.Label
    $lblSerialLabel.Text = "Serial Number:"
    $lblSerialLabel.Font = $fontBold
    $lblSerialLabel.Location = New-Object System.Drawing.Point(15, 114)
    $lblSerialLabel.AutoSize = $true
    $dlg.Controls.Add($lblSerialLabel)

    $txtSerial = New-Object System.Windows.Forms.TextBox
    $txtSerial.Location = New-Object System.Drawing.Point(120, 111)
    $txtSerial.Width = 250
    $dlg.Controls.Add($txtSerial)

    $btnReadKey = New-Object System.Windows.Forms.Button
    $btnReadKey.Text = "Read Key"
    $btnReadKey.Location = New-Object System.Drawing.Point(380, 109)
    $btnReadKey.Size = New-Object System.Drawing.Size(90, 26)
    $dlg.Controls.Add($btnReadKey)

    # --- PIN ---
    $lblPinLabel = New-Object System.Windows.Forms.Label
    $lblPinLabel.Text = "PIN:"
    $lblPinLabel.Font = $fontBold
    $lblPinLabel.Location = New-Object System.Drawing.Point(15, 148)
    $lblPinLabel.AutoSize = $true
    $dlg.Controls.Add($lblPinLabel)

    $lblPinValue = New-Object System.Windows.Forms.Label
    $lblPinValue.Font = $fontPin
    $lblPinValue.Location = New-Object System.Drawing.Point(120, 145)
    $lblPinValue.AutoSize = $true
    $dlg.Controls.Add($lblPinValue)

    # --- Tip panel ---
    $pnlTip = New-Object System.Windows.Forms.Panel
    $pnlTip.Location = New-Object System.Drawing.Point(15, 180)
    $pnlTip.Size = New-Object System.Drawing.Size(455, 52)
    $pnlTip.BackColor = [System.Drawing.Color]::FromArgb(255, 243, 205)
    $dlg.Controls.Add($pnlTip)

    $lblTip = New-Object System.Windows.Forms.Label
    $lblTip.Text = "USB: Touch the metal contact when the key blinks.`nNFC: Hold key on reader during enrollment. Serial auto-read may not work over NFC."
    $lblTip.Location = New-Object System.Drawing.Point(8, 4)
    $lblTip.Size = New-Object System.Drawing.Size(440, 44)
    $lblTip.Font = New-Object System.Drawing.Font("Segoe UI", 8.5)
    $pnlTip.Controls.Add($lblTip)

    # --- Status ---
    $lblStatus = New-Object System.Windows.Forms.Label
    $lblStatus.Text = "Ready to enroll."
    $lblStatus.Font = $fontBold
    $lblStatus.Location = New-Object System.Drawing.Point(15, 246)
    $lblStatus.Size = New-Object System.Drawing.Size(455, 40)
    $dlg.Controls.Add($lblStatus)

    # --- Buttons ---
    $btnEnroll = New-Object System.Windows.Forms.Button
    $btnEnroll.Text = "Enroll"
    $btnEnroll.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $btnEnroll.Location = New-Object System.Drawing.Point(15, 293)
    $btnEnroll.Size = New-Object System.Drawing.Size(110, 34)
    $dlg.Controls.Add($btnEnroll)

    $btnClose = New-Object System.Windows.Forms.Button
    $btnClose.Text = "Close"
    $btnClose.Location = New-Object System.Drawing.Point(135, 293)
    $btnClose.Size = New-Object System.Drawing.Size(80, 34)
    $dlg.Controls.Add($btnClose)

    # --- Result tracking ---
    $result = @{ Value = "closed"; Pin = ""; ForcedPin = $false }

    # --- Generate PIN immediately ---
    if ($UseRandomPin) {
        $result.Pin = Generate-RandomPin -Length $PinLength
    } else {
        $result.Pin = $SamplePin
    }
    $lblPinValue.Text = $result.Pin

    if ($CopyToClipboard) {
        Set-Clipboard -Value $result.Pin
        Write-Host "PIN copied to clipboard: $($result.Pin)"
    }

    # --- Detect FIDO device on open (with timeout to avoid hang) ---
    $script:detectedDeviceType = "unknown"
    try {
        $deviceRaw = Run-ExeWithTimeout -Path "$PSScriptRoot\libfido2-ui.exe" -Arguments "-L" -TimeoutMs 3000
        if ($null -ne $deviceRaw -and $deviceRaw.Length -gt 0) {
            $devicelist = $deviceRaw.Split([Environment]::NewLine)
            $foundDevice = $null
            foreach ($fidodevice in $devicelist) {
                $devPath = ($fidodevice -Split ": ")[0]
                if ($devPath -ne "windows://hello" -and -not [string]::IsNullOrWhiteSpace($devPath)) {
                    $foundDevice = $fidodevice.Trim()
                    if ($fidodevice -match "pcsc://|nfc|contactless|omnikey|5022") {
                        $script:detectedDeviceType = "nfc"
                    } else {
                        $script:detectedDeviceType = "usb"
                    }
                    break
                }
            }
            if ($null -ne $foundDevice) {
                if ($script:detectedDeviceType -eq "nfc") {
                    $lblDevice.Text = "NFC reader detected: $foundDevice"
                    $pnlDevice.BackColor = [System.Drawing.Color]::FromArgb(232, 248, 232)
                } else {
                    $lblDevice.Text = "USB device detected: $foundDevice"
                }
            } else {
                $lblDevice.Text = "No FIDO2 device found. Insert USB key or place key on NFC reader."
                $pnlDevice.BackColor = [System.Drawing.Color]::FromArgb(253, 232, 232)
            }
        } else {
            $lblDevice.Text = "No FIDO2 device found. Insert USB key or place key on NFC reader."
            $pnlDevice.BackColor = [System.Drawing.Color]::FromArgb(253, 232, 232)
        }
    } catch {
        $lblDevice.Text = "Device detection timed out. Enrollment may still work."
        $pnlDevice.BackColor = [System.Drawing.Color]::FromArgb(255, 243, 205)
    }

    # --- Read Key button (with timeout) ---
    $btnReadKey.Add_Click({
        $lblStatus.Text = "Reading serial number (USB only)..."
        $lblStatus.ForeColor = [System.Drawing.Color]::DarkBlue
        $btnReadKey.Enabled = $false
        Update-UI
        try {
            $serial = Run-ExeWithTimeout -Path "$PSScriptRoot\read_serial_t2.exe" -TimeoutMs 4000
            if (-not [string]::IsNullOrWhiteSpace($serial) -and $serial -ne "None") {
                $txtSerial.Text = $serial
                $lblStatus.Text = "Serial read successfully."
                $lblStatus.ForeColor = [System.Drawing.Color]::DarkGreen
            } else {
                $lblStatus.Text = "Could not read serial. Type it manually or leave blank."
                $lblStatus.ForeColor = [System.Drawing.Color]::FromArgb(180, 120, 0)
            }
        } catch {
            $lblStatus.Text = "Read timed out. For NFC keys, type serial manually or leave blank."
            $lblStatus.ForeColor = [System.Drawing.Color]::FromArgb(180, 120, 0)
        }
        $btnReadKey.Enabled = $true
    })

    # --- Enroll button ---
    $btnEnroll.Add_Click({
        $btnEnroll.Enabled  = $false
        $btnClose.Enabled   = $false
        $btnReadKey.Enabled = $false
        $txtSerial.Enabled  = $false

        $pin = $result.Pin
        $serial = $txtSerial.Text.Trim()
        if ([string]::IsNullOrWhiteSpace($serial)) { $serial = "FIDO2Key" }

        try {
            Write-Host ""
            Write-Host "===== Enrollment started for $Upn =====" -ForegroundColor Cyan
            Write-Host "[Enroll] Serial: '$serial' | PIN: $pin | Device type: $($script:detectedDeviceType)"

            # Step 1: Set PIN on key
            $lblStatus.Text = "Setting PIN on key..."
            $lblStatus.ForeColor = [System.Drawing.Color]::DarkBlue
            Update-UI
            Write-Host "[Enroll] Step 1: Setting PIN via fido2-manage.exe -setPIN -pin $pin -device 1"
            $setPinOutput = & "$PSScriptRoot\fido2-manage.exe" -setPIN -pin $pin -device 1 2>&1
            $setPinStr = $setPinOutput | Out-String
            $setPinFailed = $setPinStr -match "ERR|error|Invalid"
            Write-Host "[Enroll] Step 1 result (exit=$LASTEXITCODE): $($setPinStr.Trim())"

            if ($setPinFailed) {
                # Key likely already has a PIN - ask the admin what to do
                Write-Host "[Enroll] setPIN failed - key may already have a PIN set." -ForegroundColor Yellow

                $pinPrompt = New-Object System.Windows.Forms.Form
                $pinPrompt.Text = "Key Already Has a PIN"
                $pinPrompt.Size = New-Object System.Drawing.Size(420, 220)
                $pinPrompt.StartPosition = "CenterScreen"
                $pinPrompt.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
                $pinPrompt.MaximizeBox = $false
                $pinPrompt.MinimizeBox = $false
                $pinPrompt.TopMost = $true
                $pinPrompt.Font = New-Object System.Drawing.Font("Segoe UI", 9)

                $lblPinPrompt = New-Object System.Windows.Forms.Label
                $lblPinPrompt.Text = "This key already has a PIN set.`nSetting a new PIN failed.`n`nEnter the current PIN to continue enrollment,`nor use a fresh key with no PIN."
                $lblPinPrompt.Location = New-Object System.Drawing.Point(15, 12)
                $lblPinPrompt.Size = New-Object System.Drawing.Size(380, 80)
                $pinPrompt.Controls.Add($lblPinPrompt)

                $lblExisting = New-Object System.Windows.Forms.Label
                $lblExisting.Text = "Current PIN:"
                $lblExisting.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
                $lblExisting.Location = New-Object System.Drawing.Point(15, 100)
                $lblExisting.AutoSize = $true
                $pinPrompt.Controls.Add($lblExisting)

                $txtExistingPin = New-Object System.Windows.Forms.TextBox
                $txtExistingPin.Location = New-Object System.Drawing.Point(105, 97)
                $txtExistingPin.Width = 150
                $txtExistingPin.Font = New-Object System.Drawing.Font("Consolas", 12)
                $pinPrompt.Controls.Add($txtExistingPin)

                $btnPinOk = New-Object System.Windows.Forms.Button
                $btnPinOk.Text = "Continue"
                $btnPinOk.Location = New-Object System.Drawing.Point(15, 140)
                $btnPinOk.Size = New-Object System.Drawing.Size(90, 30)
                $btnPinOk.Add_Click({
                    if ([string]::IsNullOrWhiteSpace($txtExistingPin.Text)) {
                        [System.Windows.Forms.MessageBox]::Show("Please enter the current PIN.", "PIN Required")
                        return
                    }
                    $pinPrompt.Tag = $txtExistingPin.Text.Trim()
                    $pinPrompt.Close()
                })
                $pinPrompt.Controls.Add($btnPinOk)

                $btnPinCancel = New-Object System.Windows.Forms.Button
                $btnPinCancel.Text = "Cancel"
                $btnPinCancel.Location = New-Object System.Drawing.Point(115, 140)
                $btnPinCancel.Size = New-Object System.Drawing.Size(80, 30)
                $btnPinCancel.Add_Click({
                    $pinPrompt.Tag = $null
                    $pinPrompt.Close()
                })
                $pinPrompt.Controls.Add($btnPinCancel)

                $pinPrompt.ShowDialog() | Out-Null
                $existingPin = $pinPrompt.Tag
                $pinPrompt.Dispose()

                if ([string]::IsNullOrWhiteSpace($existingPin)) {
                    throw "Enrollment cancelled - PIN required."
                }

                # Use the existing PIN for credential creation
                $pin = $existingPin
                Write-Host "[Enroll] Using existing PIN provided by admin."
            } else {
                Write-Host "[Enroll] Step 1: PIN set successfully."
            }

            # Step 2: Get registration options from Graph + create credential on key
            if ($script:detectedDeviceType -eq "nfc") {
                $lblStatus.Text = "Creating credential... Hold key on NFC reader."
            } else {
                $lblStatus.Text = "Creating credential... Touch key if it blinks."
            }
            Update-UI

            Write-Host "[Enroll] Step 2: Getting passkey registration options from Graph..."
            $regOptions = Get-PasskeyRegistrationOptions -UserId $Upn
            Write-Host "[Enroll] Step 2: Got options. RPID: $($regOptions.PublicKeyOptions.RelyingParty.id)"
            Write-Host "[Enroll] Step 2: Creating credential on key (fido2-cred2.exe)..."
            $passkey = $regOptions | CTAP-Create-Custom-Passkey -DisplayName $serial -pin $pin
            Write-Host "[Enroll] Step 2: Credential created successfully."

            # Step 3: Register with Entra ID
            $lblStatus.Text = "Registering with Entra ID..."
            Update-UI
            Write-Host "[Enroll] Step 3: Registering credential with Entra ID..."
            $passkey | Graph-Register-Custom-Passkey -UserId $Upn

            Write-Host "[Enroll] Step 3: Passkey registered successfully for $Upn." -ForegroundColor Green

            # Step 4: Force PIN change (requires FIDO2.1 Final firmware - non-fatal if unsupported)
            $forcePinNote = ""
            if ($ForcePinChange) {
                $lblStatus.Text = "Forcing PIN change..."
                Update-UI
                Write-Host "[Enroll] Step 4: Forcing PIN change..."
                $forcePinOutput = & "$PSScriptRoot\fido2-manage.exe" -forcePINchange -pin $pin -device 1 2>&1
                $forcePinStr = $forcePinOutput | Out-String
                $forcePinFailed = $LASTEXITCODE -ne 0 -or $forcePinStr -match "ERR|error|Invalid"
                if ($forcePinFailed) {
                    Write-Host "[Enroll] Step 4: Force PIN change failed: $($forcePinStr.Trim())" -ForegroundColor Yellow
                    $result.ForcedPin = $false
                    $forcePinNote = "`n`nNote: Force PIN change is not supported by this key.`nThis feature requires FIDO2.1 Final firmware.`nThe user will keep the PIN shown above."
                } else {
                    Write-Host "[Enroll] Step 4: PIN change forced successfully."
                    $result.ForcedPin = $true
                }
            }

            # Log (if enabled)
            if (-not [string]::IsNullOrWhiteSpace($LogPath)) {
                if (-not (Test-Path $LogPath)) {
                    "UPN,Serial Number,PIN,ForcePINChange" | Out-File -FilePath $LogPath -Encoding UTF8
                }
                "$Upn,$serial,$pin,$($result.ForcedPin)" | Out-File -FilePath $LogPath -Append -Encoding UTF8
                Write-Host "Logged results for $Upn."
            }

            $lblStatus.Text = "Enrolled successfully!"
            $lblStatus.ForeColor = [System.Drawing.Color]::DarkGreen
            Update-UI

            $result.Value = "enrolled"

            # Show PIN confirmation dialog - user must acknowledge they noted it
            $pinDlg = New-Object System.Windows.Forms.Form
            $pinDlg.Text = "Enrollment Complete - Note the PIN"
            $pinDlg.Size = New-Object System.Drawing.Size(400, 310)
            $pinDlg.StartPosition = "CenterScreen"
            $pinDlg.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
            $pinDlg.MaximizeBox = $false
            $pinDlg.MinimizeBox = $false
            $pinDlg.TopMost = $true
            $pinDlg.Font = New-Object System.Drawing.Font("Segoe UI", 9)
            $pinDlg.ControlBox = $false

            $lblPinSuccess = New-Object System.Windows.Forms.Label
            $lblPinSuccess.Text = "Key enrolled successfully for:`n$Upn"
            $lblPinSuccess.Location = New-Object System.Drawing.Point(20, 15)
            $lblPinSuccess.Size = New-Object System.Drawing.Size(350, 38)
            $lblPinSuccess.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
            $lblPinSuccess.ForeColor = [System.Drawing.Color]::DarkGreen
            $pinDlg.Controls.Add($lblPinSuccess)

            $lblPinHeader = New-Object System.Windows.Forms.Label
            $lblPinHeader.Text = "Give this PIN to the user:"
            $lblPinHeader.Location = New-Object System.Drawing.Point(20, 60)
            $lblPinHeader.AutoSize = $true
            $pinDlg.Controls.Add($lblPinHeader)

            $txtPinDisplay = New-Object System.Windows.Forms.TextBox
            $txtPinDisplay.Text = $pin
            $txtPinDisplay.ReadOnly = $true
            $txtPinDisplay.Location = New-Object System.Drawing.Point(20, 85)
            $txtPinDisplay.Size = New-Object System.Drawing.Size(200, 40)
            $txtPinDisplay.Font = New-Object System.Drawing.Font("Consolas", 24, [System.Drawing.FontStyle]::Bold)
            $txtPinDisplay.TextAlign = [System.Windows.Forms.HorizontalAlignment]::Center
            $txtPinDisplay.BackColor = [System.Drawing.Color]::White
            $pinDlg.Controls.Add($txtPinDisplay)

            $btnCopyPin = New-Object System.Windows.Forms.Button
            $btnCopyPin.Text = "Copy PIN"
            $btnCopyPin.Location = New-Object System.Drawing.Point(230, 90)
            $btnCopyPin.Size = New-Object System.Drawing.Size(90, 30)
            $btnCopyPin.Add_Click({
                Set-Clipboard -Value $pin
                $btnCopyPin.Text = "Copied!"
            })
            $pinDlg.Controls.Add($btnCopyPin)

            if ($forcePinNote) {
                $lblForceNote = New-Object System.Windows.Forms.Label
                $lblForceNote.Text = "Note: Force PIN change not supported by this key (requires FIDO2.1).`nThe user will keep this PIN."
                $lblForceNote.Location = New-Object System.Drawing.Point(20, 135)
                $lblForceNote.Size = New-Object System.Drawing.Size(350, 35)
                $lblForceNote.ForeColor = [System.Drawing.Color]::FromArgb(180, 120, 0)
                $lblForceNote.Font = New-Object System.Drawing.Font("Segoe UI", 8)
                $pinDlg.Controls.Add($lblForceNote)
            }

            $chkConfirmPin = New-Object System.Windows.Forms.CheckBox
            $chkConfirmPin.Text = "I have noted down / communicated the PIN to the user"
            $chkConfirmPin.Location = New-Object System.Drawing.Point(20, 185)
            $chkConfirmPin.AutoSize = $true
            $chkConfirmPin.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
            $pinDlg.Controls.Add($chkConfirmPin)

            $btnPinDone = New-Object System.Windows.Forms.Button
            $btnPinDone.Text = "Done"
            $btnPinDone.Location = New-Object System.Drawing.Point(20, 220)
            $btnPinDone.Size = New-Object System.Drawing.Size(100, 34)
            $btnPinDone.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
            $btnPinDone.Enabled = $false
            $pinDlg.Controls.Add($btnPinDone)

            $chkConfirmPin.Add_CheckedChanged({
                $btnPinDone.Enabled = $chkConfirmPin.Checked
            })

            $btnPinDone.Add_Click({ $pinDlg.Close() })

            $pinDlg.ShowDialog() | Out-Null
            $pinDlg.Dispose()

            $dlg.Close()

        } catch {
            Write-Host "Error during enrollment for ${Upn}: $($_.Exception.Message)"
            $lblStatus.Text = "Error: $($_.Exception.Message)"
            $lblStatus.ForeColor = [System.Drawing.Color]::Red
            $btnClose.Enabled   = $true
            $btnEnroll.Enabled  = $true
            $btnReadKey.Enabled = $true
            $txtSerial.Enabled  = $true
        }
    })

    # --- Close button ---
    $btnClose.Add_Click({ $dlg.Close() })

    $dlg.ShowDialog() | Out-Null
    return $result.Value
}

# ============================================================
# Main Window
# ============================================================

$script:IsConnected = $false

$form = New-Object System.Windows.Forms.Form
$form.Text = "FIDO2 Bulk Enrollment - Entra ID"
$form.Size = New-Object System.Drawing.Size(580, 735)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedSingle
$form.MaximizeBox = $false
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9)

# --- Title ---
$lblFormTitle = New-Object System.Windows.Forms.Label
$lblFormTitle.Text = "FIDO2 Bulk Enrollment Tool"
$lblFormTitle.Font = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
$lblFormTitle.ForeColor = [System.Drawing.Color]::FromArgb(26, 26, 46)
$lblFormTitle.Location = New-Object System.Drawing.Point(18, 10)
$lblFormTitle.AutoSize = $true
$form.Controls.Add($lblFormTitle)

# ============================================================
# GroupBox: Tenant Configuration
# ============================================================

$grpTenant = New-Object System.Windows.Forms.GroupBox
$grpTenant.Text = "Tenant Configuration"
$grpTenant.Location = New-Object System.Drawing.Point(15, 42)
$grpTenant.Size = New-Object System.Drawing.Size(535, 55)
$form.Controls.Add($grpTenant)

$lblTenantId = New-Object System.Windows.Forms.Label
$lblTenantId.Text = "Tenant ID:"
$lblTenantId.Location = New-Object System.Drawing.Point(12, 23)
$lblTenantId.AutoSize = $true
$grpTenant.Controls.Add($lblTenantId)

$txtTenantId = New-Object System.Windows.Forms.TextBox
$txtTenantId.Location = New-Object System.Drawing.Point(90, 20)
$txtTenantId.Width = 430
$grpTenant.Controls.Add($txtTenantId)

# ============================================================
# GroupBox: Authentication
# ============================================================

$grpAuth = New-Object System.Windows.Forms.GroupBox
$grpAuth.Text = "Authentication"
$grpAuth.Location = New-Object System.Drawing.Point(15, 103)
$grpAuth.Size = New-Object System.Drawing.Size(535, 100)
$form.Controls.Add($grpAuth)

$lblStatusDot = New-Object System.Windows.Forms.Label
$lblStatusDot.Text = [char]0x25CF  # filled circle
$lblStatusDot.Font = New-Object System.Drawing.Font("Segoe UI", 11)
$lblStatusDot.ForeColor = [System.Drawing.Color]::Red
$lblStatusDot.Location = New-Object System.Drawing.Point(12, 20)
$lblStatusDot.AutoSize = $true
$grpAuth.Controls.Add($lblStatusDot)

$lblAuthStatus = New-Object System.Windows.Forms.Label
$lblAuthStatus.Text = "Not connected"
$lblAuthStatus.Location = New-Object System.Drawing.Point(30, 22)
$lblAuthStatus.AutoSize = $true
$grpAuth.Controls.Add($lblAuthStatus)

$btnSignIn = New-Object System.Windows.Forms.Button
$btnSignIn.Text = "Sign In"
$btnSignIn.Location = New-Object System.Drawing.Point(12, 46)
$btnSignIn.Size = New-Object System.Drawing.Size(90, 26)
$grpAuth.Controls.Add($btnSignIn)

$btnSignOut = New-Object System.Windows.Forms.Button
$btnSignOut.Text = "Sign Out"
$btnSignOut.Location = New-Object System.Drawing.Point(110, 46)
$btnSignOut.Size = New-Object System.Drawing.Size(90, 26)
$btnSignOut.Enabled = $false
$grpAuth.Controls.Add($btnSignOut)

$chkDeviceCode = New-Object System.Windows.Forms.CheckBox
$chkDeviceCode.Text = "Use device code login (recommended for admin accounts)"
$chkDeviceCode.Location = New-Object System.Drawing.Point(12, 74)
$chkDeviceCode.AutoSize = $true
$chkDeviceCode.Font = New-Object System.Drawing.Font("Segoe UI", 8)
$grpAuth.Controls.Add($chkDeviceCode)

# Auto-enable device code when running as Administrator (WAM browser auth fails elevated)
$script:IsElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($script:IsElevated) {
    $chkDeviceCode.Checked = $true
}

# ============================================================
# GroupBox: User Selection
# ============================================================

$grpUser = New-Object System.Windows.Forms.GroupBox
$grpUser.Text = "User Selection"
$grpUser.Location = New-Object System.Drawing.Point(15, 209)
$grpUser.Size = New-Object System.Drawing.Size(535, 230)
$form.Controls.Add($grpUser)

$lblUpn = New-Object System.Windows.Forms.Label
$lblUpn.Text = "UPN:"
$lblUpn.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$lblUpn.Location = New-Object System.Drawing.Point(12, 24)
$lblUpn.AutoSize = $true
$grpUser.Controls.Add($lblUpn)

$txtUpn = New-Object System.Windows.Forms.TextBox
$txtUpn.Location = New-Object System.Drawing.Point(55, 21)
$txtUpn.Width = 465
$grpUser.Controls.Add($txtUpn)

$lblOrSearch = New-Object System.Windows.Forms.Label
$lblOrSearch.Text = "--- or search Entra ID ---"
$lblOrSearch.ForeColor = [System.Drawing.Color]::Gray
$lblOrSearch.Location = New-Object System.Drawing.Point(180, 52)
$lblOrSearch.AutoSize = $true
$grpUser.Controls.Add($lblOrSearch)

$txtSearch = New-Object System.Windows.Forms.TextBox
$txtSearch.Location = New-Object System.Drawing.Point(12, 74)
$txtSearch.Width = 420
$grpUser.Controls.Add($txtSearch)

$btnSearch = New-Object System.Windows.Forms.Button
$btnSearch.Text = "Search"
$btnSearch.Location = New-Object System.Drawing.Point(440, 72)
$btnSearch.Size = New-Object System.Drawing.Size(80, 26)
$grpUser.Controls.Add($btnSearch)

$lblSearchStatus = New-Object System.Windows.Forms.Label
$lblSearchStatus.Text = ""
$lblSearchStatus.ForeColor = [System.Drawing.Color]::Gray
$lblSearchStatus.Location = New-Object System.Drawing.Point(12, 104)
$lblSearchStatus.AutoSize = $true
$lblSearchStatus.Font = New-Object System.Drawing.Font("Segoe UI", 8)
$grpUser.Controls.Add($lblSearchStatus)

$lvResults = New-Object System.Windows.Forms.ListView
$lvResults.Location = New-Object System.Drawing.Point(12, 122)
$lvResults.Size = New-Object System.Drawing.Size(508, 98)
$lvResults.View = [System.Windows.Forms.View]::Details
$lvResults.FullRowSelect = $true
$lvResults.GridLines = $true
$lvResults.Columns.Add("Name", 190) | Out-Null
$lvResults.Columns.Add("UPN", 305) | Out-Null
$grpUser.Controls.Add($lvResults)

# ============================================================
# GroupBox: PIN & Log Options
# ============================================================

$grpOptions = New-Object System.Windows.Forms.GroupBox
$grpOptions.Text = "PIN && Log Options"
$grpOptions.Location = New-Object System.Drawing.Point(15, 445)
$grpOptions.Size = New-Object System.Drawing.Size(535, 140)
$form.Controls.Add($grpOptions)

# Row 1: Random PIN + Length
$chkRandomPin = New-Object System.Windows.Forms.CheckBox
$chkRandomPin.Text = "Generate random PIN"
$chkRandomPin.Location = New-Object System.Drawing.Point(12, 22)
$chkRandomPin.AutoSize = $true
$grpOptions.Controls.Add($chkRandomPin)

$lblPinLength = New-Object System.Windows.Forms.Label
$lblPinLength.Text = "Length:"
$lblPinLength.Location = New-Object System.Drawing.Point(175, 24)
$lblPinLength.AutoSize = $true
$lblPinLength.ForeColor = [System.Drawing.Color]::FromArgb(85, 85, 85)
$grpOptions.Controls.Add($lblPinLength)

$nudPinLength = New-Object System.Windows.Forms.NumericUpDown
$nudPinLength.Location = New-Object System.Drawing.Point(225, 21)
$nudPinLength.Size = New-Object System.Drawing.Size(50, 23)
$nudPinLength.Minimum = 4
$nudPinLength.Maximum = 12
$nudPinLength.Value = 6
$grpOptions.Controls.Add($nudPinLength)

$lblSamplePin = New-Object System.Windows.Forms.Label
$lblSamplePin.Text = "Default PIN (when random off):"
$lblSamplePin.Location = New-Object System.Drawing.Point(295, 24)
$lblSamplePin.AutoSize = $true
$lblSamplePin.ForeColor = [System.Drawing.Color]::FromArgb(85, 85, 85)
$grpOptions.Controls.Add($lblSamplePin)

$txtSamplePin = New-Object System.Windows.Forms.TextBox
$txtSamplePin.Location = New-Object System.Drawing.Point(462, 21)
$txtSamplePin.Width = 60
$grpOptions.Controls.Add($txtSamplePin)

# Row 2: Copy to clipboard + Force PIN change
$chkCopyClipboard = New-Object System.Windows.Forms.CheckBox
$chkCopyClipboard.Text = "Copy PIN to clipboard"
$chkCopyClipboard.Location = New-Object System.Drawing.Point(12, 50)
$chkCopyClipboard.AutoSize = $true
$grpOptions.Controls.Add($chkCopyClipboard)

$chkForcePinChange = New-Object System.Windows.Forms.CheckBox
$chkForcePinChange.Text = "Force PIN change on first use (FIDO2.1 keys only)"
$chkForcePinChange.Location = New-Object System.Drawing.Point(195, 50)
$chkForcePinChange.AutoSize = $true
$grpOptions.Controls.Add($chkForcePinChange)

# Row 3: Log file
$chkEnableLog = New-Object System.Windows.Forms.CheckBox
$chkEnableLog.Text = "Log File:"
$chkEnableLog.Location = New-Object System.Drawing.Point(12, 80)
$chkEnableLog.AutoSize = $true
$grpOptions.Controls.Add($chkEnableLog)

$txtLogPath = New-Object System.Windows.Forms.TextBox
$txtLogPath.Location = New-Object System.Drawing.Point(100, 79)
$txtLogPath.Width = 345
$txtLogPath.Enabled = $false
$grpOptions.Controls.Add($txtLogPath)

$btnBrowseLog = New-Object System.Windows.Forms.Button
$btnBrowseLog.Text = "Browse..."
$btnBrowseLog.Location = New-Object System.Drawing.Point(453, 77)
$btnBrowseLog.Size = New-Object System.Drawing.Size(70, 26)
$btnBrowseLog.Enabled = $false
$grpOptions.Controls.Add($btnBrowseLog)

$chkEnableLog.Add_CheckedChanged({
    $txtLogPath.Enabled  = $chkEnableLog.Checked
    $btnBrowseLog.Enabled = $chkEnableLog.Checked
})

# ============================================================
# Action Buttons
# ============================================================

$btnEnrollKey = New-Object System.Windows.Forms.Button
$btnEnrollKey.Text = "Enroll Key"
$btnEnrollKey.Font = New-Object System.Drawing.Font("Segoe UI", 13, [System.Drawing.FontStyle]::Bold)
$btnEnrollKey.Location = New-Object System.Drawing.Point(15, 593)
$btnEnrollKey.Size = New-Object System.Drawing.Size(390, 44)
$btnEnrollKey.Enabled = $false
$form.Controls.Add($btnEnrollKey)

$btnWipeKeys = New-Object System.Windows.Forms.Button
$btnWipeKeys.Text = "Wipe Keys"
$btnWipeKeys.Font = New-Object System.Drawing.Font("Segoe UI", 10)
$btnWipeKeys.Location = New-Object System.Drawing.Point(415, 593)
$btnWipeKeys.Size = New-Object System.Drawing.Size(135, 44)
$btnWipeKeys.ForeColor = [System.Drawing.Color]::DarkRed
$btnWipeKeys.Enabled = $false
$form.Controls.Add($btnWipeKeys)

# --- Config path label ---
$lblConfigPath = New-Object System.Windows.Forms.Label
$lblConfigPath.Text = "Config: $($script:ConfigPath)"
$lblConfigPath.Font = New-Object System.Drawing.Font("Segoe UI", 8)
$lblConfigPath.ForeColor = [System.Drawing.Color]::FromArgb(150, 150, 150)
$lblConfigPath.Location = New-Object System.Drawing.Point(15, 645)
$lblConfigPath.AutoSize = $true
$form.Controls.Add($lblConfigPath)

# ============================================================
# Load Config into UI
# ============================================================

$config = Import-AppConfig

$txtTenantId.Text            = $config.TenantId
$txtLogPath.Text             = $config.LogFilePath
$chkRandomPin.Checked        = $config.RandomPin
$nudPinLength.Value          = [Math]::Max(4, [Math]::Min(12, [int]$config.PinLength))
$chkForcePinChange.Checked   = $config.ForcePinChange
$chkCopyClipboard.Checked    = $config.CopyToClipboard
$txtSamplePin.Text           = $config.SamplePin
$chkEnableLog.Checked        = $config.EnableLog
$txtLogPath.Enabled          = $config.EnableLog
$btnBrowseLog.Enabled        = $config.EnableLog

# ============================================================
# Validation & Config Save
# ============================================================

function Update-EnrollButtonState {
    $ready = (
        $script:IsConnected -and
        (-not [string]::IsNullOrWhiteSpace($txtTenantId.Text)) -and
        (-not [string]::IsNullOrWhiteSpace($txtUpn.Text))
    )
    $btnEnrollKey.Enabled = $ready
    $btnWipeKeys.Enabled  = $ready
}

function Save-CurrentConfig {
    $cfg = @{
        TenantId        = $txtTenantId.Text
        LogFilePath     = $txtLogPath.Text
        RandomPin       = $chkRandomPin.Checked
        PinLength       = [int]$nudPinLength.Value
        ForcePinChange  = $chkForcePinChange.Checked
        CopyToClipboard = $chkCopyClipboard.Checked
        SamplePin       = $txtSamplePin.Text
        EnableLog       = $chkEnableLog.Checked
    }
    Export-AppConfig $cfg
}

$txtTenantId.Add_TextChanged({ Update-EnrollButtonState })
$txtUpn.Add_TextChanged({ Update-EnrollButtonState })

# ============================================================
# Event Handlers
# ============================================================

# --- Sign In ---
$btnSignIn.Add_Click({
    $tenantId = $txtTenantId.Text
    if ([string]::IsNullOrWhiteSpace($tenantId)) {
        [System.Windows.Forms.MessageBox]::Show("Please enter a Tenant ID first.", "Missing Tenant ID",
            [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }

    $lblAuthStatus.Text = "Connecting..."
    $lblStatusDot.ForeColor = [System.Drawing.Color]::Orange
    $btnSignIn.Enabled = $false
    Update-UI

    $graphScopes = 'UserAuthenticationMethod.ReadWrite.All','User.Read.All'

    try {
        if ($chkDeviceCode.Checked) {
            # Device code flow: fully GUI-based
            Connect-GraphDeviceCode -TenantId $tenantId -Scopes $graphScopes
        } else {
            # Browser flow: minimize form so the sign-in window is visible
            $form.WindowState = [System.Windows.Forms.FormWindowState]::Minimized
            Update-UI
            Connect-MgGraph -Scopes $graphScopes -TenantId $tenantId -NoWelcome
            $form.WindowState = [System.Windows.Forms.FormWindowState]::Normal
            $form.Activate()
        }

        $context = Get-MgContext
        if ($null -ne $context -and -not [string]::IsNullOrWhiteSpace($context.Account)) {
            $lblAuthStatus.Text = "Connected as $($context.Account)"
        } else {
            $lblAuthStatus.Text = "Connected"
        }
        $script:IsConnected = $true
        $lblStatusDot.ForeColor = [System.Drawing.Color]::ForestGreen
        $btnSignIn.Enabled = $false
        $btnSignOut.Enabled = $true
        Write-Host "Connected to Graph."
    } catch {
        $script:IsConnected = $false
        $lblStatusDot.ForeColor = [System.Drawing.Color]::Red
        $lblAuthStatus.Text = "Connection failed"
        $btnSignIn.Enabled = $true
        $form.WindowState = [System.Windows.Forms.FormWindowState]::Normal
        $form.Activate()

        $errorMsg = $_.Exception.Message
        if ($script:IsElevated -and -not $chkDeviceCode.Checked) {
            $errorMsg += "`n`nYou are running as Administrator. Browser sign-in does not work in elevated sessions.`nPlease check 'Use device code login' and try again."
        }
        [System.Windows.Forms.MessageBox]::Show("Failed to connect: $errorMsg", "Authentication Error",
            [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
    }
    Update-EnrollButtonState
})

# --- Sign Out ---
$btnSignOut.Add_Click({
    try { Disconnect-MgGraph -ErrorAction SilentlyContinue } catch {}
    $script:IsConnected = $false
    $lblStatusDot.ForeColor = [System.Drawing.Color]::Red
    $lblAuthStatus.Text = "Not connected"
    $btnSignIn.Enabled = $true
    $btnSignOut.Enabled = $false
    Write-Host "Disconnected from Graph."
    Update-EnrollButtonState
})

# --- Search Entra ID ---
$btnSearch.Add_Click({
    $searchTerm = $txtSearch.Text
    if ([string]::IsNullOrWhiteSpace($searchTerm)) {
        $lblSearchStatus.Text = "Enter a search term."
        return
    }
    if (-not $script:IsConnected) {
        $lblSearchStatus.Text = "Sign in first to search Entra ID."
        return
    }

    $lblSearchStatus.Text = "Searching..."
    $lblSearchStatus.ForeColor = [System.Drawing.Color]::DarkBlue
    $btnSearch.Enabled = $false
    Update-UI

    try {
        $users = Search-EntraUsers -SearchTerm $searchTerm
        $lvResults.Items.Clear()

        if ($null -eq $users -or $users.Count -eq 0) {
            $lblSearchStatus.Text = "No users found."
            $lblSearchStatus.ForeColor = [System.Drawing.Color]::Gray
        } else {
            foreach ($user in $users) {
                $item = New-Object System.Windows.Forms.ListViewItem($user.displayName)
                $item.SubItems.Add($user.userPrincipalName) | Out-Null
                $lvResults.Items.Add($item) | Out-Null
            }
            $lblSearchStatus.Text = "$($users.Count) user(s) found."
            $lblSearchStatus.ForeColor = [System.Drawing.Color]::DarkGreen
        }
    } catch {
        $lblSearchStatus.Text = "Search failed: $($_.Exception.Message)"
        $lblSearchStatus.ForeColor = [System.Drawing.Color]::Red
        Write-Host "Search error: $($_.Exception.Message)"
    }
    $btnSearch.Enabled = $true
})

# Search on Enter key
$txtSearch.Add_KeyDown({
    if ($_.KeyCode -eq [System.Windows.Forms.Keys]::Enter) {
        $btnSearch.PerformClick()
        $_.SuppressKeyPress = $true
    }
})

# Select user from results
$lvResults.Add_SelectedIndexChanged({
    if ($lvResults.SelectedItems.Count -gt 0) {
        $txtUpn.Text = $lvResults.SelectedItems[0].SubItems[1].Text
    }
})

# Double-click to select and focus UPN
$lvResults.Add_DoubleClick({
    if ($lvResults.SelectedItems.Count -gt 0) {
        $txtUpn.Text = $lvResults.SelectedItems[0].SubItems[1].Text
        $txtUpn.Focus()
    }
})

# --- Browse Log ---
$btnBrowseLog.Add_Click({
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Filter = "Log files (*.log)|*.log|CSV files (*.csv)|*.csv|All files (*.*)|*.*"
    $dlg.DefaultExt = "log"
    if ($dlg.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $txtLogPath.Text = $dlg.FileName
    }
})

# --- Wipe Keys ---
$btnWipeKeys.Add_Click({
    $upn = $txtUpn.Text.Trim()

    $wipeDlg = New-Object System.Windows.Forms.Form
    $wipeDlg.Text = "Wipe / Reset FIDO2 Keys"
    $wipeDlg.Size = New-Object System.Drawing.Size(520, 395)
    $wipeDlg.StartPosition = "CenterScreen"
    $wipeDlg.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $wipeDlg.MaximizeBox = $false
    $wipeDlg.MinimizeBox = $false
    $wipeDlg.Font = New-Object System.Drawing.Font("Segoe UI", 9)

    # ---- Section 1: Entra ID ----
    $grpEntra = New-Object System.Windows.Forms.GroupBox
    $grpEntra.Text = "Remove Keys from Entra ID"
    $grpEntra.Location = New-Object System.Drawing.Point(12, 10)
    $grpEntra.Size = New-Object System.Drawing.Size(480, 220)
    $wipeDlg.Controls.Add($grpEntra)

    $lblEntraUser = New-Object System.Windows.Forms.Label
    $lblEntraUser.Text = if ([string]::IsNullOrWhiteSpace($upn)) { "No user selected." } else { "User: $upn" }
    $lblEntraUser.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
    $lblEntraUser.Location = New-Object System.Drawing.Point(10, 22)
    $lblEntraUser.AutoSize = $true
    $grpEntra.Controls.Add($lblEntraUser)

    $lvEntraKeys = New-Object System.Windows.Forms.ListView
    $lvEntraKeys.Location = New-Object System.Drawing.Point(10, 44)
    $lvEntraKeys.Size = New-Object System.Drawing.Size(458, 100)
    $lvEntraKeys.View = [System.Windows.Forms.View]::Details
    $lvEntraKeys.FullRowSelect = $true
    $lvEntraKeys.GridLines = $true
    $lvEntraKeys.CheckBoxes = $true
    $lvEntraKeys.Columns.Add("Name", 160) | Out-Null
    $lvEntraKeys.Columns.Add("Created", 140) | Out-Null
    $lvEntraKeys.Columns.Add("ID", 145) | Out-Null
    $grpEntra.Controls.Add($lvEntraKeys)

    $lblEntraStatus = New-Object System.Windows.Forms.Label
    $lblEntraStatus.Text = ""
    $lblEntraStatus.Location = New-Object System.Drawing.Point(10, 150)
    $lblEntraStatus.Size = New-Object System.Drawing.Size(350, 20)
    $lblEntraStatus.ForeColor = [System.Drawing.Color]::Gray
    $grpEntra.Controls.Add($lblEntraStatus)

    $btnSelectAll = New-Object System.Windows.Forms.Button
    $btnSelectAll.Text = "Select All"
    $btnSelectAll.Location = New-Object System.Drawing.Point(10, 175)
    $btnSelectAll.Size = New-Object System.Drawing.Size(80, 28)
    $btnSelectAll.Add_Click({
        foreach ($item in $lvEntraKeys.Items) { $item.Checked = $true }
    })
    $grpEntra.Controls.Add($btnSelectAll)

    $btnRemoveSelected = New-Object System.Windows.Forms.Button
    $btnRemoveSelected.Text = "Remove Selected from Entra ID"
    $btnRemoveSelected.Location = New-Object System.Drawing.Point(100, 175)
    $btnRemoveSelected.Size = New-Object System.Drawing.Size(220, 28)
    $btnRemoveSelected.ForeColor = [System.Drawing.Color]::DarkRed
    $btnRemoveSelected.Enabled = $false
    $grpEntra.Controls.Add($btnRemoveSelected)

    # Load keys if user is selected
    $script:entraKeysLoaded = @()
    if (-not [string]::IsNullOrWhiteSpace($upn) -and $script:IsConnected) {
        try {
            $lblEntraStatus.Text = "Loading keys..."
            $endpoint = Get-MgGraphEndpoint
            $fido2Url = "$endpoint/beta/users/$([uri]::EscapeDataString($upn))/authentication/fido2Methods"
            $existing = Invoke-MgGraphRequest -Method GET -Uri $fido2Url -OutputType PSObject
            $script:entraKeysLoaded = $existing.value

            if ($null -ne $script:entraKeysLoaded -and $script:entraKeysLoaded.Count -gt 0) {
                foreach ($key in $script:entraKeysLoaded) {
                    $displayName = if ($key.displayName) { [string]$key.displayName } else { "(unnamed)" }
                    $created     = if ($key.createdDateTime) { [string]$key.createdDateTime } else { "" }
                    $keyId       = if ($key.id) { [string]$key.id } else { "" }
                    $item = New-Object System.Windows.Forms.ListViewItem($displayName)
                    $item.SubItems.Add($created) | Out-Null
                    $item.SubItems.Add($keyId) | Out-Null
                    $lvEntraKeys.Items.Add($item) | Out-Null
                }
                $lblEntraStatus.Text = "$($script:entraKeysLoaded.Count) key(s) found."
                $lblEntraStatus.ForeColor = [System.Drawing.Color]::DarkBlue
                $btnRemoveSelected.Enabled = $true
            } else {
                $lblEntraStatus.Text = "No FIDO2 keys registered for this user."
                $lblEntraStatus.ForeColor = [System.Drawing.Color]::Gray
            }
        } catch {
            $lblEntraStatus.Text = "Error loading keys: $($_.Exception.Message)"
            $lblEntraStatus.ForeColor = [System.Drawing.Color]::Red
        }
    } elseif ([string]::IsNullOrWhiteSpace($upn)) {
        $lblEntraStatus.Text = "Enter a UPN in the main window first."
    } else {
        $lblEntraStatus.Text = "Not connected to Graph."
    }

    # Remove selected handler
    $btnRemoveSelected.Add_Click({
        $checkedItems = @($lvEntraKeys.CheckedItems)
        if ($checkedItems.Count -eq 0) {
            [System.Windows.Forms.MessageBox]::Show("No keys selected. Check the keys you want to remove.", "Nothing Selected",
                [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
            return
        }

        $confirm = [System.Windows.Forms.MessageBox]::Show(
            "Remove $($checkedItems.Count) selected key(s) from Entra ID for $upn?`n`nThis cannot be undone.",
            "Confirm Remove",
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Warning)
        if ($confirm -ne [System.Windows.Forms.DialogResult]::Yes) { return }

        $btnRemoveSelected.Enabled = $false
        $deleted = 0
        $failed  = 0
        foreach ($item in $checkedItems) {
            $keyId = $item.SubItems[2].Text
            try {
                $deleteUrl = "$fido2Url/$keyId"
                Write-Host "[Wipe] Deleting key: $($item.Text) (ID: $keyId)"
                Invoke-MgGraphRequest -Method DELETE -Uri $deleteUrl
                $deleted++
                $lvEntraKeys.Items.Remove($item)
            } catch {
                Write-Host "[Wipe] Failed to delete $keyId : $($_.Exception.Message)" -ForegroundColor Red
                $failed++
            }
        }

        $summary = "Removed $deleted key(s)."
        if ($failed -gt 0) { $summary += " $failed failed." }
        $lblEntraStatus.Text = $summary
        $lblEntraStatus.ForeColor = if ($failed -gt 0) { [System.Drawing.Color]::Red } else { [System.Drawing.Color]::DarkGreen }
        Write-Host "[Wipe] $summary"
        if ($lvEntraKeys.Items.Count -gt 0) { $btnRemoveSelected.Enabled = $true }
    })

    # ---- Section 2: Physical Key Reset (via Windows Settings) ----
    $grpPhysical = New-Object System.Windows.Forms.GroupBox
    $grpPhysical.Text = "Reset Physical FIDO2 Key"
    $grpPhysical.Location = New-Object System.Drawing.Point(12, 238)
    $grpPhysical.Size = New-Object System.Drawing.Size(480, 60)
    $wipeDlg.Controls.Add($grpPhysical)

    $btnOpenSettings = New-Object System.Windows.Forms.Button
    $btnOpenSettings.Text = "Open Windows Security Key Settings"
    $btnOpenSettings.Location = New-Object System.Drawing.Point(10, 22)
    $btnOpenSettings.Size = New-Object System.Drawing.Size(250, 28)
    $btnOpenSettings.Add_Click({ Start-Process "ms-settings:signinoptions" })
    $grpPhysical.Controls.Add($btnOpenSettings)

    $lblSettingsHint = New-Object System.Windows.Forms.Label
    $lblSettingsHint.Text = "Go to Accounts > Sign-in options > Security key."
    $lblSettingsHint.Location = New-Object System.Drawing.Point(268, 28)
    $lblSettingsHint.AutoSize = $true
    $lblSettingsHint.ForeColor = [System.Drawing.Color]::FromArgb(100, 100, 100)
    $lblSettingsHint.Font = New-Object System.Drawing.Font("Segoe UI", 8)
    $grpPhysical.Controls.Add($lblSettingsHint)

    # ---- Close button ----
    $btnWipeClose = New-Object System.Windows.Forms.Button
    $btnWipeClose.Text = "Close"
    $btnWipeClose.Location = New-Object System.Drawing.Point(12, 310)
    $btnWipeClose.Size = New-Object System.Drawing.Size(80, 30)
    $btnWipeClose.Add_Click({ $wipeDlg.Close() })
    $wipeDlg.Controls.Add($btnWipeClose)

    $wipeDlg.ShowDialog() | Out-Null
    $wipeDlg.Dispose()
})

# --- Enroll Key ---
$btnEnrollKey.Add_Click({
    Save-CurrentConfig

    $upn             = $txtUpn.Text.Trim()
    $logPath         = if ($chkEnableLog.Checked) { $txtLogPath.Text } else { "" }
    $useRandomPin    = $chkRandomPin.Checked
    $forcePinChange  = $chkForcePinChange.Checked
    $copyToClipboard = $chkCopyClipboard.Checked
    $samplePin       = $txtSamplePin.Text

    if ([string]::IsNullOrWhiteSpace($upn)) {
        [System.Windows.Forms.MessageBox]::Show("Please enter or select a user UPN.", "No User",
            [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
        return
    }
    if ([string]::IsNullOrWhiteSpace($logPath)) {
        $logPath = Join-Path $PSScriptRoot "provisioning.log"
    }

    # Check if user already has FIDO2 keys registered
    try {
        $endpoint = Get-MgGraphEndpoint
        $fido2Url = "$endpoint/beta/users/$([uri]::EscapeDataString($upn))/authentication/fido2Methods"
        $existing = Invoke-MgGraphRequest -Method GET -Uri $fido2Url -OutputType PSObject
        $existingKeys = $existing.value
        if ($null -ne $existingKeys -and $existingKeys.Count -gt 0) {
            $keyList = ($existingKeys | ForEach-Object {
                "  - $($_.displayName)  (created $($_.createdDateTime))"
            }) -join "`n"
            $confirmResult = [System.Windows.Forms.MessageBox]::Show(
                "$upn already has $($existingKeys.Count) FIDO2 key(s) registered:`n`n$keyList`n`nDo you want to enroll an additional key?",
                "Existing Keys Found",
                [System.Windows.Forms.MessageBoxButtons]::YesNo,
                [System.Windows.Forms.MessageBoxIcon]::Warning)
            if ($confirmResult -ne [System.Windows.Forms.DialogResult]::Yes) {
                return
            }
        }
    } catch {
        Write-Host "Warning: Could not check existing FIDO2 keys: $($_.Exception.Message)"
    }

    $pinLength = [int]$nudPinLength.Value

    $dialogResult = Show-EnrollmentDialog `
        -Upn $upn `
        -UseRandomPin $useRandomPin `
        -PinLength $pinLength `
        -ForcePinChange $forcePinChange `
        -CopyToClipboard $copyToClipboard `
        -SamplePin $samplePin `
        -LogPath $logPath

    if ($dialogResult -eq "enrolled") {
        $txtUpn.Text = ""
        $lvResults.SelectedItems | ForEach-Object { $_.Selected = $false }
    }
})

# --- Window Closing ---
$form.Add_FormClosing({ Save-CurrentConfig })

# ============================================================
# Show Main Window
# ============================================================

$form.ShowDialog() | Out-Null
