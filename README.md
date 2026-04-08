# FIDO2 Bulk Enrollment Tool for Microsoft Entra ID

A GUI tool for bulk enrolling FIDO2 security keys on behalf of users in **Microsoft Entra ID**. Uses direct credential creation via `fido2-cred2.exe` for fast enrollment, bypassing the Windows Hello interface entirely. Supports both USB and NFC keys.

## Features

- **Interactive GUI** with user search, Entra ID integration, and real-time enrollment status
- **Entra ID user search** - search users by name or UPN directly from the tool instead of CSV files
- **USB and NFC support** - automatic device detection with NFC-specific guidance
- **Device code authentication** - reliable sign-in flow for admin accounts, auto-detected when running elevated
- **Random PIN generation** - configurable length (4-12 digits) with complexity checks (no sequential, repeated, or palindromic PINs)
- **Force PIN change** - option to require PIN change on first use (FIDO2.1 Final keys only)
- **Existing key detection** - warns before enrolling if the user already has FIDO2 keys registered
- **PIN confirmation** - after enrollment, displays the PIN prominently and requires admin acknowledgement before continuing
- **Key management** - wipe FIDO2 keys from Entra ID (select individual keys or all), with link to Windows Settings for physical key reset
- **JSON configuration** - settings saved to `%APPDATA%\FIDO2BulkEnroll\config.json` (tenant, PIN options, log preferences)
- **Optional CSV logging** - log enrollments to file (can be disabled)

## Prerequisites

### Hardware
- Compatible **FIDO2 key** (FIDO2.0 or later)
  - FIDO2.1 Final firmware required for force PIN change feature
  - Serial number auto-read supported with **PIN+ series** keys via USB only
- For NFC enrollment: a PC/SC-compatible NFC reader (e.g. HID OMNIKEY 5022 CL)

### Software
- **PowerShell** 5.1 or later (PowerShell 7 recommended)
- **Modules** (installed automatically if missing):
  - `Microsoft.Graph`
  - `DSInternals.PassKeys`

### Required Files
These must be in the same directory as the script:
- `fido2-cred2.exe` - creates credentials directly on FIDO keys (compiled with NFC support)
- `fido2-manage.exe` - sets PIN and forces PIN change on FIDO2 keys
- `libfido2-ui.exe` - dependency for device enumeration
- `read_serial_t2.exe` - reads serial numbers from PIN+ series keys (USB only)

### Permissions
The Entra ID account used must have:
- `UserAuthenticationMethod.ReadWrite.All` - for enrolling and managing FIDO2 keys
- `User.Read.All` - for searching users in Entra ID

## Usage

### 1. Launch the Tool
```powershell
.\EnrollFIDO2_GUI.ps1
```
If the execution policy blocks the script:
```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy Bypass
```

### 2. Configure and Sign In
- Enter your **Tenant ID** (e.g. `contoso.onmicrosoft.com` or tenant GUID)
- Click **Sign In** - uses device code authentication when running as Administrator (browser auth when not elevated)
- The device code flow shows a dialog with the code and URL; sign in with your admin account in any browser

### 3. Select a User
Either:
- **Type the UPN** directly in the UPN field, or
- **Search Entra ID** by name or email, then click a result to populate the UPN

### 4. Enroll a Key
- Click **Enroll Key**
- If the user already has FIDO2 keys, you'll be warned and asked to confirm
- The enrollment dialog opens:
  - **Device detection** shows whether USB or NFC is detected
  - **Serial number** can be auto-read (USB) or typed manually (NFC / from key label)
  - **PIN** is generated immediately and shown
  - Click **Enroll** to:
    1. Set PIN on the key
    2. Create the FIDO2 credential on the key (touch USB key or hold NFC key on reader)
    3. Register the credential with Entra ID
    4. Optionally force PIN change
  - A **PIN confirmation dialog** shows the PIN prominently - you must acknowledge before continuing
- After enrollment the UPN field clears, ready for the next user

### 5. Wipe Keys (Optional)
Click **Wipe Keys** to open the key management dialog:
- **Remove from Entra ID** - lists all registered FIDO2 keys for the user with checkboxes; select and remove individual keys or all
- **Reset physical key** - opens Windows Settings (Accounts > Sign-in options > Security key) for factory reset

## NFC Enrollment Notes

- `read_serial_t2.exe` (serial auto-read) only works over USB. For NFC keys, type the serial from the key's label or leave blank
- `fido2-manage.exe` (PIN set/change) uses USB device numbering. If it fails over NFC, the PIN is passed directly to `fido2-cred2.exe` during credential creation
- If the NFC key already has a PIN from a previous setup, you'll be prompted to enter the existing PIN
- For brand new keys that need a PIN set: connect via USB first to set the PIN, then use NFC for enrollment. Or set the PIN as part of the NFC enrollment (the tool will attempt this automatically)

## Configuration

Settings are saved to `%APPDATA%\FIDO2BulkEnroll\config.json`:
- Tenant ID
- PIN options (random, length, force change, clipboard, default PIN)
- Log file path and enabled state

Settings persist between sessions and are saved automatically when closing the tool.

## Log File Format

When logging is enabled, enrollments are saved as CSV:
```
UPN,Serial Number,PIN,ForcePINChange
john.doe@domain.com,T2-123456,789012,True
jane.smith@domain.com,FIDO2Key,456789,False
```

Handle this file carefully as it contains PINs.

## Troubleshooting

- **Authentication fails (elevated PowerShell)**: The "Use device code login" checkbox should be auto-checked. Device code flow bypasses WAM which is broken in elevated sessions
- **"Unable to find type" errors**: Ensure `DSInternals.PassKeys` module is installed. The tool imports it automatically but a restart may help after first install
- **NFC key not detected**: Ensure the key is on the reader when clicking Enroll. The device detection runs on dialog open; if you place the key after, enrollment still works as `fido2-cred2.exe` detects devices at enrollment time
- **FIDO_ERR_PIN_INVALID**: The key already has a PIN that doesn't match. Enter the existing PIN when prompted, or factory reset the key via Windows Settings
- **Force PIN change fails**: The key doesn't support FIDO2.1 `forcePINChange` command. The enrollment still succeeds; the user keeps the assigned PIN

## Credits

- CBOR encoding and CTAP credential creation based on [Token2 FIDO2 bulk enrollment scripts](https://github.com/niclas-eob/fido2_bulkenroll_entraid)
- Base64URL encoding from [Posh-ACME](https://github.com/rmbolger/Posh-ACME) (MIT)
- Graph API interaction adapted from [DSInternals.PassKeys](https://github.com/MichaelGrafnetter/webauthn-interop) (MIT)

## License

This project is partially licensed under the [MIT License](LICENSE), except the `read_serial_t2.exe` utility.
