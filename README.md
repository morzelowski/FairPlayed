# FairPlayed

> **Disclosure status:** This research was reported to Apple before publication. Apple reviewed the report and responded that **“this is not a security issue.”**

**FairPlay decryption for iOS App Store apps — no jailbreak, no TrollStore.**

Decrypt FairPlay-encrypted IPAs (main executable, frameworks and app extensions) on a stock iPhone, using only a development-signed helper app (FairPlayed) and Developer Mode.

Tested on a stock iPhone running **iOS 27.0.1**.

```
IPA (encrypted)  ──embed──▶  FairPlayed.app/EmbeddedPayload/<App>/  ──install──▶  iPhone
                                                                                 │
   <App>-decrypted.ipa  ◀──pull + verify──  Documents/Decrypted/  ◀──mremap_encrypted(cryptid=2)
```

> **Research tool.** Use it only on apps you own a license for, for security research or interoperability. The device must be signed in to the Apple ID that purchased the app.

## How it works

1. **`mremap_encrypted` has no privilege check.** Any process can ask the kernel to run a mapped range through FairPlay (`text_crypter_create` → `FairPlayIOKit` → `fairplayd`).
2. **`cryptid=2` avoids `PROT_EXEC`.** `cryptid` is not passed to FairPlay. In `vm_map_apple_protected` it only selects a code path, and `CRYPTID_MODEL_ENCRYPTION` (2, used for Core ML models) skips the requirement that the mapping be executable. A plain `mmap(PROT_READ)` is enough, so AMFI library validation never gets involved.
3. **FairPlay finds the license by path.** `fairplayd` opens `<dir>/SC_Info/<name>.sinf` next to the binary. The license is not tied to the calling process or to the bundle the file lives in.
4. **`fairplayd` can read installed bundles but not data containers.** `System Policy` blocks it from reading app data containers, and symlinks do not help. The target app therefore has to be **embedded in FairPlayed's own bundle** at build time.

Each slice is accepted as decrypted only when all of these hold:
- `mremap_encrypted` returns 0;
- every page reads back without a fault;
- the bytes changed;
- entropy fell from about 8.0 to below 7.5 bits per byte;
- new `ret`/`retab`/`pacibsp` instructions appeared.

The decrypted slice is written back with `cryptid = 0`.

## Requirements

- macOS with Xcode and command-line tools (`xcodebuild`, `xcrun devicectl`, `otool`)
- An Apple Developer account (a free one works) to sign FairPlayed
- iPhone with **Developer Mode** enabled: *Settings → Privacy & Security → Developer Mode*
- The iPhone signed in to the Apple ID that owns the app. A quick check is that the app runs normally when installed from the App Store.
- An encrypted App Store `.ipa` for that app, or [`ipatool`](https://github.com/majd/ipatool) installed with `brew install ipatool`

## Setup

1. Add your Apple Developer account in **Xcode → Settings → Apple Accounts**.
2. Before the first run, open `FairPlayed/FairPlayed.xcodeproj`, select the **FairPlayed** target, open **Signing & Capabilities**, enable **Automatically manage signing**, and choose your Team. Save the project and close Xcode.
3. Run `fpdecrypt.sh`. It reads the `DEVELOPMENT_TEAM` value written by Xcode, saves it in the local Git-ignored `.fairplayed.env`, and immediately removes it from `project.pbxproj` so the private Team ID cannot be committed. Later runs reuse the local value. Do not rely on `security find-identity`: Keychain may contain valid certificates for old teams.
4. Connect and unlock the iPhone, trust the Mac, and enable **Developer Mode**.
5. The script automatically detects the physical iPhone when exactly one is connected. To list devices manually, run:
   ```bash
   xcrun devicectl list devices
   ```
6. If you want the script to download the encrypted IPA, authenticate `ipatool` once:
   ```bash
   ipatool auth login --email "your-email@example.com"
   ```

## Usage

### Fastest path: download and decrypt automatically

> **First run only:** Open `FairPlayed/FairPlayed.xcodeproj` in Xcode. Select the **FairPlayed** target, open **Signing & Capabilities**, enable **Automatically manage signing**, and choose your Team. Save the project and close Xcode before running the script. `fpdecrypt.sh` will import the selected Team into the private `.fairplayed.env` file and remove it from the tracked Xcode project automatically.

Find the target app and copy its bundle identifier:

```bash
ipatool search "your search term"
```

Then run the entire download → build → install → decrypt → pull → verify pipeline:

```bash
export TARGET_APP_BUNDLE_ID="the.bundle.identifier.from.ipatool"
./fpdecrypt.sh --download "$TARGET_APP_BUNDLE_ID"
```

`--download` runs `ipatool download --purchase` and saves the input as `FairPlayed/out/encrypted.ipa`. The Apple ID must own a license for the target app.

### Use an IPA you already have

```bash
./fpdecrypt.sh path/to/encrypted.ipa
```

By default the helper app uses `com.m0u.fairplayed`. This is **not** the target app's bundle identifier. The two identifiers serve different purposes:

| Identifier | Purpose | Example in the command |
|---|---|---|
| Target app bundle ID | Tells `ipatool` which licensed app to download | `--download "$TARGET_APP_BUNDLE_ID"` |
| FairPlayed bundle ID | Signs, installs, launches, and accesses the FairPlayed helper | Default: `com.m0u.fairplayed` |

Never use the target app's bundle identifier as the FairPlayed bundle identifier: it belongs to another development team and Xcode cannot register it for you.

### Overrides and troubleshooting

Normally no options are required after the one-time Xcode signing setup. If device detection finds zero or multiple choices, specify the device explicitly. `--team-id` remains available mainly for CI:

```bash
./fpdecrypt.sh path/to/encrypted.ipa \
  --device "your-physical-iphone-udid" \
  --team-id "your-10-character-team-id" \
  --fairplayed-bundle-id "com.m0u.fairplayed"
```

Run `./fpdecrypt.sh --help` for all options. The equivalent environment variables are `DEVICE`, `TEAM_ID`, `FAIRPLAYED_BUNDLE_ID`, and `PLATFORM`.

After installing FairPlayed, the script pauses and asks you to verify the developer certificate on the iPhone under **Settings → General → VPN & Device Management → Developer App**. Press Enter only after the certificate is trusted. On later runs, this pause can be skipped with `--skip-trust-prompt` or `SKIP_TRUST_PROMPT=1`.

`fpdecrypt.sh` automates the whole pipeline:

1. Optionally downloads the licensed IPA with **`ipatool`**.
2. Imports the Team selected in Xcode into a private local config, sanitizes the Xcode project, and detects the connected physical iPhone.
3. **`embed_ipa.sh`** unpacks the IPA into `FairPlayed/payload/<App>/`.
   - The `.app` suffix is dropped, so `codesign` treats the payload as resources and leaves the binaries alone.
   - `Watch/` is removed.
   - The main `.sinf` is copied to every `SinfReplicationPaths` location, which is what `installd` would normally do for extensions and frameworks.
4. **`xcodebuild`** builds and signs FairPlayed with the payload embedded.
5. Installs FairPlayed and waits for the user to verify the developer certificate on the iPhone.
6. Launches FairPlayed with `FPD_AUTORUN=export`. It decrypts every encrypted Mach-O (main executable, frameworks, `.appex`) and packs `Documents/Decrypted/<App>-decrypted.ipa`.
7. Pulls the IPA into `FairPlayed/out/` and runs **`verify_ipa.sh`**.

If some binaries fail to decrypt, the output is named `<App>-PARTIAL.ipa` and those binaries keep their original encrypted contents. The full device log is saved to `FairPlayed/out/export-<App>.txt`, and the complete Xcode log is saved to `FairPlayed/out/build.log`.

One FairPlayed build handles one target app. Run the script again for the next IPA.

### Verifying an IPA

```bash
./verify_ipa.sh FairPlayed/out/<name>-decrypted.ipa
```

It prints the `cryptid` of every Mach-O and exits with 1 if any arm64 slice is still encrypted.

Example output:

```
cryptid=0  <name>.app/<binary>
cryptid=0  <name>.app/Frameworks/<framework>.framework/<binary>
...
summary: 45 with cryptid 0, 0 still encrypted, 0 without LC_ENCRYPTION_INFO_64
```

## Environment variables (FairPlayed)

| Variable | Meaning |
|---|---|
| `FPD_AUTORUN` | `export`: decrypt the embedded payload and build an IPA. `embedded`, `installed`, `all`: run the experiments from the research log. |
| `FPD_EXIT` | Exit when the autorun finishes. |
| `FPD_VARIANTS` | Also run the path variants (binary without `SC_Info`, copy in `tmp/`, …). |
| `FPD_SCLINK` | Variant F: path of an installed app's `SC_Info` to symlink to. |
| `FPD_FILTER`, `FPD_EXPORT` | `installed` mode: filter installed apps by name and try to export them. |
| `FPD_TARGETS`, `FPD_PATHS` | Comma-separated bundle IDs or file paths to probe. |

## Repository layout

```
fpdecrypt.sh          end-to-end pipeline
embed_ipa.sh          stage an IPA into FairPlayed/payload/
verify_ipa.sh         report cryptid of every Mach-O in an IPA
FairPlayed/
  FairPlayed/fpcore.c Mach-O parsing (thin + FAT), mremap_encrypted attempts, page reads, cryptid patching
  FairPlayed/zipio.c  IPA unzip and zip (deflate, ZIP64, path-traversal checks)
  FairPlayed/main.m   UI and autorun driver
  payload/            (generated) embedded target app
  build/              (generated) Xcode DerivedData, safe to delete
  out/                (generated) pulled IPAs and logs
```

## Limitations

- **One target per build.** The target must sit in FairPlayed's installed bundle. An IPA copied to the device after installation cannot be decrypted.
- **arm64 slices only.** watchOS content is skipped.
- **Licensed Apple ID required.** Without a matching account FairPlay returns `EPERM`, `-42004` or `-42110`.
- **Confirmed only on iOS 27.0.1.** The `cryptid=2` exception was read from macOS XNU source and confirmed by behavior on this device. Other versions are untested.

## Contributing

Pull requests are welcome. Bug fixes, compatibility improvements, documentation updates, and additional testing on other iOS versions are especially appreciated.
