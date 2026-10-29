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
- An encrypted App Store `.ipa` for that app, e.g. from [`ipatool`](https://github.com/majd/ipatool)

## Setup

1. Open `FairPlayed/FairPlayed.xcodeproj` and set your own **Team** under *Signing & Capabilities*.
2. Choose a unique bundle identifier and pass it as `BUNDLE_ID` when running the script.
3. Find your device UDID:
   ```bash
   xcrun devicectl list devices
   ```

## Usage

The complete sequence, from authenticating with `ipatool` to retrieving the decrypted IPA, is:

```bash
export APPLE_ID_EMAIL="your-email@example.com"
export APP_BUNDLE_ID="com.example.target"
export DEVICE_UDID="your-device-udid"
export FAIRPLAYED_BUNDLE_ID="com.example.fairplayed"

ipatool auth login --email "$APPLE_ID_EMAIL"
ipatool search "your search term"

mkdir -p FairPlayed/out
ipatool download \
  --bundle-identifier "$APP_BUNDLE_ID" \
  --purchase \
  --output FairPlayed/out/encrypted.ipa

DEVICE="$DEVICE_UDID" \
BUNDLE_ID="$FAIRPLAYED_BUNDLE_ID" \
./fpdecrypt.sh FairPlayed/out/encrypted.ipa
```

All values above are placeholders. Use the Apple ID that owns the app license, the target app's bundle identifier, your device UDID, and a unique bundle identifier for FairPlayed.

`fpdecrypt.sh` runs the whole pipeline:

1. **`embed_ipa.sh`** unpacks the IPA into `FairPlayed/payload/<App>/`.
   - The `.app` suffix is dropped, so `codesign` treats the payload as resources and leaves the binaries alone.
   - `Watch/` is removed.
   - The main `.sinf` is copied to every `SinfReplicationPaths` location, which is what `installd` would normally do for extensions and frameworks.
2. **`xcodebuild`** builds and signs FairPlayed with the payload embedded, and installs it on the device.
3. **FairPlayed** is launched with `FPD_AUTORUN=export`. It decrypts every encrypted Mach-O (main executable, frameworks, `.appex`) and packs `Documents/Decrypted/<App>-decrypted.ipa`.
4. The script pulls the IPA into `FairPlayed/out/` and runs **`verify_ipa.sh`**.

If some binaries fail to decrypt, the output is named `<App>-PARTIAL.ipa` and those binaries keep their original encrypted contents. The full device log is saved to `FairPlayed/out/export-<App>.txt`.

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
