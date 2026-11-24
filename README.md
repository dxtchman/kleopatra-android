# Kleo: a Kleopatra-style OpenPGP manager for Android

An OpenPGP certificate manager and crypto tool for Android, modelled on KDE's
[Kleopatra](https://apps.kde.org/kleopatra/). It's a native app: Kotlin and Jetpack Compose,
with the crypto done by [PGPainless](https://pgpainless.org) on top of Bouncy Castle. It doesn't
need GnuPG or Termux, and nothing runs in the background.

> Unofficial. Not affiliated with KDE or the GnuPG project.

## Features

| Kleopatra | Kleo |
|---|---|
| Certificate list with search and filters | ✅ All / My certificates / Others, search by name, e-mail or fingerprint |
| Certificate details | ✅ User IDs, fingerprint, validity, algorithm, usage, subkeys |
| New Key Pair | ✅ Curve25519 (default), RSA 3072/4096, expiry, passphrase |
| Import (file, clipboard) | ✅ Multiple files, pasted armour, **"Open with" and Share-to-app** |
| Export / back up secret key | ✅ Share, copy, save `.asc`, secret key backup |
| Lookup on Server | ✅ WKD, keys.openpgp.org, keyserver.ubuntu.com |
| Publish on Server | ✅ keys.openpgp.org upload and e-mail verification |
| Update certificate | ✅ Refresh from the keyserver |
| Change passphrase / expiry | ✅ |
| Notepad: Sign/Encrypt, Decrypt/Verify | ✅ Including cleartext signatures and password encryption |
| Sign/Encrypt files | ✅ Binary `.gpg` or armoured `.asc`, encrypt to self, password |
| Decrypt/Verify files | ✅ Encrypted and signed files, plus **detached `.sig` verification** |
| Coloured result banners | ✅ Green/yellow/red, Kleopatra style |
| Smartcards, certification (signing others' keys), trust levels, S/MIME | ❌ Not yet |

### Android-specific behaviour
- **Share to Kleo** from any app: shared text goes to the Notepad (and is decrypted automatically
  if it's a PGP message), and shared files go to Files.
- **Open with Kleo** for `.asc`, `.gpg`, `.pgp`, `.sig` and key files.
- Passphrases are cached only in memory, only if you tick "Remember", and are forgotten when the
  app process dies. You can also clear them from the overflow menu.
- The keyring lives in app-private storage and is **excluded from cloud backup and device
  transfer**. Secret keys stay encrypted with their OpenPGP passphrase. Use *Back up secret key*
  to keep your own copy.
- `FLAG_SECURE` keeps decrypted text out of screenshots and the recents screen.

## Building

Every push builds a debug APK in **GitHub Actions** (`.github/workflows/build.yml`).
Open the run under *Actions* and download the `kleo-debug-apk` artifact.

Building locally needs JDK 17 and the Android SDK (compileSdk 35):

```bash
./gradlew assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

`app/debug.keystore` is committed on purpose. Every build is signed with the same debug key,
so a new APK installs over the old one. If the key changed, Android would make you uninstall
first, and uninstalling **deletes your keyring**. It's a debug key, not a secret. Create a real
release key before publishing anywhere.

## Project layout

```
app/src/main/java/io/github/dxtchman/kleo/
├── crypto/
│   ├── PgpUtil.kt       parsing, sniffing, key inspection (Bouncy Castle)
│   ├── PgpOps.kt        generate / encrypt / sign / decrypt / verify (PGPainless)
│   ├── KeyRepository.kt the local keyring (one file per certificate)
│   └── KeyServer.kt     WKD, VKS (keys.openpgp.org) and HKP lookups, publishing
└── ui/
    ├── AppViewModel.kt  operations, passphrase prompts, share/open intents
    ├── KleoRoot.kt      navigation: Certificates · Notepad · Files
    ├── certs/           list, details, new key pair, lookup
    ├── notepad/         Notepad
    ├── files/           file operations
    └── common/          passphrase dialog, Sign/Encrypt sheet, result banners
```

## Roadmap ideas
- Certify (sign) other people's certificates, plus owner trust and validity
- Add or revoke user IDs, generate revocation certificates
- Hardware tokens (YubiKey/OpenPGP card over NFC/USB)
- Optional Android Keystore wrapping of the keyring
- Android Autofill / Quick Settings tile for decrypting the clipboard
