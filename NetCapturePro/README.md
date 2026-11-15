# NetCapture Pro

NetCapture Pro is an Android 12+ offline PCAP inspection app written in Kotlin and Jetpack Compose. It gives a clear five-tab view of a classic packet-capture file: **HTTPS, TCP, PACKET, UDP, and KEY**.

> **Important scope note:** this repository does not start a live VPN capture. It imports and parses a PCAP file selected by the user. The installed-app selector is a workspace list only; this build does not claim that packets in an imported PCAP can be attributed to a specific Android package. A true per-app live capture feature needs a complete VPN forwarding engine and a separate implementation phase.

## Features in this build

- Dark Jetpack Compose interface.
- Installed-app list with search and multi-select.
- Import a classic `.pcap` file using Android's document picker.
- Five analysis tabs: HTTPS, TCP, PACKET, UDP, KEY.
- IPv4 and IPv6 header inspection.
- Ethernet II, raw-IP, and Linux cooked v1 (SLL) link types.
- TCP ports and flags; UDP ports and lengths.
- Basic DNS question-name parsing.
- Best-effort TLS ClientHello / ServerHello metadata parsing when the handshake record is contained in one TCP packet: SNI, advertised/selected TLS version, ALPN, and recognized cipher-suite names.
- CSV export of parsed packet metadata.
- Local processing: the app does not upload capture files.
- GitHub Actions workflow to run unit tests and build a debug APK.

## Build requirements

- Android Studio with Android Gradle Plugin 8.7.3 support.
- JDK 17.
- Gradle 8.9.
- Android SDK Platform 35 and Build Tools 35.0.0.
- Minimum device version: Android 12 / API 31.

### Build in Android Studio

1. Download or clone this repository.
2. Open the `NetCapturePro` project root in Android Studio.
3. Set the Gradle JDK to JDK 17 in Android Studio.
4. Install Android SDK Platform 35 and Build Tools 35.0.0 from SDK Manager.
5. Configure Android Studio to use a local Gradle 8.9 installation (this source archive does not include a generated wrapper JAR).
6. Run **Build → Make Project** or run the `app` configuration.

The GitHub Actions workflow installs Gradle 8.9 itself, so no wrapper JAR is needed for the hosted build.

## Build APK on GitHub

1. Create a new GitHub repository.
2. Upload the contents of this project folder to the repository root (including `.github/workflows/android-build.yml`).
3. Push to the `main` branch, or open **Actions → Build Android APK → Run workflow**.
4. Wait for the workflow to finish successfully.
5. Open the workflow run and download the `NetCapturePro-debug-apk` artifact.
6. Extract the artifact; it contains `app-debug.apk`.

The workflow runs `:app:testDebugUnitTest` before `:app:assembleDebug`.

## Using the app

1. Open **Apps** to search and select installed applications for your workspace.
2. Open **Home** and tap **IMPORT PCAP FILE**.
3. Choose a classic `.pcap` file that you are authorized to inspect.
4. Open **Analyze** and switch between HTTPS, TCP, PACKET, UDP, and KEY.
5. Use **CSV** to export the parsed metadata.

The app limits imported files to 32 MB and inspects up to 50,000 frame records per file.

## Format and parser limitations

- Classic PCAP is supported; **PCAPNG is not supported** in this build.
- TCP stream reassembly and fragmented IP reassembly are not implemented. A TLS handshake split across TCP segments may not be recognized.
- TLS application data remains encrypted. The KEY tab shows only public handshake metadata visible in the capture; it does not extract private keys, passwords, tokens, cookies, or session secrets.
- TLS 1.3 certificate messages may be encrypted after the handshake and therefore may not be visible in a passive capture.
- DNS parsing is basic and focuses on uncompressed question names.
- This is a metadata analyzer, not a full protocol dissector or security-testing tool.

## Privacy and authorization

Only inspect captures you own or are explicitly authorized to analyze. NetCapture Pro does not bypass HTTPS, certificate pinning, app protections, or encryption. It does not attempt to obtain secret keys from other apps. The selected PCAP is processed locally and can be exported only through an explicit user action.

## Project structure

```text
NetCapturePro/
├── .github/workflows/android-build.yml
├── app/
│   ├── src/main/AndroidManifest.xml
│   ├── src/main/java/com/netcapture/pro/MainActivity.kt
│   ├── src/main/java/com/netcapture/pro/parser/PcapParser.kt
│   └── src/test/java/com/netcapture/pro/parser/PcapParserTest.kt
├── build.gradle.kts
├── settings.gradle.kts
└── gradle.properties
```
