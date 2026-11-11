# CGM sensors ported from JugglucoNG

Direct Bluetooth support for CGM sensors that JugglucoNG (Android, GPL-3.0,
https://github.com/ctqvva/JugglucoNG, fork of Juggluco by Jaap Korthals Altes) supports and
xDrip4iOS did not. Libre 2/3 and Dexcom were already supported and are not covered here.

None of this code has been compiled or run: it was written on Linux. Everything below
under "Test on a Mac" has to happen before anyone relies on these readings.

| Sensor | Status | Commit |
| --- | --- | --- |
| AiDex X / LinX (and rebrands) | Ported | `Add direct Bluetooth support for AiDex X / LinX sensors` |
| Accu-Chek SmartGuide | Ported | `Add direct Bluetooth support for Accu-Chek SmartGuide sensors` |
| iCan i3/i6 (Sinocare) | Ported, already-started sensors only | `Add direct Bluetooth support for iCan i3/i6 sensors` |
| Sibionics GS1/GS2 | Skipped | – |
| Ottai / SyAi | Skipped | – |
| MQ / Glutec | Skipped (vendor cloud + MAC) | – |
| Anytime / Yuwell | Skipped (CT5 possible later) | – |
| CareSens Air | Skipped | – |

Core Data: AiDex adds model **v38** (entity `AiDex`), SmartGuide **v39** (`AccuChekSmartGuide`),
iCan **v40** (`ICan`). All are additive, so lightweight migration applies.

---

## AiDex X / LinX

**Ported** (`xDrip/BluetoothTransmitter/CGM/AiDex/`), from
`drivers/aidex/native/{crypto,protocol,data}` and `ble/AiDexBleManager.kt`:

- Crypto: serial → F001 challenge and IV (MD5 of transformed serial digits), AES-128-CFB
  (CommonCrypto ECB as building block), CRC-8/MAXIM for the BOND vector, CRC-16/CCITT-FALSE
  for F002 commands/responses and the F003 frame.
- Key exchange: challenge to F001 → 16-byte PAIR key notified on F001 → 17-byte BOND read on
  F002 → session key. Saved-key reconnects skip F001 and read BOND directly.
- Encrypted F003 live frames (glucose mg/dL, minute offset since sensor start, CRC check),
  5-byte status frames (battery mV).
- F002 commands: startup device info (0x10: firmware, hardware, wear days, model), start time
  (0x21, or CGM Session Start Time 0x2AAA on a paired link), SET_NEW_SENSOR (0x20) to activate a
  fresh sensor whose start time reads all zeros (JugglucoNG does the same), history range (0x22)
  and calibrated history pages (0x23) for up to 12 h of backfill, delivered every 5 minutes.
- Identity: the serial is parsed from the advertised name (`AiDEX X-…`, `LinX …`, `Smart-…`,
  `IndiaX-…`, `VitaTok-…`, generation letters X/F/G/Q…); scanning is filtered on service 0x181F.
- Pairing key stored in the Keychain per serial (`AiDexPairingStore`,
  `AfterFirstUnlockThisDeviceOnly`, not synchronised), saved only after the first CRC-valid live
  frame proved it.
- iOS redesign of JugglucoNG's bond-state logic: the record keeps `linkPaired` (this phone
  completed an F001 write, which needs an encrypted link). An F001 write that fails with an ATT
  authentication/encryption error clears it; a disconnect with `peerRemovedPairingInformation`
  clears it and tells the user to forget the sensor in iOS Settings. Three BOND failures with the
  saved key trigger a fresh F001 pairing only when `linkPaired` (the sensor accepts F001 only
  from its bonded phone); otherwise the user is told to re-add the sensor. A single `00` on F001
  means the sensor refuses to pair (bonded elsewhere). The post-BOND config write to F001 is only
  sent on a paired link, as JugglucoNG does.
- Tests (`xDrip Tests/AiDexProtocolTests.swift`): JugglucoNG vectors (2222267V4E secret/IV,
  F-generation challenge, HCI-trace CRCs, rawr frame, live-log history page) plus NIST CFB128
  and BOND/command/frame ciphertexts generated independently with Python `cryptography`.

**Skipped**: JugglucoNG's custom algorithms (adaptive v2, raw lanes, user calibration, default
param provisioning, the BloodControl variant, the CN cloud client, broadcast-only fallback
scanning, reset/unpair maintenance commands). xDrip4iOS uses the sensor's factory-calibrated
value with `NoCalibrator`.

**Risks**
- The Swift was never compiled. Expect a few compile fixes.
- The sensor is chosen as the first AiDex found in range (no serial entry in the add flow).
- History timestamps are anchored on the live minute counter; if a sensor's live offset ever
  disagrees with history, backfilled points shift. JugglucoNG has extra "trusted offset" logic
  that was not ported.
- `SET_NEW_SENSOR` is sent automatically when the start time is zero. A misread could restart
  a running sensor session.
- History pages strip the CRC trailer before parsing; JugglucoNG passes it into the parser. If
  real pages differ, rows could shift by one.
- The iOS pairing behaviour (when the dialog appears, whether F002/F003 work unencrypted) is
  inferred from JugglucoNG's Android notes.
- Warm-up uses xDrip's default 45 minutes on top of the sensor's own invalid-reading flag.

**Test on a Mac**
1. Build; run `AiDexProtocolTests`.
2. Fresh sensor, not paired with any other app: add "AiDex X / LinX", accept the iOS pairing
   dialog. Check the trace for `PAIR key received`, `session key established`, activation
   (`SET_NEW_SENSOR` status 0x00) and `PAIR key validated and stored`.
3. Compare live values and the minute offset against the vendor app or a fingerstick for a day.
4. Kill/relaunch the app and toggle Bluetooth: the reconnect must use the saved key (no dialog).
5. Stay out of range for over an hour, come back: backfill should fill the gap in 5-min steps
   at the right times.
6. Forget the sensor in iOS Settings and reconnect: expect the "forget in iOS settings" or
   re-pair path, not a loop.
7. A sensor already paired with the vendor app: expect "refused to pair".

---

## Accu-Chek SmartGuide

**Ported** (`xDrip/BluetoothTransmitter/CGM/AccuChek/`), from Juggluco's
`AccuGattCallback.java` and `cpp/accu/java.cpp`:

- Standard Bluetooth CGM profile (0x181F) plus Device Information. The sensor calculates
  glucose; values (SFLOAT mg/dL) are used as delivered with `NoCalibrator`.
- Juggluco's sequence: encrypted CGM Status read (triggers the iOS pairing/PIN dialog) → DIS
  reads → notifications on 2AA7, indications on RACP and SOCP → `Get Communication Interval`
  → CGM Feature → status → session start/run time → calibration-value reads (`05 00 00 …`,
  `05 FF FF …`) → RACP "report records ≥ offset" from the last delivered minute (max 12 h back).
- Record timestamps = session start (now − CGM Status minutes) + record minutes, as Juggluco.
- Every measurement's E2E-CRC is checked. The variant (CRC-16/MCRF4XX) was identified by
  matching all eight frames quoted in Juggluco's comments.
- Juggluco's "below range" heuristic: a `-INF` record after a value below 120 mg/dL within
  5–30 minutes is stored as 39 mg/dL. Records with warning/status annunciation or NaN are not
  stored.
- Paired/unpaired path chosen from a per-serial flag (iOS has no bond state), cleared on ATT
  authentication errors and `peerRemovedPairingInformation`.
- Tests (`xDrip Tests/AccuChekSmartGuideProtocolTests.swift`): Juggluco's captured frames,
  commands, SFLOAT and multi-record parsing.

**Skipped**: Appearance read (CoreBluetooth hides the GAP service), HI (+INF) records (Juggluco
drops them too), trend from the sensor (xDrip computes its own).

**Risks**
- Never compiled.
- No real "live" capture with flags `0x43` was available; the valid-record test is synthetic.
- First AiDex-style "first sensor in range" selection applies here too (`AC-` prefix).
- The calibration-value responses are not decoded, only used to advance the sequence.

**Test on a Mac**
1. Build; run `AccuChekSmartGuideProtocolTests`.
2. Add "Accu-Chek SmartGuide", enter the sensor PIN in the iOS dialog; check the trace for the
   phases and `requesting records from offset`.
3. Compare values and timestamps with the Accu-Chek app / fingersticks.
4. Reconnect after relaunch: must take the paired path without a dialog.
5. Out-of-range gap: RACP backfill should fill it.

---

## iCan i3/i6 (Sinocare)

**Ported** (`xDrip/BluetoothTransmitter/CGM/ICan/`), from `drivers/icanhealth/` and
`docs/ican-cgm-protocol.md`:

- Bundled vendor AES keys, key family chosen from characters 10–11 of the DIS serial (or the
  software revision), CBC/PKCS7 with the challenge-derived IV (bytes 1/6/10/15).
- Vendor authentication on 0x2AAC: `F3` → challenge → `F4 10 <token>` → `1C F4 01`. A sensor
  started by the vendor app rejects the default user id; the expected id is recovered from the
  `1C F4 02` rejection and authentication is retried once, as JugglucoNG does. The recovered id
  is kept per serial.
- `F6` calibration marker read and shown (0xFFFF = no vendor calibration table).
- 19-byte live frames (every 3 minutes, 1 minute on i7), warm-up XOR keyed on challenge[0],
  sensor profiles (interval, warm-up, lifetime per model family).
- RACP glucose history from the last delivered sequence (max 12 h back), `SN` batches and single
  16-byte records; command family F1 or legacy 01 chosen from the MTU (≥ 247), with JugglucoNG's
  single live-edge retry after a refused range (0x0A).
- Timestamps from the CGM Status minute counter (the stored 0x2AAA wall clock is unreliable).
- Tests (`xDrip Tests/ICanProtocolTests.swift`): JugglucoNG's captured live frames (iCGM-t3 new
  key, iCGM-t6 old key), the documented warm-up values (5.97 and 3.85 mmol/L), plus an auth
  token and an SN batch generated with Python `cryptography`.

**Skipped**: starting a fresh sensor (`1A` + session start write) and installing the vendor
calibration table (`correctCode`): the table comes from the Sinocare cloud, whose signing step
is in packed native code, and unprovisioned sensors reportedly stop after about 7 days. An idle
sensor is reported ("start it with the iCan app"). Also skipped: user calibration (vendor
libAlg port), original (current/temperature) history, the many address-rebind and
onboarding-verification paths.

**Risks**
- Never compiled.
- Glucose is the sensor's value in hundredths of mmol/L; on the one sensor JugglucoNG matched
  against the factory table, readings ran high. Compare with fingersticks.
- Sensors whose box serial selects the "direct" 16-bit history encoding are not detected (needs
  the box serial, which this port does not ask for); they would read wrong history values.
- The first iCan sensor in range is used.
- Only one authentication retry; a sensor bound to another phone of the same vendor account
  may still reject.

**Test on a Mac**
1. Build; run `ICanProtocolTests`.
2. Start a sensor with the iCan app, close the app, add "iCan i3/i6" in xDrip4iOS. Check the trace
   for `authenticated` (or `retrying with the recovered user id`), the calibration marker and
   `requesting glucose history`.
3. Compare values with the iCan app and fingersticks, including during warm-up.
4. Out-of-range gap: history should fill it at 3-minute spacing.

## Skipped sensors

- **Sibionics GS1/GS2**: the sensor sends a raw signal. JugglucoNG's own notes say treating it as
  glucose reads about 2 mmol/L low; correct values need the vendor algorithm, which JugglucoNG
  carries as ~49k lines of decompiled vendor code (`SibionicsExactV115GClip.kt`,
  `SibionicsExactV116A.kt`). Not safe to ship raw, not reviewable to port.
- **Ottai / SyAi**: glucose comes from a per-device formula the Ottai cloud sends encrypted, and
  fresh V3 sensors need cloud-mediated authentication. Requires the vendor cloud at runtime.
- **MQ / Glutec**: raw current only. Glucose needs the QR sensitivity plus a transmitter scale
  flag that only the vendor cloud returns, and the cloud session needs the Bluetooth MAC, which
  iOS does not expose. JugglucoNG's own notes (`docs/mq-bootstrap-evidence.md`) say accuracy is
  not device-validated and report clamped readings after QR bootstrap. Not portable safely.
- **Anytime / Yuwell**: CT2/CT3/CT4 need the vendor algorithm (the CT3 kernel port is not wired
  even in JugglucoNG; CT2/CT4 use empirical models). **CT5** is the candidate for a later port:
  its handshake is local (check → setID → session cipher → querySSN → setParameters) and the
  transmitter computes glucose. Not ported yet because the transmitter computes glucose from the
  K/R calibration the app writes in setParameters; when the SSN does not decode, JugglucoNG falls
  back to default K/R, so an untested port could produce plausible but wrong values. Needs a CT5
  on the bench.
- **CareSens Air**: glucose comes from i-SENS' `libCALCULATION.so` (vendor binary loaded at
  runtime).
