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
| iCan i3/i6 (Sinocare) | Not ported yet (paused by request) | – |
| Sibionics GS1/GS2 | Skipped | – |
| Ottai / SyAi | Skipped | – |
| MQ / Glutec | Skipped | – |
| Anytime / Yuwell | Skipped | – |
| CareSens Air | Skipped | – |

Core Data: AiDex adds model **v38** (entity `AiDex`), SmartGuide adds **v39** (entity
`AccuChekSmartGuide`). Both are additive, so lightweight migration applies.

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

## iCan i3/i6 (Sinocare) — not ported yet

Assessed and judged portable in part, then paused on request. Notes for later:
- Portable without cloud: CBC/PKCS7 auth with the bundled key families (selected from the
  serial/software version), user-id recovery from the `1C F4 02` reject, 19-byte live frames,
  `SN…` history batches, warm-up XOR keyed on challenge[0]. JugglucoNG has captured vectors
  (`ICanHealthLiveCbcVectorTests`).
- Not portable: provisioning fresh sensors with the vendor `correctCode` table needs Sinocare's
  cloud and a signing step whose implementation is in packed native code; unprovisioned
  sensors reportedly stop after about 7 days. A port would therefore only support sensors
  already activated by the vendor app.

## Skipped sensors

- **Sibionics GS1/GS2**: the sensor sends a raw signal. JugglucoNG's own notes say treating it as
  glucose reads about 2 mmol/L low; correct values need the vendor algorithm, which JugglucoNG
  carries as ~49k lines of decompiled vendor code (`SibionicsExactV115GClip.kt`,
  `SibionicsExactV116A.kt`). Not safe to ship raw, not reviewable to port.
- **Ottai / SyAi**: glucose comes from a per-device formula the Ottai cloud sends encrypted, and
  fresh V3 sensors need cloud-mediated authentication. Requires the vendor cloud at runtime.
- **MQ / Glutec**: raw current only. Glucose needs vendor-cloud parameters (login + the
  Bluetooth MAC, which iOS does not expose) or local fingerstick calibration; JugglucoNG's own
  status text is "Need vendor restore or local calibration".
- **Anytime / Yuwell**: the `libalgorithm-jni.so` fallback is not good enough: the CT3 kernel port
  is not wired even in JugglucoNG, CT2/CT4 use empirical models, and only CT5 computes glucose
  in the transmitter (and stops at end of life), behind an extra encrypted identity layer.
- **CareSens Air**: glucose comes from i-SENS' `libCALCULATION.so` (vendor binary loaded at
  runtime).
