# Later

## Tie .cms co-signatures together

In a .cms, co-signatures sit side by side (parallel SignerInfos). Each one covers only the
document, not the other signatures, so anyone holding the file can delete one signer and the
rest still verify. NCALayer co-signs the same way (it copies the earlier SignerInfos and adds
the new one next to them; no countersignatures). PDFs don't have this gap: each new
signature covers the whole file, earlier signatures included.

Options looked at:

- **Countersignature** (CMS `counterSignature` unsigned attribute on the earlier SignerInfo).
  Standard, but other tools, NCALayer among them, would not list the countersigner as a
  signer of the document, and deleting the earlier SignerInfo deletes the countersignature
  with it.
- **Parallel signature plus a list of the earlier signatures.** The new signer signs side by
  side as today, and adds a signed attribute holding digests of the SignerInfos already in
  the file. Other tools ignore an unknown signed attribute (Order 500/НҚ p.8 allows extra
  attributes that don't block verification). kzsigner's check turns red with "a signature
  was removed from this file" when a listed signature is missing. Needs our own OID.

Only protects files co-signed with kzsigner; a file co-signed only in NCALayer stays as it is.

## Next app batch

Small app changes, collected to build and test in one go.

- **Don't block Sign until the document is read** (agreed). Today Word, Excel, XML and other
  files the app can't show keep Sign disabled until they were opened in another app
  (`needsReading` in SignScreen.kt); PDFs never were. The law asks that the person *can* see
  what they sign (Digital Code Art. 50), not that they must. Sign is always enabled; "Read
  it" stays beside the file card, and for files the app can't show, the line under the card
  says "Open it to check what you're signing". Update AppFlows if it relies on the gate.
- **Emulator tests cover every flow** (agreed). Today the emulator stops at "isn't
  recognized" when signing, because NCA doesn't know the test keys, so these are tested only
  in the core: a finished signature (Signed screen, Send, Save, the Who signed page, adding
  to someone's PDF or .cms), a valid, revoked, expired or unconfirmed check, a detached .cms
  with its document, no internet. Plan: CI starts the fake NCA servers (tests/common/nca.rs,
  as a small binary) on the host, and the app's test build (build type "uitest") points at
  them through the emulator's host address (10.0.2.2) with the test CAs trusted for
  everything, not only adding. Then AppFlows walks each flow on screen: sign PDF, XML, Word
  (new .cms), co-sign a .cms and a signed PDF, the prompt cancelled, the key reset, signing
  with the password on a phone with no screen lock, NCA revoked, NCA not answering, check
  valid / changed / revoked / not signed / detached, About, the language switch. The released
  APK keeps NCA's real servers and trust; the test build is never released.
- **One arm64-only APK, tested as shipped** (agreed). Drop the x86_64 core from the APK
  (about 3 MB of its 10 MB). GitHub's arm64 runners can't run the emulator (no KVM, as
  reported; GitHub's docs don't say), so keep the x86_64 emulators: Android 11 and newer
  x86_64 system images translate arm64 apps, so they run the arm64-only APK. Check that it
  starts and signs on API 30, 35 and 36; if an image lacks the translation, say so and
  decide then. The test build (build type "uitest") is arm64-only too.
- **Revocation line in Signature details** (proposed): shows the core's raw text, e.g.
  "UNKNOWN (issuer certificate not available)"; give it plain words like the rest.

## Before release

- Native-speaker check of the Kazakh and Russian text that goes into signed PDFs (the Who
  signed page note, box headings, footer) and of the app's strings.
- Check on a real Pixel: typing, TalkBack, StrongBox, fingerprint.
- Match NCALayer's box size and spacing from a PDF signed with its current version.
- Pricing: decides the footer's "free" and About's "no accounts, no tracking".
- The footer's desktop link needs the repository public, and the iOS link an App Store id.
