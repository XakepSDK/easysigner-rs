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
- **Phone-only APK** (proposed, not decided): the release APK carries the x86_64 core for the
  emulator too, about 3 MB of its 10 MB. Build the release for arm64 only and the emulator
  tests' APK for x86_64.
- **Revocation line in Signature details** (proposed): shows the core's raw text, e.g.
  "UNKNOWN (issuer certificate not available)"; give it plain words like the rest.

## Before release

- Native-speaker check of the Kazakh and Russian text that goes into signed PDFs (the Who
  signed page note, box headings, footer) and of the app's strings.
- Check on a real Pixel: typing, TalkBack, StrongBox, fingerprint.
- Match NCALayer's box size and spacing from a PDF signed with its current version.
- Pricing: decides the footer's "free" and About's "no accounts, no tracking".
- The footer's desktop link needs the repository public, and the iOS link an App Store id.
