# In-person multi-party signing by QR

Status: draft, 2026-11-28. Covers only what's new for in-person signing. Signing itself (algorithms, signature levels, OCSP/TSA, the Who signed page, verification) works as the app does today.

## Goal

A lawyer and 5–10 people sign one PDF in a meeting. Each person scans a QR on the lawyer's phone and signs on their own phone. No server of ours; both phones talk directly, and NCA's TSA/OCSP are reached as today.

## Connection

The QR, the encrypted session and the transports follow ISO/IEC 18013-5, the EU wallet's in-person standard, ideally through an existing open-source library (Multipaz; *to check*). The lawyer's phone shows the QR, the signer's phone scans it, and everything after is encrypted.

Transports, best first, with BLE always open as the fallback:

| Transport | Works between | 6 MB PDF |
|---|---|---|
| Wi-Fi Aware | Android ↔ Android with the hardware; iPhone ↔ iPhone after the iOS pairing step; iPhone ↔ Android once Android pairing support spreads | ~1–2 s |
| Same Wi-Fi network (mDNS) | Any two phones on it, unless the network isolates clients | ~1–2 s |
| BLE | Every phone | ~1 min Android, ~2 min iPhone |

Only the optional reading and the final copy are large; everything else is a few KB.

## Flow per signer

Signers go strictly one after another: the lawyer's phone serves one signer at a time and shows the next QR only after the previous signer is accepted or rejected.

```mermaid
sequenceDiagram
  participant L as Lawyer's phone
  participant S as Signer's phone
  L-->>S: QR (18013-5)
  S->>L: Signer's certificate
  L->>L: Prepare this signer's revision as a temporary copy
  L->>S: Signing request, signed by the lawyer (hash to sign)
  opt Read before signing
    L->>S: Accepted document + prepared increment
    S->>S: Show document, check earlier signatures, recompute hash
  end
  S->>S: Sign as the app does today
  S->>L: Signature
  L->>L: Accept / Reject by certificate name
  L->>S: Signed ack; signer saves state and disconnects
  S-->>L: After everyone signs: scan final QR, fetch final PDF
```

1. **Certificate.** The signer's phone sends its certificate. Custom signature info can come later as a new format version.
2. **Prepare.** The lawyer's app builds this signer's revision as a temporary copy on top of the accepted document: their box on the Who signed page, drawn only from certificate data with no "signed" and no time, and an empty signature placeholder. It sends a request signed with the lawyer's NCA key, holding the document ID, the signer's slot, the hash to sign and a binding to this session.
3. **Read (optional).** The signer can see the accepted document, without their own box. Their app checks the earlier signatures and recomputes the hash itself; a mismatch blocks signing and is kept as evidence. Without reading, the signer relies on trust in the lawyer and the signed request, as in EU remote signing.
4. **Sign.** The signer signs the hash as the app does today.
5. **Accept.** The lawyer sees the name and IIN and taps Accept or Reject. Only Accept adds the revision to the document. Reject or a dropped connection discards the copy and the spot is reused. The signer gets a signed ack.

**Lawyer-specific bits:** the lawyer's app creates the Who signed page and the certification with the first signature, usually the lawyer's own, as the app does today. It unlocks the lawyer's key once per meeting (a key file asks for its password once; a hardware token may ask each time, to check).

**Code:** `kzsigner::inperson` runs this flow over any connection (`Channel`); `pdf::prepare` and `pdf::Prepared::insert` split PDF signing into "prepare and hash" and "insert signature". The 18013-5 session and the transports live in the apps and are still to do. Format 1 signs with GOST 34.10-2015 keys only (256 or 512); GOST 2004 is only verified.

## Signer without internet

The signer's OCSP and TSA requests go through the lawyer's phone inside the encrypted session. Each carries a fresh nonce, NCA echoes it (tested live), and the answers are NCA-signed, so the lawyer can't fake or replay them. The signer sends its signature only after valid answers arrive. A stall just shows "Waiting for NCA… / Cancel".

## Final copy

Connections aren't kept open. Each signer's app saves the state ("signed, waiting for others") and disconnects. The lawyer's app also tracks who has signed, so if an accepted signer scans again it recognises their certificate and shows their status instead of starting a new signing. After everyone has signed, the lawyer's phone shows a final QR, and signers scan it to fetch the finished PDF. Anyone can also get the file by messenger. On arrival the app checks that the signer's own signature is there and intact, and shows Complete.

## Threats

| Threat | Handling |
|---|---|
| Sniffing, fake phone, fake QR | 18013-5 encryption; the request and ack are lawyer-signed and bound to the session |
| Photographed QR | It only starts a session within ~60 s, and the lawyer must Accept the name |
| Dishonest lawyer (shows A, has B signed) | Prevented for signers who read first; others rely on trust and the signed request |
| Lawyer tampering with relayed NCA traffic | Can only delay, visibly |
| Final file that leaves out a signer | Not prevented; each signer can see whether their own signature is in their copy |
| Someone sends a signer's (public) certificate after the end to get the final file | Not prevented: the file is shared with the signers anyway; a key-proof on rescan can come later |
| Signer uses the relay to reach other hosts | The lawyer's phone passes on only to NCA's OCSP, TSA and CRL hosts, a few requests per signer |

## Open items

- Read before signing can be fooled: the lawyer's prepared piece could also swap a page. Possible fix later: the signer's app refuses to sign if that piece adds anything besides the signer's own box and signature slot.

- Choose and test the 18013-5 library on Android and iPhone.
- Wi-Fi Aware between iPhone and Android, and the iOS pairing step.
- Same-Wi-Fi on office and guest networks, which often block it.
- NCA OCSP nonce with a GOST 2015 user certificate.
- NCA's checker on a file with a new signature field per signer after the certification.
- Hardware token PIN prompts.
- Field test: 5–10 signers, mixed Android and iPhone.

Later: signing by link, NFC tap, offline signing.

Sources: [EC decision DMA.100203](https://ec.europa.eu/competition/digital_markets_act/cases/202523/DMA_100203_1655.pdf), [NL Wallet, 18013-5 close proximity](https://minbzk.github.io/nl-wallet/main/architecture/use-cases/close-proximity-disclosure.html), [IT-Wallet proximity flow](https://italia.github.io/eid-wallet-it-docs/versione-corrente/en/proximity-flow.html), [18013-5 proximity CLI notes](https://github.com/joostd/mdoc-proximity-cli-tools), [ISO 18013-5 draft](https://mobiledl-e5018.web.app/ISO_18013-5_E_draft.pdf), [MATTR verifier authentication](https://learn.mattr.global/docs/holding/proximity-verifier-authentication), [EUDI iOS RQES library architecture](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-rqes-csc-swift/blob/main/architecture.md), [EUDI wallet-driven tester, document retrieval schema](https://github.com/eu-digital-identity-wallet/eudi-app-web-walletdriven-tester-py/blob/main/app/schemas/document_retrieval.py), [CSC Data Model v1.0](https://cloudsignatureconsortium.org/resources/data-model-v-1-0-0/), [EUDI ARF signing topic](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework/blob/main/docs/discussion-topics/ab-digital-signature-using-wallet.md), [EU pilot report D8.2 on wallet signing](https://ec.europa.eu/digital-building-blocks/sites/download/attachments/924975315/D8.2%20Pilot%20report%20on%20use%20of%20the%20EUDI%20wallet%20for%20signing%20including%20signing%20for%20onboarding%20to%20financial%20services%20(June%202025).pdf), [ETSI TS 119 101](https://www.etsi.org/deliver/etsi_TS/119100_119199/119101/01.01.01_60/ts_119101v010101p.pdf), [Android NSD guide](https://developer.android.com/develop/connectivity/wifi/use-nsd), [Android NsdManager](https://developer.android.com/reference/android/net/nsd/NsdManager), [Android local network permission](https://developer.android.com/privacy-and-security/local-network-permission), [Apple WWDC20 local network privacy](https://developer.apple.com/wwdc20/10110), [Apple forums, local network permission bugs](https://developer.apple.com/forums/thread/790307), [Meraki client isolation](https://documentation.meraki.com/MR/Firewall_and_Traffic_Shaping/Wireless_Client_Isolation), [Aruba client isolation](https://arubanetworking.hpe.com/techdocs/central/latest/content/nms/access-points/cfg/networks/client-isolation.htm), [Android Wi-Fi Aware (AOSP)](https://source.android.com/docs/core/connect/wifi-aware), [Apple WWDC25 Wi-Fi Aware](https://developer.apple.com/videos/play/wwdc2025/228), [Apple forums, Wi-Fi Aware iOS↔Android](https://developer.apple.com/forums/thread/790195), [react-native-wifi-aware notes](https://github.com/mahdidavoodi7/react-native-wifi-aware), [cross-platform Wi-Fi Aware notes](https://hackmd.io/@grjte/cross-platform-wifi-aware), [Silicon Labs BLE throughput](https://docs.silabs.com/gecko-os/1/bgx/1.x/throughput), [Apple forums, Core Bluetooth throughput](https://developer.apple.com/forums/thread/770717), [Nordic DevZone, connection limit](https://devzone.nordicsemi.com/f/nordic-q-a/63409/ble-multi-link-connection---maximum-devices/258704), [PDF reference, DocMDP](https://www.verypdf.com/document/pdf-format-reference/txtidx0732.htm).
