# cover

Cover (COrim VERifier) is an implementation of CoRIM-based verifier as outline in CoRIM draft
spec (rev 8.) Section 9 \[[1]\]. It attempts follow the outlined algorithm up to phase 4 (ACS
generation). In lieu of subsequent phases, it uses a Rego-based policy engine for policy
evaluation, and generates an attestation result in EAR \[[2]\] format.

This implementation is intended as a Proof-of-Concept only. It has the following limitations:
- Arm CCA is the only attestation scheme that is currently implemented.
- Only signed CoRIMs are supported.
- Only basic in-memory implementation of key and CoRIM stores are implemented.

The verification flow proceeds as follows.

- CoRIMs are processed by validating their signatures and extracting contained measurements
  into the "corim store" as RV (reference values), EV (endorsed values), and EVS (endorsed
  values series) relations.
- The signature on the evidence is verified using a trust anchor obtained from the corim store
  based on an identifier inside the evidence. This is scheme-specific. For CCA, the instance ID
  is used. Evidence claims are then extracted as ECT (environment-claims tuple) records.
- The evidence ECTs are then matched to the relations in the corim store. This results in the
  ACS (appraisal claims set) -- a vector of ECT records containing evidence claims and matched
  reference values and endorsements.
- The ACS is used as an input into the policy engine along with scheme-specific policies. Each
  policy results in an appraisal containing an AR4SI \[[3]\] trust vector.
- The appraisals are added to an attestation result in EAR \[[2]\] format.

[1]: https://www.ietf.org/archive/id/draft-ietf-rats-corim-08.html#name-example-verifier-algorithm
[2]: https://www.ietf.org/archive/id/draft-fv-rats-ear-05.html
[3]: https://www.ietf.org/archive/id/draft-ietf-rats-ar4si-09.html


## API

Verification flow consists of the following components:
- A key store that contains keys that are used to verify signatures on CoRIMs. The key for a
  CoRIM is looked up from the store based on the `kid` inside the CoRIM.
- A CoRIM store that loads endorsements and reference values from CoRIMs.
- A scheme that defines how evidence is processed to extract claims, and what policy is applied
  to create an attestation result.
- A verifier that is actually responsible for appraising the evidence to generate an attestation
  result in EAR format.

```rust
    use std::fs;
    use std::collections::HashMap;
    use cover::{CcaScheme, CorimStore, KeyStore, MemKeyStore, MemCorimStore, Scheme, Verifier};

    // load the key used to verify CoRIM signatures
    let mut keystore = MemKeyStore::new();
    let key =  fs::read("test/corim/key.pub.pem").unwrap();
    keystore.add("key.pub.pem".as_bytes(), &key).unwrap();

    // load CoRIMs
    let mut store = MemCorimStore::new(keystore);
    for path in [
        "test/corim/signed-corim-cca-ref-plat.cbor",
        "test/corim/signed-corim-cca-ref-realm.cbor",
        "test/corim/signed-corim-cca-ta.cbor",
    ] {
        let bytes = fs::read(path).unwrap();
        store.add_bytes(&bytes).unwrap();
    }

    // load supported attestation schemes
    let mut schemes = HashMap::new();
    let cca_scheme: Box<dyn Scheme> = Box::new(CcaScheme::new());
    schemes.insert("cca".to_string(), cca_scheme);

    // create the verifier
    let verifier = Verifier::new(store, schemes);

    // load evidence
    let evidence = fs::read("test/cca/cca-token-01.cbor").unwrap();

    /// appraise evidence and produce the attestation result
    let result = verifier.verify("cca", evidence.as_slice(), None).unwrap();

    // assert that appraisal status for all submods in the result is "affirming".
    for (_, appraisal) in &result.ear.submods {
        assert_eq!(appraisal.status.to_string(), "affirming");
    }

```

## CLI

 This crate includes the `cover-cli` executable that can be used to run the verifier,
 producing an EAR serialized as JSON.

```bash
    target/debug/cover-cli  --corim-dir test/corim/ \
        --key test/corim/key.pub.pem --pretty  test/cca/cca-token-01.cbor \
        --nonce adfadaewafewr32r --output cca-token-01.ear.json
```

use `-h` to see the full list of command line arguments.

