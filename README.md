# OpenDOF End-To-End Security Java Interface

A Java demonstration of end-to-end encrypted IoT communication over the OpenDOF (Distributed Object Framework) platform. The project implements a full Diffie-Hellman key exchange followed by AES/CBC symmetric encryption for all subsequent data, using the OpenDOF OAL (Object Abstraction Layer) API.

---

## Overview

OpenDOF is a publish/subscribe middleware for IoT devices. Objects on the DOF bus expose typed interfaces; any node can get, set, or invoke items on any object it can reach. This project adds an end-to-end security layer on top of that model: before any alarm data is exchanged, the requestor and provider perform a DH handshake over the bus and derive a shared AES key that neither party ever transmits.

The demo application (`TrainingUI`) creates two providers and one requestor in the same JVM, connected via a loopback DOF bus, and presents a Swing GUI for exercising Get, Set, and Invoke operations.

---

## Security Protocol — ETE Handshake

```
Requestor                                   Provider
---------                                   --------
1. Generate 2048-bit DH params
2. Generate DH key pair (pub/priv)
3. Generate random 16-byte IV
4. SEND_ENCODED_PUB_KEY invoke ──────────►
   params: [IV blob, requestorPubKey blob]
                                        5. Decode requestor's pub key
                                        6. Extract DH params from that key
                                        7. Generate own DH key pair (same params)
                                        8. Run DH doPhase(requestorPubKey)
                                        9. generateSecret() → shared bytes
                                       10. secKey = first 16 bytes → AES-128
                                       11. Init AES/CBC ciphers with IV
                                       12. Respond with providerPubKey blob ◄──
13. Decode providerPubKey blob
14. Run DH doPhase(providerPubKey)
15. generateSecret() → same shared bytes
16. secKey = first 16 bytes → AES-128
17. Init AES/CBC ciphers with same IV
         [both sides now share identical AES key + IV]
18. All subsequent data encrypted/decrypted
    via DataTransform.transformSendData /
    transformReceiveData
```

---

## Architecture

```
+----------------+      DOF Bus (loopback)      +------------------+
|   Requestor    | ◄──────────────────────────► |    Provider      |
|                |                              |                  |
| sendGetRequest |   Get(PROPERTY_ALARM_ACTIVE) | TBAOperationList.|
| sendSetRequest |   Set(PROPERTY_ALARM_ACTIVE) | get / set /      |
| sentInvokeReq  |   Invoke(METHOD_SET_NEW_TIME)| invoke           |
| SEND_ENCODED.. |   Invoke(SEND_ENCODED_PUB_K) | ETEOperationList.|
|                |                              | handleSend...    |
+----------------+                              +------------------+
        |                                               |
        ▼                                               ▼
  DefaultDataTransform                      savedEncryptCipher
  (encrypt outgoing,                        savedDecryptCipher
   decrypt incoming)                        (initialized post-handshake)
```

**Class relationships:**

- `TrainingUI` creates `DOFAbstraction`, two `Provider` instances, and one `Requestor`
- `DOFAbstraction` wraps the `DOF` node and creates `DOFSystem` instances
- `Requestor` queries for providers advertising `TBAInterface`, holds a `DefaultDataTransform` after key exchange
- `Provider` hosts both `TBAInterface` and `ETEInterface` on a single `DOFObject`
- `DataTransform` (interface) is implemented by `Requestor.DefaultDataTransform`

---

## File Descriptions

| File | Role |
|------|------|
| `TrainingUI.java` | Swing GUI entry point; wires DOF systems, providers, requestor |
| `DOFAbstraction.java` | Thin wrapper that creates/destroys the DOF node and systems |
| `Provider.java` | DOF provider hosting TBAInterface (alarm) and ETEInterface (key exchange) |
| `Requestor.java` | DOF requestor; drives DH handshake and holds the AES DataTransform |
| `DataTransform.java` | Interface with `transformSendData` / `transformReceiveData` |
| `ETEInterface.java` | Defines the `SEND_ENCODED_PUB_KEY` method and its DOF type signatures |
| `TBAInterface.java` | Defines the alarm properties, method, event, and exception |
| `Tester.java` | Stub for headless testing (currently commented out) |
| `ProviderSnippet.java` | Educational reference showing provider-side DH algorithm |
| `RequestorSnippet.java` | Educational reference showing requestor-side DH algorithm |
| `DataTransformSnippets.java` | Educational reference showing DataTransform wiring |

---

## Key Interfaces

### `ETEInterface`

```
IID: [63:{53551070}]
Property 1: BLOB_KEY (256 bytes, read/write)
Method   2: SEND_ENCODED_PUB_KEY
             params:  [INIT_VECTOR (16 bytes), BLOB_KEY (256 bytes)]
             returns: [BLOB_KEY (256 bytes)]
```

### `TBAInterface`

```
IID: [1:{01000034}]
Property 1: ALARM_ACTIVE   (Boolean, read/write)
Property 2: ALARM_TIME_VALUE (DateTime, read-only)
Method   3: SET_NEW_TIME   params: [DateTime]  returns: [Boolean]
Event    4: ALARM_TRIGGERED (no parameters)
Exception 5: BAD_TIME_VALUE (no parameters)
```

### `DataTransform`

```java
public interface DataTransform {
    byte[] transformSendData(DOFInterfaceID interfaceID, byte[] data);
    byte[] transformReceiveData(DOFInterfaceID interfaceID, byte[] data);
}
```

---

## Building

Requires the OpenDOF OAL jar on the classpath (e.g. `opendof-oal-java-3.x.jar`).

```bash
javac -cp path/to/opendof-oal.jar \
      src/org/opendof/core/oal/endtoend/*.java
```

---

## Running

```bash
java -cp path/to/opendof-oal.jar:src \
     org.opendof.core.oal.endtoend.TrainingUI
```

The GUI window displays provider panels and requestor panels. Use the radio buttons to select a provider, then click **Get**, **Set**, or **Invoke** to exercise operations. The first Get triggers the ETE session setup and `SEND_ENCODED_PUB_KEY` handshake.

---

## Design Notes

**Why first 16 bytes of DH secret → AES-128?**
The DH shared secret is a large integer (2048-bit in Requestor's implementation). AES-128 needs exactly 16 bytes. Truncating to the first 16 bytes is a common simplification for educational purposes; production code would run the secret through a KDF (e.g. HKDF) instead.

**Why must the IV be shared and stored?**
AES/CBC decryption of the first block requires the same IV used during encryption. The requestor generates the IV, sends it as the first parameter to `SEND_ENCODED_PUB_KEY`, and both sides store it in `initializationVector` before initialising their ciphers.

**Why are DH params extracted from the requestor's public key?**
The provider must use the same DH group (prime + generator) as the requestor, otherwise `doPhase` produces different secrets. Rather than negotiating parameters separately, the provider extracts them directly from the requestor's encoded public key via `((DHPublicKey) requestorPubKey).getParams()`.

**Why does `beginSession` appear in `sendGetRequest`?**
`beginSession` in OpenDOF establishes a typed session context between two objects. Here it registers the ETE session type (`ETEInterface.IID`) on the TBA connection, signalling that the requestor wants end-to-end security. The actual key exchange is driven by `SEND_ENCODED_PUB_KEY`; `beginSession` sets up the DOF-layer context.

---

## Educational Files

`ProviderSnippet.java`, `RequestorSnippet.java`, and `DataTransformSnippets.java` are reference-only files. They contain annotated pseudocode and algorithm sketches written by the original student developers as working notes. They compile but perform no runtime operations.
