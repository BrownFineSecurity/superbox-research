# SuperBOX App Store Encryption Research

Complete reverse engineering analysis of the encryption scheme used by the `com.apk.store` Android application on SuperBOX streaming devices.

## Overview

This repository documents the encryption methods used by the SuperBOX App Store application for HTTP API communication. The encryption is implemented in the native library `libaijni.so` and uses AES-128-CBC with custom key derivation algorithms.

**Target Application:** `com.apk.store`
**Device:** SuperBOX S6 PRO
**Analysis Date:** December 2025

## Repository Contents

| File | Description |
|------|-------------|
| `superbox_decrypt.py` | Complete decryption tool for HTTP traffic |
| `req.txt` | Sample captured HTTP request/response |
| `appstore.apk` | Original APK file |

## Quick Start

```bash
# Install dependencies
pip install pycryptodome

# Decrypt captured traffic
python3 superbox_decrypt.py req.txt

# With verbose key derivation details
python3 superbox_decrypt.py req.txt -v

# JSON output
python3 superbox_decrypt.py req.txt --format json
```

## Encryption Scheme Summary

The application encrypts three types of data using AES-128-CBC, each with different key derivation:

| Data | Key Derivation | Purpose |
|------|----------------|---------|
| `key` param | MAC + timestamp | Device authentication |
| `key1` param | MAC + timestamp | IP geolocation data |
| `dev` param | Timestamp only | Device information JSON |
| Response body | MAC + model | Server response |

### Key Derivation Details

#### Request Parameters (key, key1) and Response

```
Key Material = MAC[4:10] + "errorstr" + suffix
                 │              │           │
                 │              │           └── utctime (request) or model (response)
                 │              └── Magic string (see suffix table)
                 └── Characters 4-9 of MAC address (hex filtered)

MD5 Hash = md5(Key Material)
AES Key = MD5[8:24] (16 ASCII characters)
AES IV = same as Key
```

**Magic Suffix Table** (selected by first byte of `sKeys = "0!a$qN38"`):

| Index | Suffix | Trigger |
|-------|--------|---------|
| 0 | `errorstr` | Default (sKeys[0]='0') |
| 1 | `3fe083ff` | sKeys[0]='1' |
| 2 | `c1badf71` | sKeys[0]='2' |
| 3 | `01e8206d` | sKeys[0]='3' |
| 4 | `87e1872a` | sKeys[0]='4' |
| 5 | `f60939f0` | sKeys[0]='5' |
| 6 | `fc4857ef` | sKeys[0]='6' |
| 7 | `5cd28633` | sKeys[0]='7' |
| 8 | `7b078876` | sKeys[0]='8' |

#### Dev Parameter (Different Algorithm)

The `dev` parameter uses `api_getDevMsg2` which has a completely different key derivation:

```python
def derive_dev_key_iv(utctime: str) -> tuple:
    """
    Generate 32-char hex key from timestamp, then split into Key/IV.
    """
    hex_chars = "0123456789ABCDEF"

    # Step 1: Generate 32-character key from timestamp
    key32 = []
    for i in range(32):
        char_val = ord(utctime[i % len(utctime)]) + i - 48
        key32.append(hex_chars[char_val % 16])

    # Step 2: Extract Key (positions 0-7 and 24-31)
    key = key32[0:8] + key32[24:32]  # 16 chars

    # Step 3: Extract IV (positions 8-23)
    iv = key32[8:24]  # 16 chars

    return key.encode(), iv.encode()
```

## Example Decryption

### Input (req.txt)

```http
POST /api5/desktop/v5/stbauth? HTTP/1.1
mac: 006e222570c3
model: SuperBOX_S6PRO
utctime: 1765493334588

key=k4qUM5BwScufd0WtS0kKn%2BuQHqU4%2B9ydjl7ANbdG9VI%3D&key1=...&dev=...

HTTP/1.1 200 OK
andnfsM9lst8ccUutjjWKZIY0pJHkDWN3Mv9h9rYC4Gki...
```

### Output

```
[key parameter]
cpuid=0123456789abcdef

[key1 parameter - IP Geolocation]
{
  "as": "AS9009 M247 Europe SRL",
  "city": "Los Angeles",
  "ip": "146.70.230.149",
  "proxy": true
}

[dev parameter - Device Info]
{
  "date": "2025-12-11 14:48:53",
  "sn": "3c0001041c244c7e1d92",
  "ethmac": "00:6e:22:25:70:c3",
  "appName": "com.apk.store",
  "uid": "23515087980646ffb74fc3e017002cbe",
  "model": "SuperBOX_S6PRO",
  "hardware": "sun50iw9p1",
  "sdk": "31",
  "system": "Android12"
}

[response body]
{
  "code": 0,
  "msg": "auth success",
  "data": {
    "stb": 1,
    "bscfg": {
      "tvauth": "https://vac.colemyapp.com/v1/auth",
      "tvmk": "https://bro.applocal.top/v1/caches"
    }
  }
}
```

## HTTP Request Structure

### Headers

| Header | Purpose |
|--------|---------|
| `mac` | Device MAC address (used in key derivation) |
| `model` | Device model name (used for response decryption) |
| `utctime` | Unix timestamp (used for request encryption) |
| `ver` | Application version |
| `pkg` | Package name (`com.apk.store`) |

### Encrypted Parameters

| Parameter | Content | Encryption |
|-----------|---------|------------|
| `key` | Auth parameters (e.g., `cpuid=...`) | AES-128-CBC |
| `key1` | IP geolocation JSON array | AES-128-CBC |
| `dev` | Device information JSON | AES-128-CBC |

### Response

- Base64-encoded AES-128-CBC ciphertext
- JSON structure with `code`, `msg`, and `data` fields

## Device Info JSON Structure

The `dev` parameter contains comprehensive device information:

```json
{
  "date": "2025-12-11 14:48:53",
  "sn": "3c0001041c244c7e1d92",
  "ethmac": "00:6e:22:25:70:c3",
  "wifimac": "",
  "appName": "com.apk.store",
  "appVer": "2025061117",
  "uid": "23515087980646ffb74fc3e017002cbe",
  "serialNo": "3F100000000000000000000000000000",
  "imei": "",
  "meid": "",
  "deviceid": "",
  "androidid": "6d9e3cf8ec35eb72",
  "model": "SuperBOX_S6PRO",
  "device": "raven",
  "hardware": "sun50iw9p1",
  "brand": "google",
  "sdk": "31",
  "system": "Android12",
  "version": "F9C625EEA28B6B2356440AE122DB508D13445CAD",
  "memory": "3909",
  "hdmi": "0",
  "cvbs": "0",
  "uptime": "5726.92 22330.08",
  "display": "SuperBOX_S6PRO.20250611.V1.0.0",
  "arm": "cortex-a7",
  "ril": "0",
  "eth": "1",
  "wifi": "0",
  "rand": "2025-12-11 14:48:540825014306426"
}
```

## Native Library Analysis

### Key Functions in `libaijni.so`

| Address | Function | Purpose |
|---------|----------|---------|
| `0x25a044` | `api_encodeAES` | AES encrypt for key/key1 params |
| `0x25a2a4` | `api_decodeAES` | AES decrypt for response |
| `0x25ba84` | `api_getDevMsg2` | **Dev param encryption** |
| `0x25aed4` | `api_getDevMsg` | Alternate device info function |
| `0x25953c` | `genAesEm` | Key derivation for encryption |
| `0x2597b4` | `genAesDm` | Key derivation for decryption |
| `0x25c510` | `api_getDevSign` | RSA signing (unused) |
| `0x25c7b0` | `api_getDevKey` | RSA key (unused) |

### Global Variables

| Address | Name | Purpose |
|---------|------|---------|
| `0x284370` | `byte_284370` | Device UID storage (32 bytes) |
| `0x284394` | `dword_284394` | Filtered MAC address |
| `0x28436C` | `dword_28436C` | Model name storage |
| `0x283648` | `dword_283648` | Key index (0-8) |

### Java Entry Points

```java
// From com.p011ai.jni.JniApi.java
public native byte[] encodeAES(byte[] keys, byte[] utctime, byte[] plaintext);
public native byte[] decodeAES(byte[] keys, byte[] ciphertext);
public native byte[] get_dev(byte[] unused, byte[] utctime);
```

## Security Analysis

### Weaknesses Identified

1. **Key = IV**: Using the same value for both AES key and IV is cryptographically weak
2. **Predictable Keys**: Key material derived from observable values (MAC, timestamp, model)
3. **Static Magic Suffixes**: Hardcoded values can be extracted from binary
4. **No Authentication**: AES-CBC provides confidentiality but not integrity
5. **Timestamp-only Dev Key**: The dev parameter key is derived solely from the timestamp

### Attack Vectors

- **Passive Decryption**: All traffic can be decrypted by capturing HTTP requests
- **Traffic Replay**: Without authentication, captured requests could be replayed
- **Device Fingerprinting**: Device info in `dev` parameter enables tracking

## Tool Usage

### Basic Usage

```bash
# Decrypt single capture
python3 superbox_decrypt.py request.txt

# Multiple captures in one file
python3 superbox_decrypt.py all_traffic.txt

# Verbose output with key derivation
python3 superbox_decrypt.py request.txt -v

# JSON output
python3 superbox_decrypt.py request.txt --format json

# Save to file
python3 superbox_decrypt.py request.txt -o decrypted.txt
```

### Input File Format

The tool expects HTTP request/response pairs in text format:

```http
POST /api5/desktop/v5/stbauth? HTTP/1.1
Header1: value1
Header2: value2

body=parameters&here

HTTP/1.1 200 OK
Response-Header: value

response_body_here
```

## References

- APK: `com.apk.store` from SuperBOX S6 PRO
- Native library: `libaijni.so` (ARM32)
- Analysis tools: IDA Pro, jadx, apktool

## License

This research is provided for educational and security research purposes only.
