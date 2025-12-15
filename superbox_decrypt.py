#!/usr/bin/env python3
"""
SuperBOX App Store Decryption Tool
===================================

Decrypts encrypted HTTP request/response traffic from the com.apk.store
Android application running on SuperBOX devices.

Based on reverse engineering of libaijni.so native library.

Encryption Methods:
  - key/key1: AES-128-CBC (MAC + timestamp based key derivation)
  - dev:      AES-128-CBC (timestamp-only based key derivation)
  - response: AES-128-CBC (MAC + model based key derivation)

Usage:
    python3 superbox_decrypt.py <input_file> [options]

Examples:
    python3 superbox_decrypt.py req.txt
    python3 superbox_decrypt.py traffic.txt --format json
    python3 superbox_decrypt.py captures.txt -o decrypted.json --format json
"""

import argparse
import hashlib
import base64
import json
import re
import sys
from urllib.parse import unquote, parse_qs
from typing import Optional, Tuple, Dict, List, Any
from dataclasses import dataclass

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad, pad
except ImportError:
    print("Error: pycryptodome is required. Install with: pip install pycryptodome")
    sys.exit(1)


# Magic suffix lookup table based on dword_283648 value (set by sKeys[0] character)
# sKeys = "0!a$qN38" -> first char '0' is not in '1'-'9', so default (0) is used
MAGIC_SUFFIXES = {
    0: 'errorstr',   # default - sKeys[0] = '0' or not '1'-'9'
    1: '3fe083ff',   # sKeys[0] = '1'
    2: 'c1badf71',   # sKeys[0] = '2'
    3: '01e8206d',   # sKeys[0] = '3'
    4: '87e1872a',   # sKeys[0] = '4'
    5: 'f60939f0',   # sKeys[0] = '5'
    6: 'fc4857ef',   # sKeys[0] = '6'
    7: '5cd28633',   # sKeys[0] = '7'
    8: '7b078876',   # sKeys[0] = '8'
}


@dataclass
class HTTPRequest:
    """Parsed HTTP request"""
    method: str
    path: str
    headers: Dict[str, str]
    body: str
    raw: str


@dataclass
class HTTPResponse:
    """Parsed HTTP response"""
    status_code: int
    status_message: str
    headers: Dict[str, str]
    body: str
    raw: str


@dataclass
class HTTPCapture:
    """A captured request/response pair"""
    request: Optional[HTTPRequest]
    response: Optional[HTTPResponse]


def get_magic_suffix(key_index: int = 0) -> str:
    """Get magic suffix based on key index (dword_283648)"""
    return MAGIC_SUFFIXES.get(key_index, MAGIC_SUFFIXES[0])


def derive_key_iv(mac: str, suffix_data: str, key_index: int = 0) -> Tuple[bytes, bytes]:
    """
    Derive AES key and IV using genAesEm/genAesDm logic.

    Used for:
      - Request key/key1 params: suffix_data = utctime
      - Response decryption: suffix_data = model

    Args:
        mac: Device MAC address (hex chars only, e.g., "006e222570c3")
        suffix_data: Either utctime (request) or model (response)
        key_index: dword_283648 value (0-8, default 0)

    Returns:
        tuple: (key_bytes, iv_bytes) - both are 16 ASCII chars
    """
    # Clean MAC address - keep only hex characters
    mac_clean = ''.join(c for c in mac.lower() if c in '0123456789abcdef')

    # Extract MAC characters at indices 4-9 (6 characters)
    if len(mac_clean) < 10:
        raise ValueError(f"MAC address too short: {mac_clean} (need at least 10 hex chars)")
    mac_part = mac_clean[4:10]

    # Get magic suffix for the key index
    magic = get_magic_suffix(key_index)

    # Build key material: MAC[4:10] + magic_suffix + suffix_data
    key_material = mac_part + magic + suffix_data

    # MD5 hash
    md5_hex = hashlib.md5(key_material.encode()).hexdigest()

    # Key = MD5 hex chars 8-23 (16 ASCII characters used as bytes)
    aes_key = md5_hex[8:24].encode('ascii')

    # IV = same as key (per genAesEm/genAesDm implementation)
    aes_iv = aes_key

    return aes_key, aes_iv


def derive_key_iv_dev(utctime: str) -> Tuple[bytes, bytes]:
    """
    Derive AES key and IV for 'dev' parameter using api_getDevMsg2 algorithm.

    This uses a completely different key derivation from key/key1/response:
    1. Generate 32-char key from timestamp
    2. Key = chars[0:8] + chars[24:32] (16 chars)
    3. IV = chars[8:24] (16 chars)

    Args:
        utctime: UTC timestamp string from request header

    Returns:
        tuple: (key_bytes, iv_bytes)
    """
    hex_chars = "0123456789ABCDEF"
    timestamp_bytes = utctime.encode('utf-8')
    timestamp_len = len(timestamp_bytes)

    # Generate 32-character key from timestamp
    # Algorithm: key32[i] = hex_chars[(timestamp[i % len] - '0' + i) & 0xF]
    key32 = bytearray(32)
    for i in range(32):
        char_index = i % timestamp_len
        char_val = timestamp_bytes[char_index] + i - 48  # 48 = ord('0')
        key32[i] = ord(hex_chars[char_val & 0xF])

    # Extract key: positions 0-7 and 24-31 (16 chars total)
    key = bytearray(16)
    for j in range(32):
        if j < 8:
            key[j] = key32[j]
        elif (j & 0x7FFFFFF8) == 0x18:  # j in range [24, 31]
            key[j - 16] = key32[j]

    # Extract IV: positions 8-23 (16 chars)
    iv = bytearray(16)
    for k in range(32):
        if 8 <= k <= 23:
            iv[k - 8] = key32[k]

    return bytes(key), bytes(iv)


def decrypt_aes_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Decrypt AES-128-CBC with PKCS7 padding"""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    try:
        return unpad(plaintext, AES.block_size)
    except ValueError:
        return plaintext


def decrypt_response(response_b64: str, mac: str, model: str, key_index: int = 0) -> str:
    """
    Decrypt HTTP response body.

    Key derivation: MAC[4:10] + magic_suffix + model

    Args:
        response_b64: Base64-encoded response body
        mac: Device MAC address
        model: Device model string
        key_index: dword_283648 value (default 0)

    Returns:
        Decrypted response string
    """
    key, iv = derive_key_iv(mac, model, key_index)
    ciphertext = base64.b64decode(response_b64)
    plaintext = decrypt_aes_cbc(ciphertext, key, iv)
    return plaintext.decode('utf-8', errors='replace')


def decrypt_request_param(param_value: str, mac: str, utctime: str, key_index: int = 0) -> str:
    """
    Decrypt request parameter (key or key1).

    Key derivation: MAC[4:10] + magic_suffix + utctime

    Args:
        param_value: URL-encoded, base64-encoded parameter value
        mac: Device MAC address
        utctime: Timestamp from request header
        key_index: dword_283648 value (default 0)

    Returns:
        Decrypted parameter string
    """
    b64_value = unquote(param_value)
    key, iv = derive_key_iv(mac, utctime, key_index)
    ciphertext = base64.b64decode(b64_value)
    plaintext = decrypt_aes_cbc(ciphertext, key, iv)
    return plaintext.decode('utf-8', errors='replace')


def decrypt_dev_param(param_value: str, utctime: str) -> str:
    """
    Decrypt 'dev' request parameter.

    Key derivation uses api_getDevMsg2 algorithm (timestamp-only based).

    Args:
        param_value: URL-encoded, base64-encoded parameter value
        utctime: Timestamp from request header

    Returns:
        Decrypted device info JSON string
    """
    b64_value = unquote(param_value)
    key, iv = derive_key_iv_dev(utctime)
    ciphertext = base64.b64decode(b64_value)
    plaintext = decrypt_aes_cbc(ciphertext, key, iv)
    return plaintext.decode('utf-8', errors='replace')


def parse_http_request(raw: str) -> Optional[HTTPRequest]:
    """Parse raw HTTP request text"""
    lines = raw.strip().split('\n')
    if not lines:
        return None

    # Parse request line
    request_line = lines[0].strip()
    match = re.match(r'^(\w+)\s+(\S+)\s+HTTP/', request_line)
    if not match:
        return None

    method = match.group(1)
    path = match.group(2)

    # Parse headers
    headers = {}
    body_start = 1
    for i, line in enumerate(lines[1:], 1):
        line = line.strip()
        if not line:
            body_start = i + 1
            break
        if ':' in line:
            key, value = line.split(':', 1)
            headers[key.strip().lower()] = value.strip()

    # Parse body
    body = '\n'.join(lines[body_start:]).strip() if body_start < len(lines) else ''

    return HTTPRequest(method=method, path=path, headers=headers, body=body, raw=raw)


def parse_http_response(raw: str) -> Optional[HTTPResponse]:
    """Parse raw HTTP response text"""
    lines = raw.strip().split('\n')
    if not lines:
        return None

    # Parse status line
    status_line = lines[0].strip()
    match = re.match(r'^HTTP/[\d.]+\s+(\d+)\s+(.*)$', status_line)
    if not match:
        return None

    status_code = int(match.group(1))
    status_message = match.group(2)

    # Parse headers
    headers = {}
    body_start = 1
    for i, line in enumerate(lines[1:], 1):
        line = line.strip()
        if not line:
            body_start = i + 1
            break
        if ':' in line:
            key, value = line.split(':', 1)
            headers[key.strip().lower()] = value.strip()

    # Parse body
    body = '\n'.join(lines[body_start:]).strip() if body_start < len(lines) else ''

    return HTTPResponse(status_code=status_code, status_message=status_message,
                       headers=headers, body=body, raw=raw)


def parse_captures(content: str) -> List[HTTPCapture]:
    """Parse file content containing HTTP request/response pairs."""
    captures = []
    current_request = None
    current_response = None
    current_block = []

    lines = content.split('\n')

    for line in lines:
        stripped = line.strip()

        # Check if this starts a new HTTP request
        if re.match(r'^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+', stripped):
            # Save previous capture if exists
            if current_request or current_response:
                captures.append(HTTPCapture(request=current_request, response=current_response))
                current_request = None
                current_response = None

            if current_block:
                current_block = []
            current_block.append(line)

        # Check if this starts an HTTP response
        elif stripped.startswith('HTTP/'):
            if current_block and not current_request:
                current_request = parse_http_request('\n'.join(current_block))
                current_block = []
            current_block.append(line)

        elif current_block or stripped:
            current_block.append(line)

        elif not stripped and current_block:
            first_line = current_block[0].strip() if current_block else ''
            if first_line.startswith('HTTP/'):
                current_response = parse_http_response('\n'.join(current_block))
            elif re.match(r'^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+', first_line):
                current_request = parse_http_request('\n'.join(current_block))
            current_block = []

    # Handle remaining block
    if current_block:
        first_line = current_block[0].strip() if current_block else ''
        if first_line.startswith('HTTP/'):
            current_response = parse_http_response('\n'.join(current_block))
        elif re.match(r'^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+', first_line):
            current_request = parse_http_request('\n'.join(current_block))

    if current_request or current_response:
        captures.append(HTTPCapture(request=current_request, response=current_response))

    return captures


def process_capture(capture: HTTPCapture, verbose: bool = False) -> Dict[str, Any]:
    """Process a single HTTP capture and decrypt its contents"""
    result = {
        'request': None,
        'response': None,
        'decrypted': {},
        'key_derivation': {},
        'errors': []
    }

    if not capture.request:
        result['errors'].append("No request found in capture")
        return result

    req = capture.request
    result['request'] = {
        'method': req.method,
        'path': req.path,
        'headers': req.headers
    }

    # Extract required headers
    mac = req.headers.get('mac', '')
    model = req.headers.get('model', '')
    utctime = req.headers.get('utctime', '')

    if not mac:
        result['errors'].append("Missing 'mac' header")
        return result

    # Store key derivation info
    mac_clean = ''.join(c for c in mac.lower() if c in '0123456789abcdef')
    mac_part = mac_clean[4:10] if len(mac_clean) >= 10 else mac_clean

    if utctime:
        key_material_req = mac_part + "errorstr" + utctime
        md5_req = hashlib.md5(key_material_req.encode()).hexdigest()
        result['key_derivation']['request'] = {
            'mac_part': mac_part,
            'magic': 'errorstr',
            'suffix': utctime,
            'key_material': key_material_req,
            'md5': md5_req,
            'key_iv': md5_req[8:24]
        }

        # Dev parameter key derivation
        key_dev, iv_dev = derive_key_iv_dev(utctime)
        result['key_derivation']['dev'] = {
            'utctime': utctime,
            'key': key_dev.decode('ascii'),
            'iv': iv_dev.decode('ascii')
        }

    if model:
        key_material_resp = mac_part + "errorstr" + model
        md5_resp = hashlib.md5(key_material_resp.encode()).hexdigest()
        result['key_derivation']['response'] = {
            'mac_part': mac_part,
            'magic': 'errorstr',
            'suffix': model,
            'key_material': key_material_resp,
            'md5': md5_resp,
            'key_iv': md5_resp[8:24]
        }

    # Parse request body parameters
    if req.body:
        params = parse_qs(req.body)

        # Decrypt 'key' parameter
        if 'key' in params:
            try:
                key_value = params['key'][0]
                decrypted_key = decrypt_request_param(key_value, mac, utctime)
                result['decrypted']['key'] = decrypted_key
            except Exception as e:
                result['errors'].append(f"Error decrypting 'key': {e}")

        # Decrypt 'key1' parameter
        if 'key1' in params:
            try:
                key1_value = params['key1'][0]
                decrypted_key1 = decrypt_request_param(key1_value, mac, utctime)
                result['decrypted']['key1'] = decrypted_key1
                try:
                    result['decrypted']['key1_json'] = json.loads(decrypted_key1)
                except:
                    pass
            except Exception as e:
                result['errors'].append(f"Error decrypting 'key1': {e}")

        # Decrypt 'dev' parameter (uses different key derivation!)
        if 'dev' in params:
            try:
                dev_value = params['dev'][0]
                decrypted_dev = decrypt_dev_param(dev_value, utctime)
                result['decrypted']['dev'] = decrypted_dev
                try:
                    result['decrypted']['dev_json'] = json.loads(decrypted_dev)
                except:
                    pass
            except Exception as e:
                result['errors'].append(f"Error decrypting 'dev': {e}")

    # Process response
    if capture.response:
        resp = capture.response
        result['response'] = {
            'status_code': resp.status_code,
            'status_message': resp.status_message,
            'headers': resp.headers
        }

        if resp.body and model:
            # Check if response is already cleartext JSON
            try:
                json.loads(resp.body)
                result['decrypted']['response_body'] = resp.body
                result['decrypted']['response_json'] = json.loads(resp.body)
                result['decrypted']['response_encrypted'] = False
            except:
                # Attempt decryption
                try:
                    decrypted_response = decrypt_response(resp.body, mac, model)
                    result['decrypted']['response_body'] = decrypted_response
                    result['decrypted']['response_encrypted'] = True
                    try:
                        result['decrypted']['response_json'] = json.loads(decrypted_response)
                    except:
                        pass
                except Exception as e:
                    result['errors'].append(f"Error decrypting response: {e}")
        elif not model:
            result['errors'].append("Missing 'model' header - cannot decrypt response")

    return result


def format_output(results: List[Dict], output_format: str = 'text', verbose: bool = False) -> str:
    """Format results for output"""
    if output_format == 'json':
        return json.dumps(results, indent=2, ensure_ascii=False)

    # Text format
    output = []
    for i, result in enumerate(results, 1):
        output.append("=" * 70)
        output.append(f"Capture #{i}")
        output.append("=" * 70)

        if result['request']:
            req = result['request']
            output.append(f"\nRequest: {req['method']} {req['path']}")
            output.append(f"MAC: {req['headers'].get('mac', 'N/A')}")
            output.append(f"Model: {req['headers'].get('model', 'N/A')}")
            output.append(f"UTC Time: {req['headers'].get('utctime', 'N/A')}")

        if verbose and result.get('key_derivation'):
            kd = result['key_derivation']
            output.append("\n--- Key Derivation ---")
            if 'request' in kd:
                output.append(f"\n[key/key1 params]")
                output.append(f"  MAC[4:10]: {kd['request']['mac_part']}")
                output.append(f"  Magic: {kd['request']['magic']}")
                output.append(f"  Material: {kd['request']['key_material']}")
                output.append(f"  MD5: {kd['request']['md5']}")
                output.append(f"  Key/IV: {kd['request']['key_iv']}")
            if 'dev' in kd:
                output.append(f"\n[dev param]")
                output.append(f"  UTC Time: {kd['dev']['utctime']}")
                output.append(f"  Key: {kd['dev']['key']}")
                output.append(f"  IV: {kd['dev']['iv']}")
            if 'response' in kd:
                output.append(f"\n[response]")
                output.append(f"  Material: {kd['response']['key_material']}")
                output.append(f"  Key/IV: {kd['response']['key_iv']}")

        if result['response']:
            resp = result['response']
            output.append(f"\nResponse: {resp['status_code']} {resp['status_message']}")

        if result['decrypted']:
            output.append("\n--- Decrypted Data ---")

            if 'key' in result['decrypted']:
                output.append(f"\n[key parameter]")
                output.append(result['decrypted']['key'])

            if 'key1' in result['decrypted']:
                output.append(f"\n[key1 parameter]")
                if 'key1_json' in result['decrypted']:
                    output.append(json.dumps(result['decrypted']['key1_json'], indent=2))
                else:
                    output.append(result['decrypted']['key1'])

            if 'dev' in result['decrypted']:
                output.append(f"\n[dev parameter - Device Info]")
                if 'dev_json' in result['decrypted']:
                    output.append(json.dumps(result['decrypted']['dev_json'], indent=2))
                else:
                    output.append(result['decrypted']['dev'])

            if 'response_body' in result['decrypted']:
                encrypted_str = " (was encrypted)" if result['decrypted'].get('response_encrypted') else " (cleartext)"
                output.append(f"\n[response body{encrypted_str}]")
                if 'response_json' in result['decrypted']:
                    output.append(json.dumps(result['decrypted']['response_json'], indent=2))
                else:
                    output.append(result['decrypted']['response_body'])

        if result['errors']:
            output.append("\n--- Errors ---")
            for error in result['errors']:
                output.append(f"  ! {error}")

        output.append("")

    return '\n'.join(output)


def main():
    parser = argparse.ArgumentParser(
        description='Decrypt SuperBOX App Store HTTP traffic',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python3 superbox_decrypt.py req.txt
    python3 superbox_decrypt.py captures.txt --format json
    python3 superbox_decrypt.py traffic.txt -v --output decrypted.txt

Encryption Methods:
    key/key1: AES-128-CBC with key = MD5(MAC[4:10] + "errorstr" + utctime)[8:24]
    dev:      AES-128-CBC with timestamp-derived key (api_getDevMsg2)
    response: AES-128-CBC with key = MD5(MAC[4:10] + "errorstr" + model)[8:24]
        """
    )

    parser.add_argument('input_file', help='Input file containing HTTP captures')
    parser.add_argument('-o', '--output', help='Output file (default: stdout)')
    parser.add_argument('-f', '--format', choices=['text', 'json'], default='text',
                       help='Output format (default: text)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Show key derivation details')

    args = parser.parse_args()

    try:
        with open(args.input_file, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"Error: File not found: {args.input_file}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        sys.exit(1)

    captures = parse_captures(content)

    if not captures:
        print("No HTTP captures found in input file", file=sys.stderr)
        sys.exit(1)

    if args.verbose:
        print(f"Found {len(captures)} capture(s)", file=sys.stderr)

    results = []
    for capture in captures:
        result = process_capture(capture, verbose=args.verbose)
        results.append(result)

    output = format_output(results, args.format, args.verbose)

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(output)
        if args.verbose:
            print(f"Output written to: {args.output}", file=sys.stderr)
    else:
        print(output)


if __name__ == "__main__":
    main()
