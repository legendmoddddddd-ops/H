#!/usr/bin/env python3
import argparse
import json
import mmap
import os
import shutil
import subprocess
import sys
from datetime import datetime


def debug_print(enabled: bool, message: str) -> None:
    if enabled:
        print(f"[DEBUG] {message}")


def parse_aob_string(aob_string: str):
    """
    Parse an AOB string into (values, masks) byte arrays.

    - Supports tokens like "7A", "??" (full wildcard), and nibble wildcards "A?" or "?F".
    - Returns (values_bytes, masks_bytes) where each mask byte indicates which bits are significant.
    """
    tokens = aob_string.strip().split()
    values = bytearray()
    masks = bytearray()

    for token in tokens:
        t = token.strip()
        if t == "" or t == "*":
            continue
        if t == "??" or t == "?":
            values.append(0x00)
            masks.append(0x00)
            continue

        if len(t) == 2:
            high, low = t[0], t[1]
            high_mask = 0xF0 if high != '?' else 0x00
            low_mask = 0x0F if low != '?' else 0x00

            try:
                high_val = int(high, 16) << 4 if high != '?' else 0x00
                low_val = int(low, 16) if low != '?' else 0x00
            except ValueError:
                raise ValueError(f"Invalid hex token in AOB: {t}")

            values.append(high_val | low_val)
            masks.append(high_mask | low_mask)
        else:
            # Allow tokens like "0x7A" or single byte without space? Enforce two hex chars only.
            t_norm = t.lower().replace("0x", "")
            if len(t_norm) != 2:
                raise ValueError(f"Invalid AOB token length (expected 2 nibbles): {t}")
            values.append(int(t_norm, 16))
            masks.append(0xFF)

    return bytes(values), bytes(masks)


def find_aob_matches(data: memoryview, values: bytes, masks: bytes):
    """
    Find all offsets where the masked AOB pattern matches in data.
    - data: memoryview over the binary data
    - values: bytes of pattern values
    - masks: bytes of bit masks for each pattern byte
    Returns a list of integer offsets.
    Optimized with anchor-based scanning (first significant byte in pattern).
    """
    matches = []

    pattern_len = len(values)
    data_len = len(data)

    if pattern_len == 0 or pattern_len > data_len:
        return matches

    # Determine anchor index as the first byte with any significant bits
    anchor_index = -1
    for i in range(pattern_len):
        if masks[i] != 0x00:
            anchor_index = i
            break

    if anchor_index == -1:
        # Entire pattern is wildcard; match at every possible position
        for i in range(0, data_len - pattern_len + 1):
            matches.append(i)
        return matches

    anchor_mask = masks[anchor_index]
    anchor_value = values[anchor_index]

    i = 0
    last_start = data_len - pattern_len
    while i <= last_start:
        # Quick anchor check
        b = data[i + anchor_index]
        if (b & anchor_mask) == (anchor_value & anchor_mask):
            # Verify full pattern
            matched = True
            di = i
            for j in range(pattern_len):
                if (data[di + j] & masks[j]) != (values[j] & masks[j]):
                    matched = False
                    break
            if matched:
                matches.append(i)
                i += pattern_len  # skip ahead by pattern length
                continue
        i += 1

    return matches


def load_patterns_file(path: str, verbose: bool):
    debug_print(verbose, f"Attempting to load patterns from {path}")
    if not os.path.exists(path):
        debug_print(verbose, f"Pattern file {path} not found. Using defaults.")
        return None
    with open(path, "r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            raise SystemExit(f"Invalid JSON in {path}: {e}")
    debug_print(verbose, f"Loaded patterns file with keys: {list(data.keys())}")
    return data


DEFAULT_PATTERNS = {
    "bgmi": {
        "Root_Detected": "7A 44",
        "Report_Function": "11 49",
    },
    "ff": {
        "Emulator_Bypass_AntiBan": "00 20 07 47",
        "Memory_Scan_Detection": "?? 49 ?? 44",
    },
}


def normalize_and_select_patterns(raw_patterns, target: str):
    """
    Accept either structured {"bgmi": {...}, "ff": {...}} or flat {name: aob}.
    Returns a mapping {pattern_name: aob_string} for the selected target(s).
    """
    if raw_patterns is None:
        raw_patterns = DEFAULT_PATTERNS

    # If flat mapping, assign to both groups when 'all' or keep as is
    if all(isinstance(v, str) for v in raw_patterns.values()):
        # flat
        if target == "bgmi":
            return {f"BGMI::{k}": v for k, v in raw_patterns.items()}
        elif target == "ff":
            return {f"FF::{k}": v for k, v in raw_patterns.items()}
        else:
            return raw_patterns

    # structured
    selected = {}
    def add_group(prefix, group):
        for name, aob in group.items():
            selected[f"{prefix}::{name}"] = aob

    if target == "bgmi":
        add_group("BGMI", raw_patterns.get("bgmi", {}))
    elif target == "ff":
        add_group("FF", raw_patterns.get("ff", {}))
    else:
        add_group("BGMI", raw_patterns.get("bgmi", {}))
        add_group("FF", raw_patterns.get("ff", {}))

    return selected


def is_elf_file(mm: mmap.mmap) -> bool:
    try:
        header = mm[:4]
    except ValueError:
        return False
    return header == b"\x7fELF"


def run_adb_logcat(verbose: bool, max_lines: int = 1000, timeout_sec: int = 10):
    """
    Try to collect non-root logs via adb logcat -d.
    Returns a list of lines, or None if adb is not available or fails.
    """
    try:
        debug_print(verbose, "Running: adb logcat -d")
        proc = subprocess.run(
            ["adb", "logcat", "-d"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_sec,
            check=False,
        )
    except FileNotFoundError:
        debug_print(verbose, "adb not found in PATH; skipping logcat collection.")
        return None
    except subprocess.TimeoutExpired:
        debug_print(verbose, "adb logcat timed out; skipping.")
        return None

    output = proc.stdout.splitlines()
    if not output:
        debug_print(verbose, f"adb logcat returned no lines. stderr: {proc.stderr.strip()}")
        return []

    # Filter for relevant keywords
    keywords = (
        "bgmi", "battlegrounds", "free fire", "ff", "anti", "ban", "cheat", "root", "emulator"
    )
    filtered = [line for line in output if any(k.lower() in line.lower() for k in keywords)]
    if not filtered:
        filtered = output

    if len(filtered) > max_lines:
        filtered = filtered[-max_lines:]
    return filtered


def copy_to_downloads(path: str, verbose: bool) -> None:
    home = os.path.expanduser("~")
    downloads = os.path.join(home, "Downloads")
    debug_print(verbose, f"Checking Downloads directory: {downloads}")
    if os.path.isdir(downloads):
        dest = os.path.join(downloads, os.path.basename(path))
        shutil.copy(path, dest)
        print(f"Also copied to {dest}")
    else:
        print("Downloads folder not found, skipping copy.")


def scan_file_for_patterns(lib_path: str, patterns_map: dict, verbose: bool):
    results = {}
    with open(lib_path, "rb") as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            debug_print(verbose, f"Read {len(mm)} bytes from {lib_path}")
            if not is_elf_file(mm):
                print("Warning: Input does not look like an ELF file (.so). Proceeding anyway.")

            data = memoryview(mm)
            for name, aob in patterns_map.items():
                debug_print(verbose, f"Searching for pattern: {name} ({aob})")
                try:
                    values, masks = parse_aob_string(aob)
                except ValueError as e:
                    print(f"Skipping pattern {name}: {e}")
                    continue
                offsets = find_aob_matches(data, values, masks)
                if offsets:
                    hex_offsets = [hex(o) for o in offsets]
                    results[name] = hex_offsets
                    debug_print(verbose, f"Found offsets for {name}: {hex_offsets}")
                else:
                    debug_print(verbose, f"No offsets found for {name}.")
    return results


def write_outputs(base_out_path: str, lib_path: str, results: dict, write_json: bool, verbose: bool):
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ")
    lib_name = os.path.basename(lib_path)

    # Text output
    text_lines = []
    text_lines.append(f"AOB scan results for {lib_name} @ {timestamp}\n")
    if results:
        for name, offs in results.items():
            text_lines.append(f"{name}:")
            for off in offs:
                text_lines.append(f"  {off}")
            text_lines.append("")
    else:
        text_lines.append("No patterns matched.")

    text_out = base_out_path if base_out_path.endswith(".txt") else f"{base_out_path}.txt"
    with open(text_out, "w", encoding="utf-8") as f:
        f.write("\n".join(text_lines))
    print(f"Output written to {text_out}")

    # JSON output
    if write_json:
        json_out = base_out_path.replace(".txt", "") + ".json"
        payload = {
            "library": lib_name,
            "timestamp": timestamp,
            "results": results,
        }
        with open(json_out, "w", encoding="utf-8") as jf:
            json.dump(payload, jf, indent=2)
        print(f"JSON output written to {json_out}")
        return text_out, json_out

    return text_out, None


def main():
    parser = argparse.ArgumentParser(
        description="Fast AOB scanner with wildcard support for FF/BGMI libraries",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--lib", required=True, help="Path to target .so library")
    parser.add_argument(
        "--target",
        required=True,
        choices=["ff", "bgmi", "all"],
        help="Select which pattern group to use",
    )
    parser.add_argument(
        "--patterns",
        default=os.path.join(os.path.dirname(__file__), "patterns.json"),
        help="Path to patterns.json (structured or flat)",
    )
    parser.add_argument("--out", default="output", help="Output file path or prefix (without extension)")
    parser.add_argument("--json", action="store_true", help="Also write JSON results")
    parser.add_argument("--copy-downloads", action="store_true", help="Copy outputs to ~/Downloads if present")
    parser.add_argument("--adb-log", action="store_true", help="Attempt to capture non-root adb logcat for context")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose debug output")

    args = parser.parse_args()

    lib_path = args.lib
    if not os.path.exists(lib_path):
        print(f"File not found: {lib_path}")
        sys.exit(1)

    debug_print(args.verbose, f"Processing library: {lib_path}")

    raw_patterns = load_patterns_file(args.patterns, args.verbose)

    # If no external patterns, persist defaults for convenience
    if raw_patterns is None:
        try:
            with open(args.patterns, "w", encoding="utf-8") as pf:
                json.dump(DEFAULT_PATTERNS, pf, indent=2)
            debug_print(args.verbose, f"Saved default patterns to {args.patterns}")
        except OSError:
            debug_print(args.verbose, f"Could not save default patterns to {args.patterns}")

    patterns_map = normalize_and_select_patterns(raw_patterns, args.target)

    if not patterns_map:
        print("No patterns available to scan. Check your patterns.json or defaults.")
        sys.exit(1)

    results = scan_file_for_patterns(lib_path, patterns_map, args.verbose)

    text_out, json_out = write_outputs(args.out, lib_path, results, args.json, args.verbose)

    if args.copy_downloads:
        copy_to_downloads(text_out, args.verbose)
        if json_out:
            copy_to_downloads(json_out, args.verbose)

    if args.adb_log:
        lines = run_adb_logcat(args.verbose)
        if lines is not None:
            log_out = args.out.replace(".txt", "") + "_logcat.txt"
            with open(log_out, "w", encoding="utf-8") as lf:
                lf.write("\n".join(lines))
            print(f"ADB logcat written to {log_out}")
            if args.copy_downloads:
                copy_to_downloads(log_out, args.verbose)


if __name__ == "__main__":
    main()

