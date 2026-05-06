#!/usr/bin/env python3

import subprocess
import json
import re
import yaml
from collections import defaultdict, Counter
import sys
import tempfile
import concurrent.futures
from pathlib import Path
import random
import argparse

def analyze_file_structure(lines, sample_size=1000):
    """Quick structure analysis for format discovery."""
    patterns = {
        'separators': Counter(),
        'prefixes': Counter(),
        'lengths': Counter(),
        'hex_patterns': Counter()
    }

    sample = lines[:sample_size]
    for line in sample:
        line = line.strip()
        if not line:
            continue

        # Separators
        patterns['separators']['colon'] += line.count(':')
        patterns['separators']['pipe'] += line.count('|')
        patterns['separators']['semicolon'] += line.count(';')

        # Common hash prefixes
        for prefix in ['{SHA}', '{SSHA}', '{MD5}', '$1$', '$2a$', '$2y$', '$6$', '$P$', '$S$']:
            if prefix in line:
                patterns['prefixes'][prefix] += 1

        # Hex pattern lengths (for quick hash type guessing)
        hex_matches = re.findall(r'[a-fA-F0-9]+', line)
        for match in hex_matches:
            if len(match) >= 16:  # Only count longer hex strings
                patterns['hex_patterns'][len(match)] += 1

    return patterns

def extract_with_patterns(lines, sample_size=100):
    """Try multiple extraction patterns and rank by success."""

    extraction_patterns = [
        # (name, regex, extract_func, description)
        ('windows_sam', r'^([^:]+):(\d+):([A-F0-9]{32}):([A-F0-9]{32}):',
         lambda m: (m.group(1), m.group(4) if m.group(4) != 'AAD3B435B51404EEAAD3B435B51404EE' else m.group(3)),
         'Windows SAM format'),

        ('ldap_ssha', r'^([^:]+):\{SSHA\}([A-Za-z0-9+/=]+)',
         lambda m: (m.group(1), f"{{SSHA}}{m.group(2)}"),
         'LDAP SSHA'),

        ('ldap_sha', r'^([^:]+):\{SHA\}([A-Za-z0-9+/=]+)',
         lambda m: (m.group(1), f"{{SHA}}{m.group(2)}"),
         'LDAP SHA'),

        ('unix_md5crypt', r'^([^:]+):(\$1\$[^:]+):',
         lambda m: (m.group(1), m.group(2)),
         'Unix md5crypt'),

        ('unix_sha512crypt', r'^([^:]+):(\$6\$[^:]+):',
         lambda m: (m.group(1), m.group(2)),
         'Unix SHA512crypt'),

        ('unix_bcrypt', r'^([^:]+):(\$2[ayb]?\$[^:]+):',
         lambda m: (m.group(1), m.group(2)),
         'Unix bcrypt'),

        ('des_crypt', r'^([^:]+):([a-zA-Z0-9./]{13}):',
         lambda m: (m.group(1), m.group(2)),
         'DES crypt'),

        ('wordpress', r'^([^:]+):(\$P\$[./0-9A-Za-z]{31})',
         lambda m: (m.group(1), m.group(2)),
         'WordPress phpass'),

        ('simple_hex32', r'^([^:]+):([a-fA-F0-9]{32})$',
         lambda m: (m.group(1), m.group(2)),
         'Simple 32-char hex'),

        ('simple_hex40', r'^([^:]+):([a-fA-F0-9]{40})$',
         lambda m: (m.group(1), m.group(2)),
         'Simple 40-char hex'),

        ('simple_hex64', r'^([^:]+):([a-fA-F0-9]{64})$',
         lambda m: (m.group(1), m.group(2)),
         'Simple 64-char hex'),

        ('colon_generic', r'^([^:]+):([^:]+)$',
         lambda m: (m.group(1), m.group(2)),
         'Generic colon-separated'),
    ]

    # Take a reasonable subset to work with, then sample from that
    work_lines = lines[:min(10000, len(lines))]
    actual_sample_size = min(sample_size, len(work_lines))
    sample_lines = random.sample(work_lines, actual_sample_size)
    results = {}

    for name, pattern, extract_func, description in extraction_patterns:
        matches = []
        for line in sample_lines:
            line = line.strip()
            match = re.match(pattern, line)
            if match:
                try:
                    username, hash_val = extract_func(match)
                    matches.append((username, hash_val, line))
                except:
                    continue

        if matches:
            results[name] = {
                'description': description,
                'matches': len(matches),
                'coverage': len(matches) / len(sample_lines),
                'examples': matches[:5],
                'unique_hashes': len(set(m[1] for m in matches))
            }

    return sorted(results.items(), key=lambda x: x[1]['coverage'], reverse=True)

def process_hashes_batch(hash_list, hash_id_binary, context_info=None):
    """Process hashes in batch mode for speed with context awareness."""
    if not hash_list:
        return {}

    try:
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            for hash_val in hash_list:
                f.write(f"{hash_val}\n")
            temp_file = f.name

        result = subprocess.run(
            [hash_id_binary, '--file', temp_file, '--json'],
            capture_output=True,
            text=True,
            timeout=120
        )

        Path(temp_file).unlink()

        if result.returncode == 0:
            batch_result = json.loads(result.stdout)
            results = batch_result.get("results", [])

            # Apply context-aware corrections
            if context_info:
                results = apply_context_corrections(results, context_info)

            return results
        else:
            return []

    except Exception as e:
        print(f"Error in batch processing: {e}")
        return []

def apply_context_corrections(results, context_info):
    """Apply context-aware hash identification corrections."""
    corrected_results = []

    for result in results:
        if not result.get('detected_types'):
            corrected_results.append(result)
            continue

        hash_val = result['hash']
        detected_types = result['detected_types']

        # Get context for this specific hash
        hash_context = context_info.get(hash_val, {})
        source_pattern = hash_context.get('source_pattern', 'unknown')

        # Context-based corrections
        if source_pattern == 'windows_sam' and len(hash_val) == 32:
            # 32-char hex from Windows SAM = NTLM, not SHAKE128/MD5
            corrected_types = []
            for dtype in detected_types:
                if dtype['name'] in ['SHAKE128', 'MD5', 'MD4', 'RIPEMD128']:
                    # Replace with NTLM
                    if dtype['name'] == 'SHAKE128':  # Most likely to be wrong
                        corrected_types.append({
                            'name': 'NTLM',
                            'hashcat_mode': 1000,
                            'john_format': 'NT',
                            'confidence': 0.95,  # High confidence due to context
                            'category': 'Basic',
                            'description': 'NTLM hash (Windows)',
                            'salt_detected': False,
                            'pattern_matched': 'context_corrected_ntlm'
                        })
                    else:
                        # Lower the confidence of other 32-char matches
                        dtype = dtype.copy()
                        dtype['confidence'] = dtype['confidence'] * 0.3
                        corrected_types.append(dtype)
                else:
                    corrected_types.append(dtype)

            # Sort by confidence again
            corrected_types.sort(key=lambda x: x['confidence'], reverse=True)
            result['detected_types'] = corrected_types

        elif source_pattern == 'ldap_ssha':
            # LDAP SSHA should be mode 111, high confidence
            for dtype in detected_types:
                if 'SSHA' in dtype['name']:
                    dtype['confidence'] = 0.98

        elif source_pattern == 'unix_md5crypt':
            # $1$ format should be md5crypt mode 500
            for dtype in detected_types:
                if 'md5crypt' in dtype['name']:
                    dtype['confidence'] = 0.98

        elif source_pattern == 'des_crypt' and len(hash_val) == 13:
            # 13-char should be DES crypt mode 1500
            for dtype in detected_types:
                if 'DES' in dtype['name'] or 'crypt' in dtype['name']:
                    dtype['confidence'] = 0.95

        corrected_results.append(result)

    return corrected_results

def extract_all_hashes(lines, extraction_method):
    """Extract all hashes using the chosen method."""
    name, pattern, extract_func = extraction_method

    hash_to_users = defaultdict(list)

    for line_num, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue

        match = re.match(pattern, line)
        if match:
            try:
                username, hash_val = extract_func(match)
                if hash_val and hash_val not in ['AAD3B435B51404EEAAD3B435B51404EE', '']:
                    hash_to_users[hash_val].append((username, line_num))
            except:
                continue

    return hash_to_users

def write_hashcat_files(categories, output_dir):
    """Generate hashcat-ready files organized by mode."""
    output_dir = Path(output_dir)
    output_dir.mkdir(exist_ok=True)

    mode_data = defaultdict(list)

    for category, hashes in categories.items():
        for entry in hashes:
            mode = entry.get('mode', 'unknown')
            username = entry['username']
            hash_val = entry['hash']

            # Format based on hashcat requirements for each mode
            if mode in [111, 101]:  # LDAP formats
                line = hash_val  # Just the hash with {SSHA} prefix
            elif mode in [500, 1500, 3200]:  # Unix crypt formats
                line = hash_val  # Just the hash
            elif mode == 1000:  # NTLM
                line = hash_val  # Just the hash
            else:
                line = f"{username}:{hash_val}"  # Default format

            mode_data[mode].append(line)

    # Write files
    files_written = []
    for mode, lines in mode_data.items():
        if mode != 'unknown':
            filename = f"mode_{mode}.txt"
            filepath = output_dir / filename

            with open(filepath, 'w') as f:
                f.write('\n'.join(sorted(set(lines))))  # Remove duplicates

            files_written.append((filepath, len(set(lines))))

    return files_written

def main():
    parser = argparse.ArgumentParser(description='Contest Hash Analyzer - All-in-one tool')
    parser.add_argument('contest_file', help='Contest hash dump file')
    parser.add_argument('--hash-id-binary', default='./target/release/hash-id',
                       help='Path to hash-id binary')

    # Modes
    parser.add_argument('--explore', action='store_true',
                       help='Format discovery mode (fast, for unknown formats)')
    parser.add_argument('--analyze', action='store_true',
                       help='Full analysis mode (slower, complete categorization)')

    # Options
    parser.add_argument('--sample-size', type=int, default=200,
                       help='Sample size for exploration')
    parser.add_argument('--parallel', type=int, default=4,
                       help='Parallel processing chunks')
    parser.add_argument('--output-dir', default='./hashcat_modes',
                       help='Directory for hashcat files')
    parser.add_argument('--hashcat-files', action='store_true',
                       help='Generate hashcat-ready mode files')
    parser.add_argument('--json', action='store_true',
                       help='Output results as JSON')

    args = parser.parse_args()

    # Default to explore mode if nothing specified
    if not args.explore and not args.analyze:
        args.explore = True

    print(f"Contest Hash Analyzer")
    print(f"File: {args.contest_file}")
    print(f"Mode: {'Explore' if args.explore else 'Analyze'}")
    print("=" * 50)

    # Read file
    with open(args.contest_file, 'r', encoding='utf-8', errors='ignore') as f:
        lines = [line.strip() for line in f if line.strip()]

    print(f"Total lines: {len(lines):,}")

    if args.explore:
        # EXPLORATION MODE - Fast format discovery
        print(f"\n🔍 FORMAT DISCOVERY (sample: {args.sample_size})")
        print("-" * 30)

        # Structure analysis
        structure = analyze_file_structure(lines, args.sample_size)

        print("File structure:")
        print(f"  Most common separators: {structure['separators'].most_common(3)}")
        print(f"  Hash prefixes found: {structure['prefixes'].most_common()}")
        print(f"  Hex string lengths: {structure['hex_patterns'].most_common(5)}")

        # Pattern extraction
        print(f"\nTesting extraction patterns...")
        extraction_results = extract_with_patterns(lines, args.sample_size)

        print(f"\nTop patterns by coverage:")
        for name, data in extraction_results[:5]:
            print(f"✓ {data['description']}: {data['matches']}/{args.sample_size} ({data['coverage']*100:.1f}%)")
            for username, hash_val, _ in data['examples'][:2]:
                print(f"    {username} → {hash_val[:30]}...")

        if extraction_results:
            best_pattern = extraction_results[0]
            print(f"\n🎯 RECOMMENDED: Use '{best_pattern[1]['description']}' pattern")
            print(f"   Coverage: {best_pattern[1]['coverage']*100:.1f}%")
            print(f"   Rerun with --analyze for full processing")

    else:
        # ANALYSIS MODE - Full processing
        print(f"\n🔬 FULL ANALYSIS")
        print("-" * 30)

        # Try ALL extraction patterns, not just the best one
        extraction_patterns = [
            ('windows_sam', r'^([^:]+):(\d+):([A-F0-9]{32}):([A-F0-9]{32}):',
             lambda m: (m.group(1), m.group(4) if m.group(4) != 'AAD3B435B51404EEAAD3B435B51404EE' else m.group(3))),
            ('ldap_ssha', r'^([^:]+):\{SSHA\}([A-Za-z0-9+/=]+)',
             lambda m: (m.group(1), f"{{SSHA}}{m.group(2)}")),
            ('ldap_sha', r'^([^:]+):\{SHA\}([A-Za-z0-9+/=]+)',
             lambda m: (m.group(1), f"{{SHA}}{m.group(2)}")),
            ('unix_md5crypt', r'^([^:]+):(\$1\$[^:]+):',
             lambda m: (m.group(1), m.group(2))),
            ('unix_sha512crypt', r'^([^:]+):(\$6\$[^:]+):',
             lambda m: (m.group(1), m.group(2))),
            ('unix_bcrypt', r'^([^:]+):(\$2[ayb]?\$[^:]+):',
             lambda m: (m.group(1), m.group(2))),
            ('des_crypt', r'^([^:]+):([a-zA-Z0-9./]{13}):',
             lambda m: (m.group(1), m.group(2))),
            ('wordpress', r'^([^:]+):(\$P\$[./0-9A-Za-z]{31})',
             lambda m: (m.group(1), m.group(2))),
        ]

        # Extract hashes using ALL patterns and combine
        print("Extracting hashes using ALL patterns...")
        all_hash_to_users = defaultdict(list)
        hash_to_context = {}  # Track which pattern each hash came from
        pattern_stats = {}

        for pattern_name, pattern_regex, extract_func in extraction_patterns:
            pattern_hashes = extract_all_hashes(lines, (pattern_name, pattern_regex, extract_func))
            pattern_stats[pattern_name] = len(pattern_hashes)

            for hash_val, users_list in pattern_hashes.items():
                all_hash_to_users[hash_val].extend(users_list)
                # Track the source pattern for context-aware identification
                if hash_val not in hash_to_context:
                    hash_to_context[hash_val] = pattern_name

        # Show extraction stats
        print("Pattern extraction results:")
        for pattern_name, count in pattern_stats.items():
            if count > 0:
                print(f"  {pattern_name}: {count:,} hashes")

        hash_to_users = dict(all_hash_to_users)

        unique_hashes = list(hash_to_users.keys())
        total_extractions = sum(len(users) for users in hash_to_users.values())

        print(f"Extracted: {total_extractions:,} total, {len(unique_hashes):,} unique")

        # Process in parallel chunks with context awareness
        print("Identifying hash types with context corrections...")
        chunk_size = max(1, len(unique_hashes) // args.parallel)
        chunks = [unique_hashes[i:i + chunk_size] for i in range(0, len(unique_hashes), chunk_size)]

        hash_results = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.parallel) as executor:
            # Create context info for each chunk
            futures = {}
            for i, chunk in enumerate(chunks):
                # Create context info mapping for this chunk
                chunk_context = {}
                for hash_val in chunk:
                    source_pattern = hash_to_context.get(hash_val, 'unknown')
                    chunk_context[hash_val] = {'source_pattern': source_pattern}

                future = executor.submit(process_hashes_batch, chunk, args.hash_id_binary, chunk_context)
                futures[future] = i

            for future in concurrent.futures.as_completed(futures):
                chunk_idx = futures[future]
                results = future.result()
                print(f"Processed chunk {chunk_idx + 1}/{len(chunks)}")

                for i, result in enumerate(results):
                    if chunk_idx < len(chunks) and i < len(chunks[chunk_idx]):
                        hash_val = chunks[chunk_idx][i]
                        hash_results[hash_val] = result

        # Aggregate results
        categories = defaultdict(list)
        total_identified = 0

        for hash_val, users_info in hash_to_users.items():
            result = hash_results.get(hash_val)

            if result and result.get('detected_types'):
                total_identified += len(users_info)
                best_match = result['detected_types'][0]
                category = best_match['category']

                for username, line_num in users_info:
                    categories[category].append({
                        'line': line_num,
                        'username': username,
                        'hash': hash_val,
                        'type': best_match['name'],
                        'mode': best_match.get('hashcat_mode', 'unknown'),
                        'confidence': best_match['confidence']
                    })

        identification_rate = (total_identified / total_extractions) * 100 if total_extractions > 0 else 0

        # Results summary
        print(f"\n📊 RESULTS")
        print(f"Identification rate: {identification_rate:.1f}% ({total_identified:,}/{total_extractions:,})")

        if args.json:
            result = {
                'file': args.contest_file,
                'total_lines': len(lines),
                'extraction_pattern': best_pattern_data['description'],
                'total_extracted': total_extractions,
                'unique_hashes': len(unique_hashes),
                'total_identified': total_identified,
                'identification_rate': identification_rate,
                'categories': {cat: hashes for cat, hashes in categories.items()}
            }
            print(json.dumps(result, indent=2))
        else:
            for category, hashes in sorted(categories.items()):
                print(f"\n{category}: {len(hashes):,} hashes")

                type_counts = Counter(h['type'] for h in hashes)
                for hash_type, count in type_counts.most_common(5):
                    mode = next(h['mode'] for h in hashes if h['type'] == hash_type)
                    print(f"  {hash_type}: {count:,} (mode {mode})")

        # Generate hashcat files
        if args.hashcat_files and categories:
            print(f"\n💾 GENERATING HASHCAT FILES")
            files_written = write_hashcat_files(categories, args.output_dir)

            print(f"Wrote {len(files_written)} files to {args.output_dir}:")
            for filepath, count in files_written:
                print(f"  {filepath.name}: {count:,} hashes")

            print(f"\nReady for cracking! Example:")
            if files_written:
                example_file = files_written[0][0]
                mode = example_file.stem.split('_')[1]
                print(f"  hashcat -m {mode} {example_file} wordlist.txt")

if __name__ == '__main__':
    main()