"""Per-version vtable slot anchor verifier.

Reads a CSV of hand-verified (class, method, expected_slot) anchors for a
runtime version, then asserts the generated vtable_structs place those
methods at the expected slot index.  Designed to catch silent drift
between CommonLib header layouts and actual binary layouts -- e.g. the
+2 Actor vtable insertion in Skyrim VR or the +1 insertion in F4 VR that
the shared-header parse cannot otherwise see.

CSV format (header row required):

    class,method,slot,note
    PlayerCharacter,Update,0xAD,SE/AE flat layout
    Actor,UpdateNonRenderSafe,0xB1,
    Actor,KillDying,0xAA,inherited base impl

- ``class`` may be the leaf name (``PlayerCharacter``) or fully qualified
  (``RE::PlayerCharacter``).  The verifier tries both forms.
- ``method`` is the leaf method name as it appears in the vtable struct
  (overload aliases ``__overload_N`` are already stripped on emission --
  if a class has two slots with the same leaf name, only the first match
  is checked, so pick anchors with unique names).
- ``slot`` is the 0-based slot index (decimal or ``0x``-prefixed hex).
  Stored as bytes internally (slot * 8) -- verifier compares offset / 8.
- ``note`` is free-form, ignored.

Usage from a build script::

    from anchor_verifier import verify_or_exit
    verify_or_exit('svr', vtable_structs,
                   os.path.join(SCRIPT_DIR, 'anchors', 'svr.csv'))
"""
import csv
import os
import sys


def _candidate_keys(class_name):
    """Yield possible vtable_structs keys for a user-supplied class name."""
    yield class_name
    if '::' not in class_name:
        yield 'RE::' + class_name
    elif class_name.startswith('RE::'):
        yield class_name[len('RE::'):]


def _parse_slot(text):
    text = text.strip()
    if not text:
        return None
    try:
        if text.lower().startswith('0x'):
            return int(text, 16)
        return int(text)
    except ValueError:
        return None


def _read_anchors(path):
    """Yield (class, method, expected_slot_or_None, parse_error_or_note)."""
    with open(path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for lineno, row in enumerate(reader, start=2):
            cls = (row.get('class') or '').strip()
            method = (row.get('method') or '').strip()
            slot_raw = (row.get('slot') or '').strip()
            note = (row.get('note') or '').strip()
            if not cls or not method or not slot_raw:
                # Skip blank / comment-only rows silently.
                if cls or method or slot_raw:
                    yield cls, method, None, 'incomplete row at line {}'.format(lineno)
                continue
            slot = _parse_slot(slot_raw)
            if slot is None:
                yield cls, method, None, 'unparseable slot {!r} at line {}'.format(slot_raw, lineno)
                continue
            yield cls, method, slot, note


def verify_anchors(version, vtable_structs, anchors_csv):
    """Check vtable_structs against an anchors CSV for a given version.

    Returns a list of human-readable mismatch strings (empty on success).
    A missing or empty CSV is itself reported as a single mismatch so the
    caller can decide whether to treat it as fatal.
    """
    if not os.path.isfile(anchors_csv):
        return ['[{}] anchors file missing: {}'.format(version, anchors_csv)]

    mismatches = []
    anchor_count = 0

    for cls, method, expected_slot, note in _read_anchors(anchors_csv):
        if expected_slot is None:
            mismatches.append('[{}] {}::{}: {}'.format(version, cls or '?', method or '?', note))
            continue
        anchor_count += 1

        struct = None
        for key in _candidate_keys(cls):
            if key in vtable_structs:
                struct = vtable_structs[key]
                break
        if struct is None:
            mismatches.append('[{}] {}::{}: class not found in vtable_structs'.format(
                version, cls, method))
            continue

        match_off = None
        for slot in struct.get('slots', []):
            # slots is list of (offset, name, ret, params)
            off, name = slot[0], slot[1]
            if name == method:
                match_off = off
                break
        if match_off is None:
            mismatches.append('[{}] {}::{}: method name not found in {} vtable struct'.format(
                version, cls, method, cls))
            continue

        actual_slot = match_off // 8
        if actual_slot != expected_slot:
            mismatches.append(
                '[{}] {}::{}: expected slot 0x{:X}, got 0x{:X} (byte offset 0x{:X}){}'
                .format(version, cls, method, expected_slot, actual_slot, match_off,
                        '  -- ' + note if note else ''))

    if anchor_count == 0 and not mismatches:
        mismatches.append('[{}] anchors CSV has no usable rows: {}'.format(version, anchors_csv))

    return mismatches


def verify_or_exit(version, vtable_structs, anchors_csv):
    """Verify and ``sys.exit(1)`` on any mismatch.  Prints success line otherwise."""
    mismatches = verify_anchors(version, vtable_structs, anchors_csv)
    if mismatches:
        print('\nERROR: vtable anchor verification failed for {} ({} issue{}):'
              .format(version, len(mismatches), '' if len(mismatches) == 1 else 's'))
        for m in mismatches:
            print('  ' + m)
        print('\nFix one of: (a) the CommonLib header layout for this version, '
              '(b) the anchor table at {}, '.format(anchors_csv) +
              '(c) skip vtable emission for this version if the headers cannot match the binary.')
        sys.exit(1)
    print('  anchor check OK ({})'.format(version))
