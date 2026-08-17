#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Hero Siege Standalone Item Scanner
=================================
Standalone rewrite: no wrapper chain, no execution of older masters.
Current scope: authoritative Unique Sword native function + generic assignment protocol extraction.
The architecture is intentionally modular so later versions can add every DefineItem* function.
"""
from pathlib import Path
import argparse, csv, hashlib, json, math, shutil, struct, time, zipfile
from collections import Counter, defaultdict

MASTER_VERSION = "permanent-master-v12-standalone"

# Current authoritative anchor. Later scanners can populate this registry automatically.
FUNCTIONS = {
    "DefineItemUniqueWeaponsSword": {
        "begin": 0x05856C00,
        "end":   0x0588E599,
        "prep":  0x0C54E830,
        "primary_segments": list(range(2, 71, 2)),
        "known_segments": {8: "Godfather", 20: "Thor", 40: "Genji"},
    }
}

TARGET = 0x0C579810
FIELD_SETTER = 0x0C566890
ITEM_HELPER = 0x058A48A0
VALUE_HELPER = 0x56710
CLEANUP = 0x56560

KNOWN_EXPECTED = {
    "Godfather": {"target_subsequence": [13315, 1424, 11], "value_0x100": 1855},
    "Thor":      {"target_subsequence": [8860, 1424, 83],  "value_0x100": 16155},
    "Genji":     {"target_subsequence": [8866, 1424, 78],  "value_0x100": 29455},
}

REG = ["RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI"]
XREG = ["R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"]


def u16(b, o): return struct.unpack_from("<H", b, o)[0]
def u32(b, o): return struct.unpack_from("<I", b, o)[0]
def u64(b, o): return struct.unpack_from("<Q", b, o)[0]
def s32(b, o): return struct.unpack_from("<i", b, o)[0]


def finite_double(q):
    try:
        x = struct.unpack("<d", struct.pack("<Q", q))[0]
        if not math.isfinite(x) or abs(x) > 1e12:
            return None
        return int(round(x)) if abs(x - round(x)) < 1e-10 else x
    except Exception:
        return None


def sha256(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def desktop():
    for p in (Path.home() / "Desktop", Path.home() / "OneDrive" / "Desktop"):
        if p.exists():
            return p
    return Path.cwd()


def choose_exe(root):
    for p in (
        root / "Hero_Siege.exe",
        root / "bin" / "Hero_Siege.exe",
        root / "Hero Siege.exe",
        root / "bin" / "Hero Siege.exe",
    ):
        if p.exists():
            return p
    xs = list(root.rglob("Hero_Siege.exe"))
    if not xs:
        raise SystemExit("Hero_Siege.exe not found")
    return xs[0]


def save_json(path, obj):
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding="utf-8")


class PE:
    def __init__(self, path):
        self.path = path
        self.data = path.read_bytes()
        self.sections = []
        self._parse()

    def _parse(self):
        d = self.data
        pe = u32(d, 0x3C)
        coff = pe + 4
        nsec = u16(d, coff + 2)
        optsz = u16(d, coff + 16)
        opt = coff + 20
        self.image_base = u64(d, opt + 24)
        sec = opt + optsz
        for i in range(nsec):
            o = sec + i * 40
            self.sections.append({
                "name": d[o:o+8].split(b"\0", 1)[0].decode("ascii", "ignore"),
                "virtual_size": u32(d, o + 8),
                "rva": u32(d, o + 12),
                "raw_size": u32(d, o + 16),
                "raw_ptr": u32(d, o + 20),
                "executable": bool(u32(d, o + 36) & 0x20000000),
            })

    def rva_to_off(self, rva):
        for s in self.sections:
            span = max(s["virtual_size"], s["raw_size"])
            if s["rva"] <= rva < s["rva"] + span:
                delta = rva - s["rva"]
                if delta < s["raw_size"]:
                    return s["raw_ptr"] + delta
        return None

    def get(self, begin, end):
        off = self.rva_to_off(begin)
        if off is None:
            return b""
        return self.data[off:off + (end - begin)]

    def slot(self, rva, n=16):
        off = self.rva_to_off(rva)
        if off is None:
            return None
        b = self.data[off:off+n]
        return {
            "rva": rva,
            "rva_hex": f"0x{rva:X}",
            "raw": b.hex(" "),
            "u32": u32(b, 0) if len(b) >= 4 else None,
            "u64": u64(b, 0) if len(b) >= 8 else None,
        }


def direct_calls(pe, begin, end):
    b = pe.get(begin, end)
    out = []
    i = 0
    while i + 5 <= len(b):
        if b[i] == 0xE8:
            r = begin + i
            out.append({"rva": r, "target": (r + 5 + s32(b, i + 1)) & 0xFFFFFFFF})
            i += 5
        else:
            i += 1
    return out


def build_segments(pe, func):
    calls = direct_calls(pe, func["begin"], func["end"])
    preps = [c["rva"] for c in calls if c["target"] == func["prep"]]
    segments = []
    for i, a in enumerate(preps):
        z = preps[i + 1] if i + 1 < len(preps) else func["end"]
        segments.append({"segment_index": i, "begin": a, "end": z, "size": z - a})
    return calls, preps, segments


def scan_events(pe, begin, end):
    """Small exact-pattern decoder for only the instructions needed by this scanner."""
    b = pe.get(begin, end)
    events = []
    imm64 = {}
    i = 0
    while i < len(b):
        r = begin + i
        if i + 5 <= len(b) and b[i] == 0xE8:
            events.append({"rva": r, "kind": "CALL", "target": (r + 5 + s32(b, i + 1)) & 0xFFFFFFFF})
            i += 5
            continue

        if i + 10 <= len(b) and b[i] == 0x48 and 0xB8 <= b[i+1] <= 0xBF:
            reg = REG[b[i+1] - 0xB8]
            q = u64(b, i + 2)
            rec = {"rva": r, "kind": "IMM64", "dst": reg, "qword": q, "double": finite_double(q)}
            events.append(rec)
            imm64[reg] = rec
            i += 10
            continue

        if i + 7 <= len(b) and b[i] == 0x48 and b[i+1] in (0x89, 0x8B, 0x8D):
            m = b[i+2]
            mod, rr, rm = (m >> 6) & 3, (m >> 3) & 7, m & 7
            if mod == 2 and rm == 5:
                reg = REG[rr]
                disp = s32(b, i + 3)
                if b[i+1] == 0x89:
                    rec = {"rva": r, "kind": "STORE_RBP", "disp": disp, "src": reg}
                    prod = imm64.get(reg)
                    if prod and 0 <= r - prod["rva"] <= 0x60:
                        rec.update({"source_rva": prod["rva"], "qword": prod["qword"], "double": prod["double"]})
                    events.append(rec)
                elif b[i+1] == 0x8B:
                    events.append({"rva": r, "kind": "LOAD_RBP", "disp": disp, "dst": reg})
                else:
                    events.append({"rva": r, "kind": "LEA_RBP", "disp": disp, "dst": reg})
                i += 7
                continue

        # REX + MOV register-register / LEA or LOAD RBP used for ABI tracing.
        if i + 3 <= len(b) and 0x40 <= b[i] <= 0x4F and b[i+1] in (0x89, 0x8B, 0x8D):
            rex, op, m = b[i], b[i+1], b[i+2]
            mod, rr, rm = (m >> 6) & 3, (m >> 3) & 7, m & 7
            reg = (XREG if rex & 4 else REG)[rr]
            rmreg = (XREG if rex & 1 else REG)[rm]
            if mod == 3 and op in (0x89, 0x8B):
                dst, src = (rmreg, reg) if op == 0x89 else (reg, rmreg)
                events.append({"rva": r, "kind": "MOV_REG", "dst": dst, "src": src})
                i += 3
                continue
            if mod == 2 and rm == 5 and i + 7 <= len(b):
                events.append({"rva": r, "kind": "LOAD_RBP" if op == 0x8B else "LEA_RBP", "dst": reg, "disp": s32(b, i+3)})
                i += 7
                continue

        i += 1
    return events


def nearest_numeric_store(events, call_rva, disp, lookback=0x180):
    xs = [e for e in events if e["kind"] == "STORE_RBP" and e.get("disp") == disp and e.get("double") is not None and e["rva"] < call_rva and call_rva - e["rva"] <= lookback]
    return xs[-1] if xs else None


def last_assignment(events, reg, before_rva):
    xs = [e for e in events if e.get("dst") == reg and e["rva"] < before_rva]
    return xs[-1] if xs else None


def trace_call_args(events, call_rva):
    return {reg: last_assignment(events, reg, call_rva) for reg in ("RCX", "RDX", "R8", "R9")}


def find_rip_selector_loads(pe, begin, call_rva, window=0x120):
    a = max(begin, call_rva - window)
    b = pe.get(a, call_rva)
    out = []
    for i in range(0, max(0, len(b) - 6)):
        if b[i:i+2] == b"\x8B\x15":  # MOV EDX,[RIP+disp32]
            r = a + i
            t = (r + 6 + s32(b, i + 2)) & 0xFFFFFFFF
            out.append({"rva": r, "rva_hex": f"0x{r:X}", "slot_rva": t, "slot_rva_hex": f"0x{t:X}", "slot": pe.slot(t)})
    return out


def find_r8d_imm(pe, begin, call_rva, window=0x80):
    a = max(begin, call_rva - window)
    b = pe.get(a, call_rva)
    hits = []
    for i in range(0, max(0, len(b) - 6)):
        if b[i:i+2] == b"\x41\xB8":
            hits.append({"rva": a+i, "rva_hex": f"0x{a+i:X}", "imm": u32(b, i+2), "imm_hex": f"0x{u32(b, i+2):X}"})
    return hits[-1] if hits else None


def find_virtual_source(pe, begin, setter_call_rva, window=0x180):
    """Find the nearest CALL [RAX+8] whose return is moved into RDI."""
    a = max(begin, setter_call_rva - window)
    b = pe.get(a, setter_call_rva)
    hits = []
    for i in range(0, max(0, len(b) - 3)):
        if b[i:i+3] != b"\xFF\x50\x08":
            continue
        after = b[i+3:min(len(b), i+24)]
        m = after.find(b"\x48\x89\xC7")  # MOV RDI,RAX
        if m < 0:
            continue
        call_rva = a + i
        # nearest MOV EDX,[RIP+disp32] before virtual call
        sels = []
        for j in range(max(0, i-48), i):
            if b[j:j+2] == b"\x8B\x15":
                r = a + j
                t = (r + 6 + s32(b, j+2)) & 0xFFFFFFFF
                sels.append({"rva": r, "rva_hex": f"0x{r:X}", "slot_rva": t, "slot_rva_hex": f"0x{t:X}", "slot": pe.slot(t)})
        hits.append({
            "call_rva": call_rva,
            "call_rva_hex": f"0x{call_rva:X}",
            "return_to_rdi_rva": call_rva + 3 + m,
            "selector": sels[-1] if sels else None,
        })
    return hits[-1] if hits else None


def contains_subsequence(seq, sub):
    j = 0
    for x in seq:
        if j < len(sub) and x == sub[j]:
            j += 1
    return j == len(sub)


def extract_function(pe, name, func):
    calls, preps, segments = build_segments(pe, func)
    rows = []
    assignments = []

    for ordinal, segidx in enumerate(func["primary_segments"]):
        if segidx >= len(preps):
            continue
        begin = preps[segidx]
        end = preps[segidx+2] if segidx + 2 < len(preps) else func["end"]
        events = scan_events(pe, begin, end)
        block_calls = [e for e in events if e["kind"] == "CALL"]
        target_calls = [e for e in block_calls if e["target"] == TARGET]
        setter_calls = [e for e in block_calls if e["target"] == FIELD_SETTER]

        target_payloads = []
        for c in target_calls:
            q = nearest_numeric_store(events, c["rva"], 0x1D0)
            target_payloads.append(q["double"] if q else None)

        numeric = defaultdict(list)
        for e in events:
            if e["kind"] == "STORE_RBP" and e.get("double") is not None:
                numeric[e["disp"]].append(e["double"])
        local_1d0 = list(dict.fromkeys(numeric.get(0x1D0, [])))
        local_100 = list(dict.fromkeys(numeric.get(0x100, [])))

        row = {
            "function": name,
            "candidate_ordinal": ordinal,
            "segment_index": segidx,
            "known_name": func["known_segments"].get(segidx),
            "begin": begin,
            "end": end,
            "size": end - begin,
            "call_count": len(block_calls),
            "target_payloads": target_payloads,
            "canonical_0x1D0": local_1d0,
            "value_0x100": local_100,
            "setter_call_count": len(setter_calls),
        }
        rows.append(row)

        for setter_index, c in enumerate(setter_calls):
            r = c["rva"]
            args = trace_call_args(events, r)
            prior_100 = nearest_numeric_store(events, r, 0x100, lookback=0x300)
            selectors = find_rip_selector_loads(pe, begin, r)
            helper_selector = selectors[-1] if selectors else None
            virtual = find_virtual_source(pe, begin, r)
            r8 = find_r8d_imm(pe, begin, r)
            assignments.append({
                "function": name,
                "candidate_ordinal": ordinal,
                "segment_index": segidx,
                "known_name": row["known_name"],
                "setter_index": setter_index,
                "setter_call_rva": r,
                "setter_call_rva_hex": f"0x{r:X}",
                "value": prior_100.get("double") if prior_100 else None,
                "value_store_rva": prior_100.get("rva") if prior_100 else None,
                "value_store_delta": r - prior_100["rva"] if prior_100 else None,
                "r9_points_to_0x100": bool(args.get("R9") and args["R9"].get("kind") == "LEA_RBP" and args["R9"].get("disp") == 0x100),
                "helper_selector": helper_selector,
                "virtual_source": virtual,
                "r8d": r8,
                "canonical_0x1D0": local_1d0,
            })

    return {
        "function": name,
        "begin": func["begin"],
        "end": func["end"],
        "direct_call_count": len(calls),
        "prep_count": len(preps),
        "segment_count": len(segments),
        "rows": rows,
        "assignments": assignments,
    }


def summarize_assignments(assignments):
    pair = Counter()
    helper = Counter()
    virtual = Counter()
    r8 = Counter()
    values = []
    for a in assignments:
        hs = (a.get("helper_selector") or {}).get("slot_rva_hex")
        vs = ((a.get("virtual_source") or {}).get("selector") or {}).get("slot_rva_hex")
        rv = (a.get("r8d") or {}).get("imm_hex")
        pair[(vs, hs)] += 1
        helper[hs] += 1
        virtual[vs] += 1
        r8[rv] += 1
        if a.get("value") is not None:
            values.append(a["value"])
    return {
        "assignment_count": len(assignments),
        "value_count": len(values),
        "distinct_values": len(set(values)),
        "selector_pairs": [{"virtual_selector": a, "helper_selector": b, "count": c} for (a,b),c in pair.most_common()],
        "helper_selector_frequency": [{"slot": k, "count": v} for k,v in helper.most_common()],
        "virtual_selector_frequency": [{"slot": k, "count": v} for k,v in virtual.most_common()],
        "r8d_frequency": [{"value": k, "count": v} for k,v in r8.most_common()],
    }


def validate_known(rows):
    out = []
    for r in rows:
        name = r["known_name"]
        if not name:
            continue
        ex = KNOWN_EXPECTED[name]
        out.append({
            "name": name,
            "candidate_ordinal": r["candidate_ordinal"],
            "segment_index": r["segment_index"],
            "target_subsequence_ok": contains_subsequence(r["target_payloads"], ex["target_subsequence"]),
            "value_0x100_ok": ex["value_0x100"] in r["value_0x100"],
        })
    for x in out:
        x["overall_ok"] = x["target_subsequence_ok"] and x["value_0x100_ok"]
    return out


def write_primary_csv(path, rows):
    cols = ["function", "candidate_ordinal", "segment_index", "known_name", "begin", "end", "size", "call_count", "setter_call_count", "target_payloads", "canonical_0x1D0", "value_0x100"]
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in rows:
            q = dict(r)
            q["begin"] = f"0x{r['begin']:X}"
            q["end"] = f"0x{r['end']:X}"
            for k in ("target_payloads", "canonical_0x1D0", "value_0x100"):
                q[k] = json.dumps(r[k], ensure_ascii=False)
            q["known_name"] = q["known_name"] or ""
            w.writerow(q)


def zip_dir(src, zpath):
    if zpath.exists():
        zpath.unlink()
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
        for p in src.rglob("*"):
            if p.is_file():
                z.write(p, p.relative_to(src))


def main():
    t0 = time.time()
    ap = argparse.ArgumentParser()
    ap.add_argument("hero_siege_dir")
    args = ap.parse_args()
    root = Path(args.hero_siege_dir).resolve()
    exe = choose_exe(root)
    pe = PE(exe)

    desk = desktop()
    out = desk / "hero_siege_master"
    zpath = desk / "hero_siege_master.zip"
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    function_results = []
    all_rows = []
    all_assignments = []
    for name, func in FUNCTIONS.items():
        r = extract_function(pe, name, func)
        function_results.append({k:v for k,v in r.items() if k not in ("rows", "assignments")})
        all_rows.extend(r["rows"])
        all_assignments.extend(r["assignments"])

    assignment_summary = summarize_assignments(all_assignments)
    known = validate_known(all_rows)
    canonical = [r["canonical_0x1D0"] for r in all_rows]
    canonical_full = len(canonical) == 35 and all(bool(x) for x in canonical)
    canonical_distinct = len({json.dumps(x) for x in canonical})

    summary = {
        "version": MASTER_VERSION,
        "architecture": "standalone-no-wrapper",
        "exe": str(exe),
        "exe_sha256": sha256(exe),
        "functions_scanned": function_results,
        "primary_candidate_count": len(all_rows),
        "assignment_summary": assignment_summary,
        "canonical_0x1D0": {"coverage_full": canonical_full, "distinct": canonical_distinct, "collisions": len(canonical) - canonical_distinct},
        "known_validation": known,
        "next_design_goal": "generalize assignment extractor from one authoritative DefineItem function to all DefineItem* functions",
    }

    save_json(out / "master_summary.json", summary)
    save_json(out / "item_records.json", all_rows)
    save_json(out / "property_assignments.json", all_assignments)
    save_json(out / "selector_matrix.json", assignment_summary)
    save_json(out / "known_validation.json", known)
    write_primary_csv(out / "primary_blocks.csv", all_rows)

    diag = [
        f"MASTER_VERSION={MASTER_VERSION}",
        "ARCHITECTURE=standalone-no-wrapper",
        f"EXE={exe}",
        f"PRIMARY_CANDIDATES={len(all_rows)}",
        f"ASSIGNMENTS={len(all_assignments)}",
        f"CANONICAL_0x1D0_DISTINCT={canonical_distinct}",
        f"KNOWN={known}",
        f"SELECTORS={assignment_summary}",
    ]
    (out / "diagnostics.txt").write_text("\n".join(diag) + "\n", encoding="utf-8")
    zip_dir(out, zpath)
    print(f"Done: {zpath}")
    print(f"Master: {MASTER_VERSION}")
    print("Architecture: standalone-no-wrapper")
    print(f"Elapsed: {time.time()-t0:.1f}s")


if __name__ == "__main__":
    main()
