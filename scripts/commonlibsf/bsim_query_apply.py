# @category BSim
# @runtime PyGhidra
"""Headless BSim cross-program name port.

For the currentProgram, generates BSim signatures, queries an H2 file
database, and for each function takes the highest-similarity match
from the corpus and renames the local function (if the match's source
name is a real RE-derived name -- skips FUN_*, thunk_*, _dynamic_*).

Run via pyghidra or analyzeHeadless ``-postScript bsim_query_apply.py
file:/path/to/SF_BSim 0.85 25.0``.

Args (positional):
  1. BSim DB URL  e.g. file:/C:/Development/Tools/BethesdaGhidraScripts/bsim/SF_BSim
  2. min similarity threshold (0.0-1.0; lower=more matches, more noise)
  3. min significance bound (BSim's "self-significance" -- prunes tiny funcs)
  4. optional: --dry  (don't apply, just print stats)

Only renames functions whose current name starts with FUN_ or thunk_FUN_.
Preserves hand-named work.
"""
import re
import sys

# Args
args = list(getScriptArgs())
DB_URL          = args[0] if len(args) > 0 else "file:/C:/Development/Tools/BethesdaGhidraScripts/bsim/SF_BSim"
MIN_SIMILARITY  = float(args[1]) if len(args) > 1 else 0.85
MIN_SIGNIFICANCE = float(args[2]) if len(args) > 2 else 25.0
DRY_RUN         = "--dry" in args

MAX_MATCHES_PER_FUNCTION = 5

print(f"BSim DB:           {DB_URL}")
print(f"Min similarity:    {MIN_SIMILARITY}")
print(f"Min significance:  {MIN_SIGNIFICANCE}")
print(f"Dry run:           {DRY_RUN}")
print(f"Target program:    {currentProgram.getName()}")

from ghidra.features.bsim.query import BSimClientFactory, GenSignatures
from ghidra.features.bsim.query.protocol import QueryNearest
from ghidra.program.model.symbol import SourceType

NOISE_PREFIXES = ("FUN_", "thunk_FUN_", "sub_")
NOISE_SUBSTRINGS = ("_dynamic_initializer_for_", "_lambda_", "API-MS-")


def is_noise(name):
    if not name:
        return True
    if any(name.startswith(p) for p in NOISE_PREFIXES):
        return True
    return any(s in name for s in NOISE_SUBSTRINGS)


def is_overwritable(current_name):
    """We rename FUN_* / thunk_FUN_* / sub_* but never overwrite hand-named work."""
    if not current_name:
        return True
    return current_name.startswith("FUN_") or current_name.startswith("thunk_FUN_") or current_name.startswith("sub_")


_SAFE_RE = re.compile(r"[^A-Za-z0-9_<>$~?@:.-]")


def sanitize_name(name):
    parts = name.split("::")
    out = []
    for p in parts:
        p = p.strip()
        p = _SAFE_RE.sub("_", p)
        if p and p[0].isdigit():
            p = "_" + p
        out.append(p or "_")
    return "::".join(out)


def main():
    url = BSimClientFactory.deriveBSimURL(DB_URL)
    database = BSimClientFactory.buildClient(url, False)
    if not database.initialize():
        err = database.getLastError()
        print(f"DB init failed: {err.message if err else '?'}")
        return

    def new_gensig():
        g = GenSignatures(False)
        g.setVectorFactory(database.getLSHVectorFactory())
        g.openProgram(currentProgram, None, None, None, None, None)
        return g

    gensig = new_gensig()

    fm = currentProgram.getFunctionManager()
    func_count = fm.getFunctionCount()
    print(f"Total functions in program: {func_count}")

    n_scanned = 0
    n_renamed = 0
    n_below_thresh = 0
    n_no_match = 0
    n_db_err = 0
    n_already_named = 0
    n_noise_match = 0
    sample_renames = []

    monitor.setMaximum(func_count)
    monitor.setIndeterminate(False)
    funcs_iter = fm.getFunctions(True)

    # We must scan + query per function (or batch).  Process in chunks
    # to reduce overhead.
    BATCH = 50
    chunk = []
    def flush_chunk():
        nonlocal n_scanned, n_renamed, n_below_thresh, n_no_match
        nonlocal n_db_err, n_already_named, n_noise_match, gensig
        if not chunk:
            return
        # Reset the signature corpus by disposing + creating fresh; there's
        # no public clearVectors on GenSignatures.
        gensig.dispose()
        gensig = new_gensig()
        scanned_funcs = []
        for f in chunk:
            try:
                gensig.scanFunction(f)
                scanned_funcs.append(f)
            except Exception:
                pass
        query = QueryNearest()
        query.manage = gensig.getDescriptionManager()
        query.max = MAX_MATCHES_PER_FUNCTION
        query.thresh = MIN_SIMILARITY
        query.signifthresh = MIN_SIGNIFICANCE
        try:
            response = database.query(query)
        except Exception as e:
            n_db_err += len(chunk)
            chunk.clear()
            return
        if response is None:
            err = database.getLastError()
            print(f"  query returned None: {err.message if err else '?'}")
            n_db_err += len(chunk)
            chunk.clear()
            return

        # Map: source function description -> matches
        sim_iter = response.result.iterator()
        while sim_iter.hasNext():
            sim = sim_iter.next()
            base = sim.getBase()  # FunctionDescription of the local function being queried
            local_addr = base.getAddress()  # source RVA (= addr of the local function)
            local_func = fm.getFunctionAt(currentProgram.getImageBase().add(local_addr))
            if local_func is None:
                continue
            if not is_overwritable(local_func.getName()):
                n_already_named += 1
                continue

            # Find highest-similarity match across all source programs
            best = None
            best_sim = -1.0
            sub_iter = sim.iterator()
            while sub_iter.hasNext():
                note = sub_iter.next()
                fdesc = note.getFunctionDescription()
                exerec = fdesc.getExecutableRecord()
                name = fdesc.getFunctionName()
                # Skip same-program self-matches and noisy names
                if exerec.getMd5() == currentProgram.getExecutableMD5():
                    continue
                if is_noise(name):
                    continue
                s = note.getSimilarity()
                if s > best_sim:
                    best_sim = s
                    best = (exerec.getNameExec(), name, s, note.getSignificance())

            if best is None:
                # Either no match or only noise/self matches
                n_no_match += 1
                continue

            if best_sim < MIN_SIMILARITY:
                n_below_thresh += 1
                continue

            src_exe, src_name, sim_score, sig_score = best
            new_name = sanitize_name(src_name)
            if DRY_RUN:
                n_renamed += 1
                if len(sample_renames) < 20:
                    sample_renames.append((local_func.getName(), new_name, src_exe, sim_score, sig_score))
            else:
                try:
                    # Parse namespace path
                    parts = new_name.split("::")
                    leaf = parts[-1]
                    ns_parts = parts[:-1]
                    parent = currentProgram.getGlobalNamespace()
                    sym = currentProgram.getSymbolTable()
                    for p in ns_parts:
                        sub = sym.getNamespace(p, parent)
                        if sub is None:
                            sub = sym.createNameSpace(parent, p, SourceType.USER_DEFINED)
                        parent = sub
                    local_func.setParentNamespace(parent)
                    local_func.setName(leaf, SourceType.USER_DEFINED)
                    n_renamed += 1
                    if len(sample_renames) < 20:
                        sample_renames.append((local_func.getName(), new_name, src_exe, sim_score, sig_score))
                except Exception as e:
                    n_db_err += 1

        n_scanned += len(scanned_funcs)
        chunk.clear()

    while funcs_iter.hasNext():
        if monitor.isCancelled():
            break
        f = funcs_iter.next()
        if not is_overwritable(f.getName()):
            n_already_named += 1
            monitor.incrementProgress(1)
            continue
        chunk.append(f)
        if len(chunk) >= BATCH:
            flush_chunk()
            print(f"  scanned={n_scanned}  renamed={n_renamed}  already_named={n_already_named}  below_thresh={n_below_thresh}  no_match={n_no_match}  db_err={n_db_err}", flush=True)
            monitor.incrementProgress(BATCH)
    flush_chunk()

    print("\n=== Summary ===")
    print(f"  scanned:        {n_scanned}")
    print(f"  renamed:        {n_renamed}")
    print(f"  already named:  {n_already_named}")
    print(f"  below thresh:   {n_below_thresh}")
    print(f"  no match:       {n_no_match}")
    print(f"  db error:       {n_db_err}")
    print(f"  noise match:    {n_noise_match}")
    if sample_renames:
        print("\nSample renames (first 20):")
        for cur, new, exe, sim, sig in sample_renames:
            print(f"  {cur:24s}  ->  {new[:60]:60s}  ({exe[:20]}  sim={sim:.3f}  sig={sig:.1f})")

    gensig.dispose()
    database.close()


main()
