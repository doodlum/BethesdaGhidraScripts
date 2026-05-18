#!/usr/bin/env python3
"""One-off: apply CommonLibImport_SF.py to Starfield.exe in the user's
StarfieldProject via pyghidra.

analyzeHeadless.bat can run auto-analysis but its scripting engine is
Jython; CommonLibImport_SF.py is a pyghidra (Python 3) script.  This
script opens the existing project, finds Starfield.exe, applies the
import script, and saves -- the same pattern as scripts/run_headless.py
but pointed at the user's StarfieldProject instead of the pipeline
project.
"""
import os
import sys
from pathlib import Path

REPO_DIR    = Path(__file__).resolve().parent.parent
GHIDRA_DIR  = REPO_DIR / "tools" / "ghidra"
SCRIPT_PATH = REPO_DIR / "ghidrascripts" / "CommonLibImport_SF.py"

PROJECT_DIR  = Path(r"C:/GhidraProjects/Starfield")
PROJECT_NAME = "StarfieldProject"
PROGRAM_NAME = "Starfield.exe"


def main():
    os.environ.setdefault("GHIDRA_INSTALL_DIR", str(GHIDRA_DIR))
    import pyghidra
    pyghidra.start(install_dir=GHIDRA_DIR)

    from ghidra.util.task import ConsoleTaskMonitor
    import java.lang
    monitor = ConsoleTaskMonitor()

    with pyghidra.open_project(PROJECT_DIR, PROJECT_NAME, create=False) as project:
        root = project.getProjectData().getRootFolder()

        # Walk for the Starfield.exe domain file (recursive in case it sits
        # under a folder like /Starfield 1.6.34/).
        def find(folder):
            for f in folder.getFiles():
                if f.getName() == PROGRAM_NAME:
                    return f
            for sub in folder.getFolders():
                hit = find(sub)
                if hit is not None:
                    return hit
            return None

        domain_file = find(root)
        if domain_file is None:
            print(f"ERROR: {PROGRAM_NAME} not found in project tree")
            sys.exit(1)
        print(f"Found program: {domain_file.getPathname()}")

        consumer = java.lang.Object()
        program = domain_file.getDomainObject(consumer, True, False, monitor)
        try:
            print(f"Running {SCRIPT_PATH.name} via pyghidra...")
            stdout, stderr = pyghidra.ghidra_script(
                SCRIPT_PATH, project, program,
                echo_stdout=True, echo_stderr=True)
            if stderr:
                print("STDERR:", stderr, file=sys.stderr)
            print("Saving...")
            program.save("CommonLibSF import", monitor)
            print("Done.")
        finally:
            program.release(consumer)


if __name__ == "__main__":
    main()
