@echo off
rem Quaestor operator CLI launcher. Keeps the repository root out of PATH concerns:
rem adjust QUAESTOR_SRC if you installed the sources elsewhere.
setlocal
set "QUAESTOR_SRC=%~dp0..\src"
python -c "import sys; sys.path.insert(0, r'%QUAESTOR_SRC%'); from quaestor.transports.cli import main; raise SystemExit(main())" %*
