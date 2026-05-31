@echo off
cd /d ./ENSEC-CLI
rmdir /s /q build
rmdir /s /q dist
rmdir /s /q ensec_cli.egg-info

python -m build
twine check dist/*
pause