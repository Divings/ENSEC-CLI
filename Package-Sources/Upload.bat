@echo off
cd /d ./ENSEC-CLI
python -m twine upload dist/*
pause