@echo off
rem 作業ディレクトリに移動
cd /d ./ENSEC-CLI

rem パッケージをアップロード
python -m twine upload dist/*
pause