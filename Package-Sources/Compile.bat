@echo off
rem メインの作業ディレクトリへ移動
cd /d ./ENSEC-CLI

rem 一時ディレクトリを削除
rmdir /s /q build
rmdir /s /q dist
rmdir /s /q ensec_cli.egg-info

rem ビルド&チェック
python -m build
twine check dist/*
pause