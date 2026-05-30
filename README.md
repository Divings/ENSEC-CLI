# ENSEC-CLI

ENSEC-CLI (EncryptSecure Command Line Interface) は、EncryptSecureDEC の暗号化エンジンを利用したコマンドライン向け暗号化ツールです。

GUIを必要とせず、サーバー環境やターミナル環境での利用を想定しています。

## 特徴

* AES-GCMによるファイル暗号化
* ファイル復号
* Windows対応
* Linux対応
* Pythonベース
* EncryptSecureDECとの互換性を重視
* 暗号化ファイルをWAVファイルとして保存可能

## 開発目的

EncryptSecureDECはGUIアプリケーションとして開発されていますが、

* GUIを利用できない環境
* サーバー上での運用
* 自動化スクリプトとの連携
* 旧バージョン利用者向け環境

などの用途に対応するため、CLI版としてENSEC-CLIを開発しています。

## 動作環境

* Python 3.10以上推奨
* Windows 10 / 11
* Linux

## インストール

リポジトリを取得します。

```bash
git clone https://github.com/Divings/ENSEC.git
cd ENSEC
```

依存ライブラリをインストールします。

```bash
pip install -r requirements.txt
```

## 使用方法

### ファイルを暗号化

```bash
python ensec.py encrypt sample.txt
```

### ファイルを復号

```bash
python ensec.py decrypt sample.txt.enc
```

※実際のコマンドは実装に合わせて変更してください。

## プロジェクトについて

ENSEC-CLIは合同会社Anvelk Innovationsによって開発されています。

暗号化技術の普及と、より安全なデータ保護環境の提供を目的として継続開発を行っています。

## 関連プロジェクト

* EncryptSecureDEC
* ENSEC WebApp

## ライセンス

MIT License
