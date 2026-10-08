# SecuLens for PHP

[English](README.md) | [日本語](README.jp.md)

SecuLensの独立したPHP実装です。SPDX／CycloneDX JSONのSBOMを読み込み、OSVの脆弱性情報とバージョンを照合します。SPDXライセンスポリシーの評価、PHPのAST解析、顧客提出用Word・JSONレポートの生成に対応します。Python、Node.js、Trivyの実行環境は不要です。

**バージョン1.0.0。** 脆弱性の一致は指定データベースに基づく根拠、ASTの検出は確認候補です。完全なSAST、悪用可能性、法的な適合性の確定は行いません。[Python版](https://github.com/masahiroid/seculens-python)・[JS／TypeScript版](https://github.com/masahiroid/seculens)とJSONレポートの形式を揃えています。

## インストール

PHP 8.2以降、Composer 2、PHP拡張`curl`・`dom`・`mbstring`・`xml`・`zip`が必要です。依存ライブラリが必要とする拡張もComposerが確認します。

Packagist登録前は、リポジトリから導入してください。

```sh
git clone https://github.com/masahiroid/seculens-php.git
cd seculens-php
composer install --no-dev
php bin/seculens
```

[GitHub Releases](https://github.com/masahiroid/seculens-php/releases)のソースアーカイブを展開し、同じように`composer install --no-dev`を実行する方法も使えます。依存ライブラリはアーカイブに同梱していません。

Packagist登録後に使う予定のコマンド：

```sh
composer require --dev masahiroid/seculens
vendor/bin/seculens
```

この方法にはPackagistへの登録が必要です。CLI名は`seculens`、Composerのパッケージ名は必須のベンダー名を含む`masahiroid/seculens`です。[公開手順](docs/publishing.md)も参照してください。

## 対話ウィザード

インストールしたCLIは引数なしの`seculens`、ソースからは`php bin/seculens`で起動します。既定は英語です。言語選択で`ja`を入力すると日本語になります。日本語で直接開始する場合：

```sh
php bin/seculens wizard --lang ja
```

既存SBOMの検査またはSBOM生成を選びます。検査ではSBOM、ローカルDBまたはOSV取得、任意のライセンスポリシーとPHPソース、顧客名・対象名・作成者、レポート形式、出力先、検出時の終了方針を設定します。ウィザードでは顧客提出用レポートが既定です。最後に設定を確認し、開始を明示的に選択してください。

入力終了（EOF）や開始確認の拒否では検査・生成を開始しません。`pcntl`対応環境ではCtrl+Cで終了コード130になります。相対パスは現在の作業フォルダーを基準に指定してください。

## 既存SBOMの検査

保存済みOSVデータベースでオフライン検査：

```sh
php bin/seculens scan bom.json --db database.json --policy policy.json \
  --source ./src --customer "顧客企業" --target "顧客Webサービス" \
  --issuer "評価チーム" --lang ja --report-style customer --output reports/customer
```

リポジトリの実演用サンプル：

```sh
php bin/seculens scan examples/cyclonedx.json --db examples/database.json \
  --policy examples/policy.json --source examples --lang ja \
  --report-style customer --output reports/demo
```

**同梱の脆弱性情報は架空の実演データです。本番の脆弱性DBではありません。** 出力は`report.docx`、`report.json`、元の`sbom.json`、`database.json`です。SBOMとDBのテキストをSHA-256ハッシュで特定できます。同じスナップショットで照合結果を再現できますが、生成日時とDOCXのメタデータは異なる場合があります。

OSVから候補を取得する場合は明示的に指定します。

```sh
php bin/seculens scan bom.json --fetch-osv --output reports/live
```

`--fetch-osv`ではパッケージ名とエコシステムを`api.osv.dev`へ送信し、照合はローカルで行います。ソースコード、バージョン、SBOM全体は送信しません。ウィザードには実行前に送信内容を表示します。通信失敗や不正な応答では検査を停止します。`--db`による検査はネットワーク接続を使いません。`--db`と`--fetch-osv`はどちらか一方を指定してください。

## SBOMの生成

[Syft](https://github.com/anchore/syft)を別途導入して実行します。

```sh
php bin/seculens sbom ./project --format cyclonedx --output bom.cdx.json
php bin/seculens sbom ./project --format spdx --output bom.spdx.json
```

`--syft /path/to/syft`で実行ファイルを指定できます。引数を個別に渡してSyftを実行し、出力の対応項目を検証します。検査対象プロジェクトのインストールやコード実行は行いません。他のツールで生成したSBOMも直接読み込めます。SyftでComposerの依存関係を取得し、その脆弱性・ライセンス評価はSecuLens内のPHP実装で行います。

## 対応入力と照合範囲

- SPDX 2.2／2.3 JSONのパッケージ・依存関係情報。
- CycloneDX 1.4〜1.7 JSONのコンポーネント、入れ子のコンポーネント、依存関係情報。
- バージョンを含むPackage URL：`pkg:npm`・`pkg:pypi`・`pkg:composer`。
- npmのSemVer、PyPIのPEP 440とパッケージ名の正規化。
- Packagistの安定版数値SemVer互換バージョン、先頭の`v`、末尾が`.0`の4桁バージョン、SemVerプレリリース。Composerのブランチ、別名、固有のバージョン形式は未評価です。
- OSVの明示的な影響バージョン、`SEMVER`／`ECOSYSTEM`範囲、修正版・最終影響版・上限の境界、撤回済み情報、ページ分割。同じ脆弱性の別名はコンポーネントごとに統合します。

不正・未対応・不完全な範囲は未評価として記録します。GIT範囲のみの情報、他のエコシステム、SPDX 3、XMLは未対応です。入力検証はSecuLensが使う項目に限られ、規格全体への適合検証ではありません。DBの完全性や脆弱なコードへの到達可能性は確認できません。**「照合なし」は指定DBに一致がないという意味で、脆弱性がないことを保証しません。**

## ライセンスポリシー

```json
{
  "allow": ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC"],
  "deny": ["AGPL-3.0-only", "AGPL-3.0-or-later"]
}
```

SPDX式の`AND`・`OR`・括弧・`WITH`例外を解析します。`AND`は全分岐の許可、`OR`はいずれかの選択肢の許可が必要です。例外は式全体をポリシーへ登録してください。同一項目の許可・拒否が競合した場合は拒否を優先します。不明・独自・未記載のライセンスは要確認です。ポリシー未指定の場合も要確認とします。宣言の正確性、ソースのライセンス、配布義務、規制への適合は検証しません。

## PHPのAST解析

`--source`で[nikic/PHP-Parser](https://github.com/nikic/PHP-Parser)を使い、`.php`ファイルをインポート・実行せずに解析します。

- `eval`、シェル実行関数、バッククォート。
- `unserialize`、非リテラルのinclude／requireパス、用途確認が必要な`md5`／`sha1`。
- `query`／`exec`メソッドへ渡す連結・補間された文字列。呼び出し先の型は解決しません。
- 循環的複雑度が10を超える関数、制御構造のネストが4を超える関数。論理演算、null合体、case、matchの分岐、三項演算も複雑度に加算します。入れ子の関数は個別に測定します。

関数のインポートは構文から識別します。名前空間のフォールバック、同名のローカル関数、変数による呼び出し、データフロー、呼び出し先の型は完全には解決しません。未検出や手動確認が必要な候補があり得ます。セキュリティに関係しないハッシュ用途まで危険と断定しません。構文エラーや、明示的に指定したソースにPHPファイルがない場合は解析範囲の不足です。vendor、依存関係・ビルドフォルダー、シンボリックリンクはスキップします。

## 顧客提出用Wordレポート

`--report-style customer`で表紙、要約、重大度の色分け、番号付き指摘一覧・詳細、構成部品の評価表、根拠ハッシュ、ページ番号を含むWordレポートを生成します。直接実行では`standard`、ウィザードでは`customer`が既定です。

`--customer`・`--target`・`--issuer`は顧客名・対象名・作成者です。対象名は未指定時にSBOMのファイル名になります。既定の`--lang en`は英語、`--lang ja`は主要な見出し・要約・組み込みルールの概要と推奨対応を日本語にします。脆弱性情報の本文や技術的な根拠には元の言語が残ります。

Critical／Highは赤、Mediumは黄、Lowは青、Noneは緑、Unratedは灰色で、色とラベルを併記します。重大度は検証済みCVSS 3.0／3.1基本ベクトルまたはOSVのDBラベルに基づきます。該当する`affected.severity`は全体のベクトルより優先します。別名統合時には根拠を残し、対応する最も高い重大度を表示します。CVSS 2／4や不正ベクトルは保存しますが計算せず、他に根拠がなければUnratedです。本文、コード候補、ライセンスから重大度を推測しません。CVSS 0／Noneも脆弱性がないことの証明ではありません。

日本語DOCXにはNoto Sans JP（SIL OFL 1.1）を埋め込み、容量が約4 MB増えます。LibreOfficeの描画で体裁を確認していますが、閲覧環境によって最終的な改ページは変わる場合があります。元の重大度情報、フィールドパス、参照先はJSONスキーマ1.1に保存します。他言語版と形式を揃え、PHPの`sourceAnalysis`には発見・解析済みファイル数も記録します。

## 終了コード

- `0`：解析範囲の不足なく検査完了。検出結果が残る場合があります。
- `1`：`--fail-on-findings`指定時に脆弱性、拒否ライセンス、セキュリティ確認候補を検出。
- `2`：入力不正、実行エラー、解析範囲の不足。指定時は検出による終了コード1が優先されます。
- `130`：`pcntl`対応環境でのCtrl+C中断。

## ライブラリAPI

```php
use SecuLens\Assessment;
use SecuLens\Database;
use SecuLens\Json;
use SecuLens\WordReport;

$records = Database::validate(Json::decode(file_get_contents('database.json')));
$report = Assessment::scan(file_get_contents('bom.json'), $records, [
    'customer' => '顧客企業',
    'target' => 'Webサービス',
    'policy' => ['allow' => ['MIT', 'Apache-2.0']],
]);
WordReport::write($report, 'report.docx', 'ja', 'customer', '評価チーム');
```

`SecuLens\Analysis::scan($source)`はPHP解析の`findings`・`metadata`を返します。`SecuLens\Runner::scan($options)`はCLIと同様の検査・出力をまとめて実行します。

## 開発

```sh
composer install
composer validate --strict
composer lint
composer test
composer audit
```

[設計](docs/architecture.md)・[セキュリティポリシー](SECURITY.md)も参照してください。コードはApache-2.0、同梱フォントはSIL OFL 1.1です。[NOTICE](NOTICE)に第三者の資産を記載しています。脆弱性情報には情報源のライセンスが適用されます。TrivyおよびSECULENSという名称の光学レンズ企業とは独立したプロジェクトです。
