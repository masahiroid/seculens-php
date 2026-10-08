# Publishing to Packagist

The Composer package name is `masahiroid/seculens`; CLI branding remains SecuLens and its executable is `seculens`.

The public source repository is https://github.com/masahiroid/seculens-php. Initial release tag: `v0.1.0`. Packagist registration is a separate step; a GitHub release does not register the package automatically.

## Initial registration

1. Register or sign in at https://packagist.org/. Choose a username you control; `masahiroid` is preferred if available.
2. Open https://packagist.org/packages/submit.
3. Enter `https://github.com/masahiroid/seculens-php` as the repository URL.
4. Check that the detected package name is `masahiroid/seculens` and submit it.
5. Confirm that `0.1.0` appears, then verify `composer require --dev masahiroid/seculens:^0.1` from a clean project.

Repository access tokens do not need to be pasted into chat. For subsequent updates, use the package page's update function or configure an authenticated GitHub webhook according to the official instructions. Select any account/link permissions yourself after reviewing the provider's consent screen.

## Release verification

```sh
composer validate --strict
composer lint
composer test
composer audit
```

The repository includes `composer.lock` to reproduce development/CI dependencies. Composer selects a compatible dependency set when another project installs this library. Package versions derive from Git tags; do not add a manual `version` field to `composer.json`.

Official references: [Packagist publishing](https://packagist.org/about), [Composer libraries](https://getcomposer.org/doc/02-libraries.md).

## 日本語での登録手順

1. [Packagist](https://packagist.org/)でアカウントを作成し、ログインします。
2. [Submit](https://packagist.org/packages/submit)を開きます。
3. リポジトリURLに `https://github.com/masahiroid/seculens-php` を入力します。
4. パッケージ名が `masahiroid/seculens` と表示されることを確認して登録します。
5. `0.1.0`の表示を確認し、別のプロジェクトでComposerからの導入を確認します。

GitHubのリリース公開とPackagistへの登録は別です。アカウント登録・認証が完了するまでは、GitHubから取得して `composer install --no-dev` で使えます。
