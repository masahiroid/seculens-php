# Publishing to Packagist

The Composer package name is `masahiroid/seculens`; CLI branding remains SecuLens and its executable is `seculens`.

The public source repository is https://github.com/masahiroid/seculens-php. The package is registered on Packagist, and a tag push updates it through the GitHub webhook.

## Release verification

```sh
composer validate --strict
composer lint
composer test
composer audit
```

The repository includes `composer.lock` to reproduce development/CI dependencies. Composer selects a compatible dependency set when another project installs this library. Package versions derive from Git tags; do not add a manual `version` field to `composer.json`.

Official references: [Packagist publishing](https://packagist.org/about), [Composer libraries](https://getcomposer.org/doc/02-libraries.md).

## 日本語

パッケージはPackagistに登録済みです。タグをプッシュすると、GitHubのWebhookで自動的に更新されます。
