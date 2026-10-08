<?php
declare(strict_types=1);
namespace SecuLens;

/** Explicit EOF handling: a closed input stream never accepts execution defaults. */
final class Wizard
{
    private bool $ja = false;
    public function __construct(private $stream, private readonly \Closure $write) {}
    private function t(string $en,string $ja): string { return $this->ja ? $ja : $en; }
    private function ask(string $prompt,string $default='',?callable $valid=null): string
    {
        while (true) {
            ($this->write)($prompt.($default!=='' ? " [$default]" : '').': ',false);
            $line = $this->readLine();
            if ($line===false) { throw new WizardCancelled(); }
            $value = trim($line); if ($value==='') { $value=$default; }
            if ($valid===null || $valid($value)) { return $value; }
            ($this->write)($this->t('Invalid value. Please try again.','値を確認して再入力してください。'),true);
        }
    }
    private function readLine(): string|false
    {
        // A blocking fgets defers PHP signal callbacks until another line arrives.
        // Poll STDIN and read one available byte at a time so Ctrl+C stays responsive.
        if (in_array(stream_get_meta_data($this->stream)['stream_type'], ['MEMORY','TEMP'], true)) {
            return fgets($this->stream);
        }
        $line = '';
        while (true) {
            $read = [$this->stream]; $write = []; $except = [];
            $ready = @stream_select($read, $write, $except, 0, 200000);
            if (function_exists('pcntl_signal_dispatch')) { pcntl_signal_dispatch(); }
            if (!$ready) { continue; }
            $byte = fgetc($this->stream);
            if ($byte === false) { return $line === '' ? false : $line; }
            $line .= $byte;
            if ($byte === "\n") { return $line; }
            if (strlen($line) > 65536) { throw new \InvalidArgumentException('Wizard input line is too long'); }
        }
    }
    private function yes(string $prompt,bool $default=false): bool
    {
        return in_array(strtolower($this->ask($prompt,$default?'y':'n',static fn(string $v): bool => in_array(strtolower($v),['y','n','yes','no'],true))), ['y','yes'], true);
    }
    public function settings(?string $language=null): ?array
    {
        try {
            if ($language===null) { $language=$this->ask('Language / 言語 (en / ja)','en',static fn(string $v): bool => in_array($v,['en','ja'],true)); }
            if (!in_array($language,['en','ja'],true)) { throw new \InvalidArgumentException('Language must be en or ja'); }
            $this->ja=$language==='ja';
            ($this->write)($this->t("\nSecuLens setup wizard\nPress Enter for defaults. Ctrl+C cancels.","\nSecuLens 設定ウィザード\nEnterで既定値を選択できます。Ctrl+Cで中止します。"),true);
            $operation=$this->ask($this->t('Operation: 1 = assess SBOM, 2 = generate SBOM','操作: 1 = 既存SBOMを検査、2 = SBOMを生成'),'1',static fn(string $v): bool => in_array($v,['1','2'],true));
            $o=['lang'=>$language,'operation'=>$operation==='1'?'scan':'sbom'];
            $required=static fn(string $v): bool => $v!=='';
            if ($o['operation']==='sbom') {
                $o['directory']=$this->ask($this->t('Project directory','プロジェクトフォルダー'),'.',$required);
                $o['format']=$this->ask($this->t('Format: cyclonedx / spdx','形式: cyclonedx / spdx'),'cyclonedx',static fn(string $v): bool => in_array($v,['cyclonedx','spdx'],true));
                $o['output']=$this->ask($this->t('SBOM output path','SBOM出力先'),'sbom.json',$required);
                $o['syft']=$this->ask($this->t('Syft executable','Syft実行ファイル'),'syft',$required);
            } else {
                $o['sbom']=$this->ask($this->t('SBOM JSON path','SBOM JSONのパス'),'sbom.json',$required);
                $online=$this->yes($this->t('Fetch OSV candidates online','OSVから脆弱性情報の候補を取得'));
                $o['fetch-osv']=$online; $o['db']=$online?null:$this->ask($this->t('Local OSV database JSON path','ローカルOSVデータベースのパス'),'database.json',$required);
                if ($online) { ($this->write)($this->t('OSV fetching sends package names and ecosystems to api.osv.dev. Versions are matched locally; source code and the entire SBOM are not uploaded.','OSV取得ではパッケージ名とエコシステムをapi.osv.devへ送信します。バージョンはローカルで照合し、ソースコードやSBOM全体は送信しません。'),true); }
                $o['policy']=$this->ask($this->t('License policy JSON path (optional)','ライセンスポリシーのパス（任意）'));
                $o['source']=$this->ask($this->t('PHP source file or directory (optional)','PHPソースファイルまたはフォルダー（任意）'));
                $o['customer']=$this->ask($this->t('Customer','顧客名'),'Customer',$required);
                $o['target']=$this->ask($this->t('Assessment target name','検査対象名'),basename($o['sbom']),$required);
                $o['issuer']=$this->ask($this->t('Prepared by (optional)','作成者（任意）'));
                $o['report-style']=$this->ask($this->t('Report style: customer / standard','レポート形式: customer / standard'),'customer',static fn(string $v): bool => in_array($v,['customer','standard'],true));
                $o['output']=$this->ask($this->t('Output directory','出力フォルダー'),'reports',$required);
                $o['fail-on-findings']=$this->yes($this->t('Exit with status 1 on actionable findings','対応対象の検出時に終了コード1を返す'));
            }
            ($this->write)($this->t("\nReview settings","\n設定の確認"),true);
            $labels=['operation'=>['Operation','操作'],'lang'=>['Language','言語'],'directory'=>['Project directory','プロジェクト'],'format'=>['Format','形式'],'output'=>['Output','出力先'],'syft'=>['Syft','Syft'],'sbom'=>['SBOM','SBOM'],'fetch-osv'=>['Fetch OSV','OSV取得'],'db'=>['Database','データベース'],'policy'=>['Policy','ポリシー'],'source'=>['PHP source','PHPソース'],'customer'=>['Customer','顧客名'],'target'=>['Target','検査対象'],'issuer'=>['Prepared by','作成者'],'report-style'=>['Report style','レポート形式'],'fail-on-findings'=>['Exit on findings','検出時の終了']];
            foreach ($o as $key=>$value) { ($this->write)('  '.$labels[$key][$this->ja?1:0].': '.(is_bool($value)?($value?'yes':'no'):($value?:'-')),true); }
            if (!$this->yes($this->t('Start','開始しますか'))) { throw new WizardCancelled(); }
            return $o;
        } catch (WizardCancelled) {
            ($this->write)($this->t("\nCancelled. No assessment or generation was started.","\n中止しました。検査・生成は開始していません。"),true);
            return null;
        }
    }
}
final class WizardCancelled extends \RuntimeException {}
