<?php
declare(strict_types=1);
namespace SecuLens;
use PhpOffice\PhpWord\PhpWord;
use PhpOffice\PhpWord\Settings;
use PhpOffice\PhpWord\IOFactory;
use PhpOffice\PhpWord\Element\Section;

final class WordReport
{
    private const PALETTE = [
        'critical'=>['Critical','重大','991B1B','FEE2E2'], 'high'=>['High','高','B91C1C','FFF1F2'],
        'medium'=>['Medium','中','92400E','FEF3C7'], 'low'=>['Low','低','075985','E0F2FE'],
        'none'=>['None','なし','166534','F0FDF4'], 'unknown'=>['Unrated','未評価','475569','F1F5F9'],
    ];
    private const CATEGORIES = ['vulnerability'=>['Vulnerability','脆弱性'],'license'=>['License','ライセンス'],'security'=>['Code review','コード確認'],'quality'=>['Quality','品質'],'coverage'=>['Coverage','検査範囲']];
    private const TRANSLATIONS = [
        'PHP source could not be fully assessed'=>'PHPソースを完全に評価できませんでした',
        'Advisory could not be fully evaluated'=>'脆弱性情報を完全に評価できませんでした',
        'Component could not be assessed'=>'構成部品を評価できませんでした',
        'License requires review'=>'ライセンスの確認が必要',
        'License denied by policy'=>'ポリシーで拒否されたライセンス',
        'Function complexity requires review'=>'関数の複雑度の確認が必要',
        'Constructed query requires review'=>'組み立てたクエリの確認が必要',
        'Hash use requires context review'=>'ハッシュの用途確認が必要',
        'Dynamic include or require path'=>'動的なincludeまたはrequireのパス',
        'Deserialization requires review'=>'デシリアライズの確認が必要',
        'Shell execution requires review'=>'シェル実行の確認が必要',
        'Dynamic PHP evaluation'=>'動的なPHPコード評価',
        'No match means no matching record in the supplied database snapshot, not absence of vulnerabilities.'=>'照合なしは使用したDB内に該当情報がないことを示し、脆弱性が存在しないことを保証しません。',
        'License policy checks are not a legal compliance determination.'=>'ライセンスポリシー評価は法的な適合性の確定を行うものではありません。',
        'AST rules identify review candidates and complexity, not proven exploitability.'=>'AST検査は要確認のコードや複雑性を抽出します。悪用可能性を立証するものではありません。',
        'SBOM content and package identifiers are supplied by the generating tool.'=>'SBOMの内容とパッケージ識別情報は生成ツールが提供したものです。',
        'Packagist matching supports stable numeric versions and SemVer prereleases only; Composer branches and other version forms may be unassessed.'=>'Packagistは安定版の数値バージョンとSemVerプレリリースのみ対応します。Composerブランチなどは未評価になる場合があります。',
        'Review the advisory references for a fixed version and validate the upgrade.'=>'参照先で修正済みバージョンを確認し、更新後の動作を検証してください。',
        'Review the call and trace untrusted input before deciding whether it is exploitable.'=>'処理と外部入力の経路を確認し、実際の悪用可能性を判断してください。',
        'Consider simplifying the function and adding focused tests.'=>'関数の分割や簡素化を検討し、分岐に対応したテストを追加してください。',
        'Confirm the license, usage and distribution conditions against the customer policy.'=>'ライセンスと利用・配布条件を確認し、顧客のポリシーに照らして判断してください。',
        'Regenerate the SBOM with complete package URLs and versions.'=>'パッケージURLとバージョンを含むSBOMを再生成してください。',
        'Review the advisory and package version manually.'=>'脆弱性情報とパッケージのバージョンを個別に確認してください。',
        'Fix syntax or provide readable PHP source and repeat the assessment.'=>'構文を修正するか読み込み可能なPHPソースを指定し、再検査してください。',
    ];
    private function __construct(private readonly bool $ja) {}
    private function t(string $en, string $ja): string { return $this->ja ? $ja : $en; }
    private function local(string $text): string { return $this->ja ? (self::TRANSLATIONS[$text] ?? $text) : $text; }
    private function status(string $s): string
    {
        return $this->ja ? (['affected'=>'脆弱性該当','matched'=>'脆弱性該当','no-match'=>'照合なし','unassessed'=>'未判定','review'=>'要確認','denied'=>'ポリシー違反'][$s] ?? $s) : $s;
    }
    public static function reportId(array $r): string { return 'SL-'.strtoupper(substr(hash('sha256', $r['sbomSha256'].'|'.$r['database']['sha256'].'|'.$r['createdAt']), 0, 12)); }
    public static function write(array $report, string $path, string $language = 'en', string $style = 'standard', string $issuer = ''): void
    {
        if (!in_array($language, ['en','ja'], true) || !in_array($style, ['standard','customer'], true)) { throw new \InvalidArgumentException('Invalid report language or style'); }
        (new self($language === 'ja'))->build($report, $path, $style === 'customer', $issuer);
    }
    private function build(array $r, string $path, bool $customer, string $issuer): void
    {
        Settings::setOutputEscapingEnabled(true);
        $word = new PhpWord(); $font = $this->ja ? 'Noto Sans JP' : 'Arial';
        $word->setDefaultFontName($font); $word->setDefaultFontSize(10.5);
        $word->setDefaultParagraphStyle(['spaceAfter'=>100,'lineHeight'=>1.15]);
        $word->addTitleStyle(0, ['name'=>$font,'size'=>18,'bold'=>true,'color'=>'000000'], ['spaceAfter'=>180,'keepNext'=>true]);
        $word->addTitleStyle(1, ['name'=>$font,'size'=>14,'bold'=>true,'color'=>'000000'], ['spaceBefore'=>180,'spaceAfter'=>140,'keepNext'=>true]);
        $word->addTitleStyle(2, ['name'=>$font,'size'=>11.5,'bold'=>true,'color'=>'000000'], ['spaceBefore'=>160,'spaceAfter'=>80,'keepNext'=>true]);
        $word->addParagraphStyle('SectionHeading', ['basedOn'=>'Heading1','outlineLevel'=>0,'pageBreakBefore'=>true,'keepNext'=>true,'spaceBefore'=>180,'spaceAfter'=>140]);
        $word->getDocInfo()->setCreator($issuer ?: 'SecuLens');
        $word->getDocInfo()->setTitle('Software Security Assessment Report');
        $word->getSettings()->setThemeFontLang(new \PhpOffice\PhpWord\Style\Language($this->ja ? 'ja-JP' : 'en-US'));
        $page = ['pageSizeW'=>11906,'pageSizeH'=>16838,'marginTop'=>1134,'marginBottom'=>1134,'marginLeft'=>1134,'marginRight'=>1134,'headerHeight'=>400,'footerHeight'=>500];
        $s = $word->addSection($page);
        $findings = $r['findings'];
        usort($findings, static fn(array $a, array $b): int => [array_search($a['category'], array_keys(self::CATEGORIES), true),array_search($a['severity']['level'] ?? 'unknown', Severity::LEVELS, true),$a['subject'],$a['ruleId'],$a['line'] ?? 0] <=> [array_search($b['category'], array_keys(self::CATEGORIES), true),array_search($b['severity']['level'] ?? 'unknown', Severity::LEVELS, true),$b['subject'],$b['ruleId'],$b['line'] ?? 0]);
        if ($customer) {
            $s->addText('SecuLens', ['size'=>28,'bold'=>true,'color'=>'000000'], ['spaceBefore'=>1400,'spaceAfter'=>280]);
            $s->addTitle($this->t('Software Security Assessment Report','ソフトウェアセキュリティ評価報告書'), 0);
            $s->addText($this->t('Vulnerability and license assessment with code review','脆弱性とライセンスの評価およびコード確認'));
            $s->addText($r['customer'].$this->t('',' 御中'), ['bold'=>true], ['spaceBefore'=>700,'spaceAfter'=>180]);
            foreach ([$this->t('Target','検査対象')=>$r['target'],$this->t('Assessment time','検査日時')=>$r['createdAt'],$this->t('Report ID','報告書ID')=>self::reportId($r)] as $label=>$value) { $s->addText($label.'  '.$value); }
            if ($issuer !== '') { $s->addText($this->t('Prepared by','作成者').'  '.$issuer); }
            $s->addText('SecuLens '.$r['tool']['version']);
            $s->addText($this->t('This report summarizes advisory matching, license policy evaluation and any PHP code checks performed. Use the findings and evidence to decide follow-up actions.','本報告書は、脆弱性情報との照合、ライセンスポリシー評価、実施したPHPコード検査の結果をまとめたものです。指摘と根拠を参照し、対応方針を決定してください。'), null, ['spaceBefore'=>600]);
            $s = $word->addSection($page + ['breakType'=>'nextPage']);
        } else { $s->addTitle($this->t('Software Security Assessment Report','ソフトウェアセキュリティ評価報告書'),0); $s->addText($r['customer'].' | '.$r['target'].' | '.$r['createdAt']); }
        $s->addFooter()->addPreserveText('SecuLens | '.self::reportId($r).' | {PAGE} / {NUMPAGES}', ['size'=>8,'color'=>'000000'], ['alignment'=>'right']);
        $s->addTitle($this->t('1 Assessment Summary','1 検査結果の要約'), 1);
        $vulns = array_values(array_filter($findings, static fn(array $f): bool => $f['category'] === 'vulnerability'));
        $unassessed = count(array_filter($r['checks'], static fn(array $c): bool => $c['status'] === 'unassessed'));
        $urgent = count(array_filter($vulns, static fn(array $f): bool => in_array($f['severity']['level'] ?? 'unknown', ['critical','high'], true)));
        $s->addText($this->t('Assessed '.count($r['sbom']['components'])." components with ".count($vulns)." vulnerability findings. $unassessed components have incomplete vulnerability assessments. Counts consolidate advisory aliases per component.", '構成部品'.count($r['sbom']['components']).'件を照合し、'.count($vulns)."件の脆弱性指摘を検出しました。脆弱性照合が未判定の構成部品は{$unassessed}件です。件数は同一部品内の別名IDを統合した値です。"));
        $s->addText($this->t("$urgent findings are Critical or High. Review available fixes and deployment context first. Unrated findings also require severity review.","重大または高の指摘は{$urgent}件です。優先して修正情報と利用状況を確認してください。未評価の指摘も重要度の確認が必要です。"));
        $rows = [[$this->t('Severity','重要度'),$this->t('Count','件数'),$this->t('Review guidance','確認方針')]]; $marks = [];
        foreach (Severity::LEVELS as $level) {
            $rows[] = [self::PALETTE[$level][$this->ja ? 1 : 0],(string) count(array_filter($vulns, static fn(array $f): bool => ($f['severity']['level'] ?? 'unknown') === $level)),in_array($level,['critical','high'],true) ? $this->t('Prioritize fixes and impact review','優先して修正情報と影響を確認') : $this->t('Review evidence and plan follow-up','根拠と対応方針を確認')];
            $marks[count($rows)-1] = [0,$level];
        }
        $this->table($s,$rows,[30,20,120],$marks);
        $s->addText($this->t('Severity uses CVSS 3.0/3.1 base scores or database labels. CVSS 2/4 vectors are retained but not calculated. Severity does not establish exploitability or business impact.','重要度はCVSS 3.0／3.1基本値またはDBのラベルに基づきます。CVSS 2／4は保存しますが計算しません。顧客環境での悪用可能性や事業影響を確定するものではありません。'));
        $rows = [[$this->t('Category','分類'),$this->t('Count','件数')]];
        foreach (self::CATEGORIES as $cat=>$labels) { $rows[] = [$labels[$this->ja ? 1 : 0],(string) count(array_filter($findings, static fn(array $f): bool => $f['category'] === $cat))]; }
        $this->table($s,$rows,[140,30]);
        if ($customer) { $s->addText($this->t('2 Findings Register','2 指摘事項の一覧'),['size'=>14,'bold'=>true,'color'=>'000000'],'SectionHeading'); }
        else { $s->addTitle($this->t('2 Findings Register','2 指摘事項の一覧'),1); }
        $s->addText($this->t('Finding numbers correspond to the details below. Code and license review states are distinct from vulnerability severity.','番号は後続の詳細と対応します。コードとライセンスの確認状態は脆弱性の重要度と区別して記載します。'));
        $rows = [[$this->t('No.','番号'),$this->t('Severity or status','重要度／状態'),$this->t('Category','分類'),$this->t('Subject and finding','対象と指摘')]]; $marks = [];
        foreach ($findings as $i=>$f) {
            $rows[] = [sprintf('F-%03d',$i+1),$this->findingLabel($f),self::CATEGORIES[$f['category']][$this->ja ? 1 : 0],$this->subject($r,$f)."\n".$f['ruleId']];
            if ($f['category'] === 'vulnerability') { $marks[$i+1] = [1,$f['severity']['level'] ?? 'unknown']; }
        }
        if ($findings) { $this->table($s,$rows,[18,28,28,96],$marks); }
        else { $s->addText($this->t('No findings recorded. Review coverage and limitations as well.','指摘事項はありません。検査範囲と制約もご確認ください。')); }
        if ($customer) { $s->addText($this->t('3 Finding Details','3 指摘事項の詳細'),['size'=>14,'bold'=>true,'color'=>'000000'],'SectionHeading'); }
        else { $s->addTitle($this->t('3 Finding Details','3 指摘事項の詳細'),1); }
        foreach ($findings as $i=>$f) {
            $s->addTitle(sprintf('F-%03d',$i+1).' '.$f['ruleId'],2);
            $s->addText($this->subject($r,$f).' | '.$this->status($f['status']),['bold'=>true],['keepNext'=>true]);
            $s->addText($this->local($f['summary']),null,['keepNext'=>true]);
            if ($f['category'] === 'vulnerability') {
                $severity = $f['severity'] ?? ['level'=>'unknown','sources'=>[]];
                $s->addText($this->t('Severity','重要度').'  '.$this->findingLabel($f).(isset($severity['score']) ? ' | CVSS 3 '.number_format($severity['score'],1) : ''),['bold'=>true,'color'=>self::PALETTE[$severity['level']][2]]);
                foreach ($severity['sources'] as $source) { $s->addText($source['recordId'].' | '.$source['field'].' | '.(isset($source['score']) ? 'CVSS 3 '.number_format($source['score'],1) : $source['type'].': '.$source['value']),['size'=>9]); }
                if (!$severity['sources']) { $s->addText($this->t('No usable severity metadata available. Review the advisory references.','重要度を判定できるDB情報がありません。参照先で確認してください。')); }
            }
            $s->addText($this->t('Evidence','根拠').'  '.$f['evidence'],null,['keepNext'=>true]);
            $s->addText($this->t('Recommendation','推奨対応').'  '.$this->local($f['recommendation']));
            foreach ($f['references'] ?? [] as $url) {
                if (filter_var($url, FILTER_VALIDATE_URL) && in_array(strtolower(parse_url($url, PHP_URL_SCHEME) ?? ''), ['http','https'], true)) { $s->addLink($url,$url,['color'=>'0563C1','size'=>9]); }
                else { $s->addText($url,['size'=>9]); }
            }
        }
        if ($customer) { $s->addText($this->t('4 Component Assessment Coverage','4 構成部品の評価状況'),['size'=>14,'bold'=>true,'color'=>'000000'],'SectionHeading'); }
        else { $s->addTitle($this->t('4 Component Assessment Coverage','4 構成部品の評価状況'),1); }
        $rows = [[$this->t('Component','構成部品'),$this->t('Version','バージョン'),$this->t('Assessment','照合結果'),$this->t('Licenses','ライセンス')]];
        foreach ($r['sbom']['components'] as $c) {
            $check = array_values(array_filter($r['checks'], static fn(array $check): bool => $check['componentId'] === $c['id']))[0] ?? [];
            $rows[] = [$c['name'],$c['version'] ?? 'unknown',$this->status($check['status'] ?? 'unassessed'),implode('; ',$c['licenses']) ?: $this->t('Unknown','不明')];
        }
        $this->table($s,$rows,[65,25,30,50]);
        $s->addTitle($this->t('5 Evidence and Limitations','5 検査の根拠と制約'),1);
        if (isset($r['sourceAnalysis'])) { $s->addText($this->t('Source analysis','コード検査').' '.$r['sourceAnalysis']['language'].' | '.$r['sourceAnalysis']['target']); }
        else { $s->addText($this->t('Source analysis was not performed.','コード検査は実施していません。')); }
        $s->addText($this->t('Full severity metadata and references are preserved in the accompanying JSON report.','重要度の原データと全参照先は同梱のJSON報告書に保存しています。'));
        foreach ([$r['sbom']['format'].' '.$r['sbom']['version'],'DB '.$r['database']['source'],'SBOM SHA256 '.$r['sbomSha256'],'DB SHA256 '.$r['database']['sha256']] as $text) { $s->addText($text,['size'=>9]); }
        foreach ([...$r['limitations'],...$r['sbom']['warnings']] as $text) { $s->addText($this->local($text)); }
        IOFactory::createWriter($word,'Word2007')->save($path);
        if ($this->ja) { FontEmbedder::embed($path); }
    }
    private function findingLabel(array $f): string
    {
        return $f['category'] === 'vulnerability' ? self::PALETTE[$f['severity']['level'] ?? 'unknown'][$this->ja ? 1 : 0] : $this->status($f['status']);
    }
    private function subject(array $r,array $f): string
    {
        foreach ($r['sbom']['components'] as $c) { if ($c['id'] === $f['subject']) { return $c['name'].'@'.($c['version'] ?? 'unknown'); } }
        return $f['subject'].(isset($f['line']) ? ':'.$f['line'] : '');
    }
    private function table(Section $s,array $rows,array $widths,array $marks=[]): void
    {
        $table = $s->addTable(['borderSize'=>4,'borderColor'=>'D9D9D9','cellMarginTop'=>90,'cellMarginBottom'=>90,'cellMarginLeft'=>90,'cellMarginRight'=>90,'layout'=>'fixed','width'=>9638,'unit'=>'dxa']);
        foreach ($rows as $i=>$row) {
            $table->addRow(null,['tblHeader'=>$i===0,'cantSplit'=>true]);
            foreach ($row as $j=>$text) {
                $fill = $i===0 ? 'E7EDF3' : ($i%2 ? 'FFFFFF' : 'F8FAFC'); $color = '000000'; $bold = $i===0;
                if (isset($marks[$i]) && $marks[$i][0] === $j) { $p = self::PALETTE[$marks[$i][1]]; $fill=$p[3]; $color=$p[2]; $bold=true; }
                $cell = $table->addCell((int) round($widths[$j]*56.69),['bgColor'=>$fill,'valign'=>'center']);
                foreach (explode("\n",(string)$text) as $line) { $cell->addText($line,['size'=>9,'bold'=>$bold,'color'=>$color],['spaceAfter'=>40,'spaceBefore'=>40,'alignment'=>$widths[$j]<=30 ? 'center' : 'left','keepNext'=>false]); }
            }
        }
        $s->addTextBreak(1,['size'=>2],['spaceAfter'=>40]);
    }
}
