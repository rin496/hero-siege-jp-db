# Hero Siege 日本語DB v0.3

## v0.3
- 24クラスを登録
- 各クラス18スキル、合計432スキルを登録
- クラス詳細ダイアログ
- 全スキル検索 / クラス絞り込み
- グローバル検索
- Angelic Augmentの確認済みサンプルを6件登録
- S9を現行、S10を未稼働として表示
- 日本語訳の「暫定 / 翻訳待ち」を明示
- 出典ページをサイト内に追加
- Vercel向け静的サイト構成

## 更新方法
基本データは `data.json` にあります。

スキルの日本語訳が確認できたら:
- `nameJa` を入力
- `translationStatus` を `verified` に変更

S10事前情報を追加する場合:
- `season`: `S10`
- `status`: `preview`
として、S9実装済みデータと混ぜないでください。

## ローカル起動
```bash
python -m http.server 8000
```

## 主なデータソース
- Hero Siege Steam News
- Hero Siege Helper
- Official Hero Siege Wiki
