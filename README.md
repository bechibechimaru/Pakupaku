# 1. Pakupakuについて

大学生向けの飲食店共有プラットフォーム「Pakupaku」は、学生同士が新しい環境で飲食店を見つけるのに役立つアプリケーションです。学生が限られた休憩時間内で予算に合ったお店を見つけられるように、先輩や友人のおすすめを共有する場として開発されました。

## 2. URL

```text
https://pakupaku.paiza-user-basic.cloud:8080/signup
```

## 3. 使用技術

### フロントエンド

- **HTML**: コンテンツ構造の作成に使用
- **CSS**: スタイリングとレイアウト
  - **Flexbox** と **Media Queries** によるレスポンシブデザイン
  - ハンバーガーメニュー、投稿フォーム、ナビゲーションメニューのカスタムデザイン
- **JavaScript**
  - **DOM操作**と**Fetch API**を活用して、ユーザーインタラクションとデータの非同期取得を実現
  - 入力補完機能とバリデーション（パスワード確認機能）を実装
- **テンプレートエンジン**: Goのテンプレートエンジン
  - サーバーサイドでデータをHTMLに埋め込み、動的な表示を可能にするために使用

フロントエンドでは、モバイルとデスクトップの両方に適したインターフェースと、学生が使いやすいシンプルで機能的なデザインを実現しています。

### バックエンド

- **プログラミング言語**: Go (Golang)
  - 主にWebサーバーとAPIの作成に使用
- **フレームワーク**:
  - 標準パッケージ（`net/http`, `database/sql`など）を活用
- **データベース**: MySQL
  - ユーザーや投稿データを保存
  - 使用パッケージ: `github.com/go-sql-driver/mysql`
- **セッション管理**: `github.com/gorilla/sessions`
  - Cookieベースのセッション管理を採用
- **環境変数管理**: `github.com/joho/godotenv`
  - `.env`ファイルからデータベース接続情報などの機密情報を読み込み
- **パスワード暗号化**: `golang.org/x/crypto/bcrypt`
  - ユーザーのパスワードをハッシュ化して安全に保存

### データベース

- MySQL

### インフラ/ホスティング

- PaizaCloud

## 4. 主な機能

1. **ユーザー登録**
   - 大学とキャンパスを入力時に候補表示し選択可能
   - 所属大学・キャンパス情報を登録

2. **ログイン機能**
   - 登録したユーザーがログインし、利用可能

3. **飲食店共有機能**
   - おすすめ飲食店を投稿し、キャンパスの仲間と共有
   - 登録情報：
     - レストラン名
     - 住所
     - カテゴリー
     - 距離
     - 混雑具合
     - 提供スピード
     - 美味しさ
     - 金額
     - グループ対応可否
     - 詳細メモ ※任意

4. **掲示板機能**
   - キャンパス単位でメンバーが自由に会話や情報交換が可能

## 5. ページ構成

- **サインアップ画面**：ユーザー登録
- **確認画面**：登録内容の確認
- **ログイン画面**：登録ユーザーのログイン
- **掲示板画面**：キャンパス単位で話せる掲示板
  - メニューバー（掲示板遷移ボタン、おすすめリストボタン、プロフィールボタン）
- **おすすめリスト画面**：おすすめ飲食店の一覧
  - メニューバー（掲示板遷移ボタン、おすすめリストボタン、プロフィールボタン）
- **プロフィール画面**：
  - 自身の登録情報を表示

## 6. セットアップと使用方法

1. **インストール方法**
   - **依存関係**：このアプリはGoとMySQLを使用しています。各パッケージのインストールが必要です。
   - リポジトリをクローンします：

    ```bash
     git clone https://github.com/your-username/pakupaku.git
     ```

2. **環境設定**
   - データベースのセットアップ
   - 環境変数に接続情報を設定

3. **実行方法**
   - Goでサーバーを起動：

     ```bash
     go run main.go
     ```

   - ブラウザで`localhost:ポート番号`にアクセス
