# pentest

Goからnmapを実行し、結果を使ってOpenAIが次に調べるポートを判断するCLI。
対象は自分の `127.0.0.1` に固定しています。

初期化から現在の設計に至る経緯は [実装フロー](docs/implementation-flow.md) にまとめています。

## Dockerで実行

Goとnmapのビルド・テスト・実行はDocker内で行います。
ホストへの追加インストールは不要です。

```sh
docker build -t pentest-nmap .
```

## Norma SDKのワークフロー（通常モード）

`.env` の `OPENAI_API_KEY` にAPIキーを設定してください。
モデルは `.env` の `OPENAI_MODEL` で指定します。`.env` はGitとDockerビルドの対象外です。
`OPENAI_MODEL` にはResponses APIのツール呼び出し対応モデルを指定します。
APIキーをDockerfileやソースに書く必要はありません。

LinuxでホストPCを調べる例：

```sh
docker run --rm --network host --env-file .env \
  pentest-nmap --agent 'HTTP用の別ポートを確認して' --ports 8080,8443
```

1. `agentcore.Session.Prompt` に調査目的を渡します。
2. OpenAIが `scan_ports` をツール呼び出しします。引数は `reason` と `ports` です。
3. Goで入力を検証し、nmapを実行します。
4. SDKがツール結果と会話履歴をOpenAIへ返し、次の判断を求めます。
5. AIが最終回答を返しても、Goが必須ポートの結果を照合します。すべて確定した場合だけ `finish` を出力します。

```json
{"reason":"HTTP用の別ポートを確認したい","ports":[8080,8443]}
```

SDKへ登録するツール名が `scan_ports` なので、引数内の `action` は不要です。
各スキャンの出力は従来どおり `step`、`action`、`result` を含みます。
完了時は `finish` のアクションと、その `reason` による要約を出力します。

Normaは `github.com/Autumn-27/norma` のコミット `4f5684e56760` に固定しています。

## 必須ポートと完了判定

エージェント実行では `--ports` が必須です。自然文から必須ポートを推測せず、
Goが受け取った番号を検査要求として保持します（1〜100件、重複はまとめます）。
指定形式は `--agent 調査目的 --ports 8080,8443`、または `--scratch 調査目的 --ports 8080,8443` です。

要求と各ポートの結果は実行中のメモリに保持します。対象のスキャンに含まれていたTCPポートの
`open` または `closed` の結果がすべて揃うことが、成功終了の条件です。
結果の欠落、UDPの結果、`filtered` などの未確定状態、失敗・タイムアウトは完了扱いにしません。

Norma版はStopフックで終了を保留し、未確定ポートをAIへ返します。
AIが検査せず再び終了してSDKが停止した場合も、終了後の照合で未完了エラーになります。
スクラッチ版は毎回 `required_ports`・`pending_ports`・`history` をAIに渡し、
未確定ポートがある `finish` は受け付けず、拒否理由も `feedback` として渡して判断上限まで続けます。
どちらも未完了のまま終了した場合は成功の `finish` を出さず、終了コード1になります。

結果保持は1回の実行内だけです。プロセス終了で失われ、再開・永続化はしません。

## スクラッチ版との比較

比較用に以前の実装も残しています。同じ目的で実行できます。

```sh
docker run --rm --network host --env-file .env \
  pentest-nmap --scratch 'HTTP用の別ポートを確認して' --ports 8080,8443
```

| 担当 | Norma版 `--agent` | スクラッチ版 `--scratch` |
|---|---|---|
| 実装 | `internal/infrastructure/norma/workflow.go` | `internal/infrastructure/openai/client.go` と `internal/application/scan.go` |
| API通信・応答解析 | SDKのResponsesプロバイダー | 標準ライブラリのHTTPとJSONで実装 |
| 次の動作 | OpenAIのツール呼び出し | Structured Outputsの `action` を解釈 |
| 会話履歴・結果の引き渡し | Sessionが保持・送信 | Observationを蓄積して毎回送信 |
| 完了 | 終了フックとSDK終了後に必須ポートを照合 | AIの `finish` を受けた時に必須ポートを照合 |
| 上限 | 10ツールターン・合計10スキャン | 完了を含む10回の判断 |
| ツールの入力・実行エラー | SDKがエラーをAIへ返し、上限内で修正可能 | 即終了 |
| 依存 | Normaとその間接依存 | エージェント部分は標準ライブラリのみ |

スクラッチ版では、以下のJSONを解析するループを自分で持ちます。

```json
{"reason":"HTTP用の別ポートを確認したい","action":"scan_ports","ports":[8080,8443]}
```

流れは `Decide(必須・未確定ポート、履歴) → validate → scan → 結果を保持 → Decide` です。
ポートを調べるだけなら十分小さく書けますが、ツールを増やすと、呼び出しIDと結果の対応、
並列処理、会話の圧縮やストリーム処理なども必要に応じて自分で実装・テストすることになります。
Norma版はそれらをSDKへ任せる構成です。今回の1ツールでは、登録・検証のコードもあるため、
SDKを入れただけで大幅に短くなるわけではありません。

## 実行範囲

両方式とも1回100ポートまで、番号は1〜65535です。
nmapは `-sT -Pn -n` 固定で、1回30秒、CLI全体は5分で打ち切ります。
API通信の再試行は無効です。Norma版ではSDKの回復処理やツールエラーからの修正が別途働きます。
Normaへ登録するのは `scan_ports` のみで、既定のシェル・ファイル・バックグラウンド用ツールは有効にしません。
AIは対象ホストやnmap引数、シェルコマンドを指定できません。
APIキーはイメージに含めず実行時に渡し、SDKを含むAPIのエラー本文はログに出しません。
調査目的とスキャン結果はOpenAIへ送信され、API利用料金が発生します。

## AIを使わない固定スキャン

TCPポート `22,80,443,8080` を調べ、XML結果をJSONで出力します。

```sh
docker run --rm --network host pentest-nmap 127.0.0.1
```

`--network host` を省略するとコンテナ自身が対象になります。
JSONにはopen以外の状態も含まれます。UDPや外部からの到達性は調べません。
サービス名はnmapのポート名であり、稼働サービスの確定情報ではありません。
モジュール名は仮に `pentest` としています。

API仕様：[OpenAI公式ドキュメント — Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs)

SDK仕様：[Norma公式リポジトリ](https://github.com/Autumn-27/Norma/tree/4f5684e567607ade605320100ec118056ab38155)

## コード構成（DDDの責務分離）

```text
cmd/pentest/                       起動、環境変数、全体の制限時間
internal/
  domain/portscan/                  ポート・検査結果・アクションと制約
  application/                     Scannerの契約、スキャン回数管理、スクラッチの実行手順
  infrastructure/
    nmap/                          nmap起動、XMLの解析とドメインモデルへの変換
    openai/                        スクラッチ用のOpenAI API通信と応答解析
    norma/                         SDKのSessionとscan_portsの接続
  interfaces/cli/                  引数検証、依存の組み立て、JSON出力
```

ドメインは外部API・XML・Norma SDK・コマンド実行に依存しません。
アプリケーションも具体的なスキャナーを知らず、自分で定義した `Scanner` 契約を使います。
両エージェントは `ScanSession.Execute` を通り、同じ入力検証・回数制限を適用します。
外部形式のnmap XMLはアダプター内に閉じ込めています。スキャン結果と `finish` のJSON形式は従来どおりです。
保存処理がないため、Repositoryや永続化層は追加していません。

テストは各パッケージに配置しています。ドメイン・アプリケーションのテストは
nmapやAPIを使わず実行でき、アダプターのテストは模擬API・模擬コマンドで接続を検証します。
Dockerビルド時に `go test ./...` と `go build ./cmd/pentest` を実行します。
ホストにGoがある場合の起動先は `go run ./cmd/pentest 127.0.0.1` です。
