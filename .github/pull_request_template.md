## 何を変えたか

## なぜ

## 確認したこと
- [ ] バックエンドのテスト: `VULNIX_NO_ENV_LOCAL=1 python3 -m unittest discover -s tests -p "test_*.py"`
- [ ] Web UI: `cd web && npm test && npm run lint && npm run build`
- [ ] 画面を変えた場合は、ブラウザで表示を確認した（スクリーンショットを添付）
- [ ] 新しい API ルートを追加した場合は、他の組織から読めない・操作できないことを `tests/test_tenancy.py` に追加した

## 安全への影響
- [ ] 所有確認・診断範囲・L2 承認・隔離・緊急停止・監査・組織間の分離を弱めていない（弱める場合は理由と代わりの対策を書く）
- [ ] 秘密情報・実在のホスト名・有料 API の呼び出しを含めていない
