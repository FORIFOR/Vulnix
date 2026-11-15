// Public landing page. Static content only: it calls no API and shows no data from
// the control plane, so it is safe to serve through a public tunnel.

const FEATURES = [
  { icon: "◆", title: "公開ページの設定を確認", body: "所有を確認したサイトの公開ページを1回読み、設定と応答を確認します。現在、実サイト向けのARTEX計画は行いません。" },
  { icon: "✓", title: "追加の検証は承認制", body: "模擬ラボで脆弱性の成立を確かめる検証は、承認されたものだけが動きます。公開版の実サイトでは実行しません。" },
  { icon: "▣", title: "検証処理を隔離", body: "模擬ラボの検証処理は許可した範囲に限定されます。Linux環境ではカーネルによる隔離も適用します。" },
  { icon: "≡", title: "推測と実測を区別", body: "未計測の候補、設定の検出、脆弱性の実証を分け、根拠となる証拠を記録します。" },
  { icon: "あ", title: "結果を日本語で説明", body: "公開版の実サイトでは内蔵の解説機能で、確認できたことと未確認のことを説明します。" },
  { icon: "■", title: "いつでも緊急停止", body: "ワンクリックで新しい操作を止め、権限を失効させ、実行中の処理の終了まで確認します。" },
];

const STEPS = [
  { n: "1", title: "URLを入力", body: "診断したい自分のサイトを登録します。" },
  { n: "2", title: "所有を確認", body: "DNS の記録、サイトに置くファイル、または対応している場合はGoogleで確認します。" },
  { n: "3", title: "診断を開始", body: "公開ページを1回読み、設定を確認します。" },
  { n: "4", title: "結果を見る", body: "確認できた設定、根拠、対策、未確認の項目を確認します。" },
];

const PRINCIPLES = [
  "所有確認が済んだサイトだけを診断します。他人のサイトは診断できません。",
  "検出（L1）と実証（L2）を混同しません。実証していない問題を「脆弱性がある」と断定しません。",
  "実在するサービスの応答本文・認証情報・個人情報を外部の AI に送りません。",
  "AI の提案から直接、検証を実行することはありません。実行の権限は Gateway だけが持ちます。",
];

export function Landing({ app = false }: { app?: boolean }) {
  return (
    <div className="min-h-dvh bg-white text-zinc-900">
      <header className="sticky top-0 z-10 border-b border-zinc-100 bg-white/85 backdrop-blur">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-4 py-3 sm:px-6">
          <a href="#top" className="flex items-center gap-2.5">
            <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-zinc-900 text-sm font-bold text-white">V</span>
            <span className="font-semibold tracking-tight">Vulnix</span>
            <span className="rounded-full border border-zinc-200 px-2 py-0.5 text-[11px] text-zinc-500">{app ? "公開β" : "クローズドβ"}</span>
          </a>
          <nav className="hidden gap-6 text-sm text-zinc-600 sm:flex">
            <a href="#features" className="hover:text-zinc-900">特長</a>
            <a href="#how" className="hover:text-zinc-900">仕組み</a>
            <a href="#safety" className="hover:text-zinc-900">安全への取り組み</a>
            <a href="#beta" className="hover:text-zinc-900">β版について</a>
            {app && <a href="/login" className="font-semibold text-zinc-900 hover:underline">ログイン</a>}
          </nav>
        </div>
      </header>

      <main id="top">
        <section className="mx-auto grid max-w-6xl items-center gap-10 px-4 pb-16 pt-14 sm:px-6 md:grid-cols-2 md:pt-20">
          <div>
            <p className="mb-4 text-sm font-medium tracking-wide text-zinc-500">AI セキュリティ診断サービス</p>
            <h1 className="text-4xl font-bold leading-tight tracking-tight sm:text-5xl">
              AI が考え、<br />人が承認し、<br />証拠で示す。
            </h1>
            <p className="mt-6 text-base leading-relaxed text-zinc-600 sm:text-lg">
              Vulnix は、AI が検証計画を立て、人の承認と隔離された環境のもとで安全に確かめ、
              結果を日本語でわかりやすく説明する Web セキュリティ診断サービスです。
            </p>
            <div className="mt-8 flex flex-wrap gap-3">
              {app ? (
                <>
                  <a href="/login" className="rounded-lg bg-zinc-900 px-5 py-2.5 text-sm font-semibold text-white hover:bg-zinc-700">無料で始める</a>
                  <a href="#demo" className="rounded-lg border border-zinc-300 px-5 py-2.5 text-sm font-semibold text-zinc-800 hover:bg-zinc-50">デモ動画を見る</a>
                </>
              ) : (
                <>
                  <a href="#demo" className="rounded-lg bg-zinc-900 px-5 py-2.5 text-sm font-semibold text-white hover:bg-zinc-700">デモ動画を見る</a>
                  <a href="#beta" className="rounded-lg border border-zinc-300 px-5 py-2.5 text-sm font-semibold text-zinc-800 hover:bg-zinc-50">β版の利用について</a>
                </>
              )}
            </div>
          </div>
          <div id="demo" className="scroll-mt-24 overflow-hidden rounded-2xl border border-zinc-200 shadow-[0_20px_60px_-20px_rgba(0,0,0,0.25)]">
            <video className="block aspect-video w-full bg-zinc-950" src="/media/vulnix-ad.mp4" poster="/media/vulnix-ad-poster.jpg"
              controls playsInline preload="metadata" />
          </div>
        </section>

        <section id="features" className="scroll-mt-20 border-t border-zinc-100 bg-zinc-50/60">
          <div className="mx-auto max-w-6xl px-4 py-16 sm:px-6">
            <h2 className="text-2xl font-bold tracking-tight sm:text-3xl">安全に、確かめて、わかりやすく。</h2>
            <div className="mt-10 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
              {FEATURES.map((f) => (
                <div key={f.title} className="rounded-xl border border-zinc-200 bg-white p-6">
                  <div className="mb-3 flex h-9 w-9 items-center justify-center rounded-lg bg-zinc-900 text-sm text-white">{f.icon}</div>
                  <h3 className="font-semibold">{f.title}</h3>
                  <p className="mt-2 text-sm leading-relaxed text-zinc-600">{f.body}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section id="how" className="scroll-mt-20">
          <div className="mx-auto max-w-6xl px-4 py-16 sm:px-6">
            <h2 className="text-2xl font-bold tracking-tight sm:text-3xl">診断の流れ</h2>
            <ol className="mt-10 grid gap-4 md:grid-cols-5">
              {STEPS.map((s) => (
                <li key={s.n} className="rounded-xl border border-zinc-200 p-5">
                  <span className="text-xs font-semibold text-zinc-400">STEP {s.n}</span>
                  <h3 className="mt-1 font-semibold">{s.title}</h3>
                  <p className="mt-2 text-sm leading-relaxed text-zinc-600">{s.body}</p>
                </li>
              ))}
            </ol>
            <div className="mt-12 grid gap-6 md:grid-cols-2">
              <figure className="overflow-hidden rounded-xl border border-zinc-200">
                <img src="/media/shot-evidence.png" alt="問題の詳細画面：証拠・危険性・修正方法" className="block w-full" loading="lazy" />
                <figcaption className="border-t border-zinc-100 px-4 py-3 text-sm text-zinc-600">問題ごとに、証拠・危険性・修正方法・修正後の確認方法を表示します。</figcaption>
              </figure>
              <figure className="overflow-hidden rounded-xl border border-zinc-200">
                <img src="/media/shot-ai-explanation.png" alt="AI による日本語の解説" className="block w-full" loading="lazy" />
                <figcaption className="border-t border-zinc-100 px-4 py-3 text-sm text-zinc-600">AI の解説には、判定（未実証かどうか）を Vulnix が必ず添えます。</figcaption>
              </figure>
            </div>
          </div>
        </section>

        <section id="safety" className="scroll-mt-20 border-t border-zinc-100 bg-zinc-50/60">
          <div className="mx-auto max-w-6xl px-4 py-16 sm:px-6">
            <h2 className="text-2xl font-bold tracking-tight sm:text-3xl">安全への取り組み</h2>
            <ul className="mt-8 grid gap-3 md:grid-cols-2">
              {PRINCIPLES.map((t) => (
                <li key={t} className="flex gap-3 rounded-xl border border-zinc-200 bg-white p-5 text-sm leading-relaxed text-zinc-700">
                  <span className="mt-0.5 text-zinc-900">✓</span>
                  <span>{t}</span>
                </li>
              ))}
            </ul>
          </div>
        </section>

        <section id="beta" className="scroll-mt-20">
          <div className="mx-auto max-w-3xl px-4 py-16 text-center sm:px-6">
            <h2 className="text-2xl font-bold tracking-tight sm:text-3xl">β版について</h2>
            {app ? (
              <>
                <p className="mt-5 leading-relaxed text-zinc-600">
                  どなたでもアカウントを作り、自分の組織とサイトを登録して、模擬ラボで診断の流れ・証拠・AI の解説を試せます。
                  チームのメンバーを招待して、役割（実行者・承認者・閲覧者など）を分けることもできます。
                </p>
                <p className="mt-3 text-sm leading-relaxed text-zinc-500">
                  β版では、実在のサイトへの通信（所有確認の実行・診断）はまだ有効にしていません。サイトの登録と、所有確認に使う値の発行までお試しいただけます。
                </p>
                <a href="/login" className="mt-6 inline-block rounded-lg bg-zinc-900 px-6 py-2.5 text-sm font-semibold text-white hover:bg-zinc-700">アカウントを作成する</a>
              </>
            ) : (
              <p className="mt-5 leading-relaxed text-zinc-600">
                Vulnix は現在、限られた参加者だけが使えるクローズドβです。
                一般の方が自分のサイトを登録して診断できる機能は、認証と利用者ごとのデータ分離の検証が終わってから公開します。
                このページから診断を始めることはできません。
              </p>
            )}
          </div>
        </section>
      </main>

      <footer className="border-t border-zinc-100">
        <div className="mx-auto max-w-6xl px-4 py-8 text-xs leading-relaxed text-zinc-500 sm:px-6">
          <p>© Vulnix — Find. Prove. Secure.</p>
          <p className="mt-1">動画と画面は、ローカルの模擬ラボで実際に動かしたときの録画です。実在サービスの診断結果ではありません。</p>
          <p className="mt-1">公開版の実サイト診断は読み取り専用です。ARTEXと外部AIを使用した実サイト診断は提供していません。</p>
        </div>
      </footer>
    </div>
  );
}
