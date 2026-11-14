// Public landing page. Static content only: it calls no API and shows no data from
// the control plane, so it is safe to serve through a public tunnel.

const FEATURES = [
  { icon: "◆", title: "本物の ARTEX が計画", body: "オープンソースの自律診断エンジン ARTEX が、検証の方向性を考えます。出せるのは「提案」だけで、実行の権限は持ちません。" },
  { icon: "✓", title: "危険な検証は承認制", body: "実際に攻撃が成立するかを確かめる検証（L2）は、対象と操作を確認した承認者が許可したものだけが動きます。" },
  { icon: "▣", title: "隔離された環境で実行", body: "ARTEX と検証 Worker は Linux の隔離環境で動き、通信先・時間・メモリ・プロセス数が制限されます。" },
  { icon: "≡", title: "推測ではなく証拠", body: "「検出（L1）」と「実証（L2）」をはっきり分け、判断の根拠になった証拠を改ざん検知つきの監査ログに残します。" },
  { icon: "あ", title: "AI が日本語で解説", body: "Abliteration AI が、何が問題か・危険性・修正方法・修正後の確認方法を、専門知識がなくても分かる言葉で説明します。" },
  { icon: "■", title: "いつでも緊急停止", body: "ワンクリックで新しい操作を止め、権限を失効させ、実行中の処理の終了まで確認します。" },
];

const STEPS = [
  { n: "1", title: "サイトを登録", body: "診断したい自分のサイトを登録します。" },
  { n: "2", title: "所有を確認", body: "DNS の TXT レコードか、サイトに置くファイルで、あなたが管理者であることを確かめます。" },
  { n: "3", title: "読み取りだけの診断（L1）", body: "公開設定やヘッダーなど、サイトに負荷をかけない観察から始めます。" },
  { n: "4", title: "必要なものだけ実証（L2）", body: "承認者が一件ずつ許可した検証だけを、隔離環境で非破壊に行います。" },
  { n: "5", title: "結果と直し方を確認", body: "証拠・危険性・修正方法・AI の解説を、ひとつの画面で確認できます。" },
];

const PRINCIPLES = [
  "所有確認が済んだサイトだけを診断します。他人のサイトは診断できません。",
  "検出（L1）と実証（L2）を混同しません。実証していない問題を「脆弱性がある」と断定しません。",
  "実在するサービスの応答本文・認証情報・個人情報を外部の AI に送りません。",
  "AI の提案から直接、検証を実行することはありません。実行の権限は Gateway だけが持ちます。",
];

export function Landing() {
  return (
    <div className="min-h-dvh bg-white text-zinc-900">
      <header className="sticky top-0 z-10 border-b border-zinc-100 bg-white/85 backdrop-blur">
        <div className="mx-auto flex max-w-6xl items-center justify-between px-4 py-3 sm:px-6">
          <a href="#top" className="flex items-center gap-2.5">
            <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-zinc-900 text-sm font-bold text-white">V</span>
            <span className="font-semibold tracking-tight">Vulnix</span>
            <span className="rounded-full border border-zinc-200 px-2 py-0.5 text-[11px] text-zinc-500">クローズドβ</span>
          </a>
          <nav className="hidden gap-6 text-sm text-zinc-600 sm:flex">
            <a href="#features" className="hover:text-zinc-900">特長</a>
            <a href="#how" className="hover:text-zinc-900">仕組み</a>
            <a href="#safety" className="hover:text-zinc-900">安全への取り組み</a>
            <a href="#beta" className="hover:text-zinc-900">β版について</a>
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
              <a href="#demo" className="rounded-lg bg-zinc-900 px-5 py-2.5 text-sm font-semibold text-white hover:bg-zinc-700">デモ動画を見る</a>
              <a href="#beta" className="rounded-lg border border-zinc-300 px-5 py-2.5 text-sm font-semibold text-zinc-800 hover:bg-zinc-50">β版の利用について</a>
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
            <p className="mt-5 leading-relaxed text-zinc-600">
              Vulnix は現在、限られた参加者だけが使えるクローズドβです。
              一般の方が自分のサイトを登録して診断できる機能は、認証と利用者ごとのデータ分離の検証が終わってから公開します。
              このページから診断を始めることはできません。
            </p>
          </div>
        </section>
      </main>

      <footer className="border-t border-zinc-100">
        <div className="mx-auto max-w-6xl px-4 py-8 text-xs leading-relaxed text-zinc-500 sm:px-6">
          <p>© Vulnix — Find. Prove. Secure.</p>
          <p className="mt-1">動画と画面は、ローカルの模擬ラボで実際に動かしたときの録画です。実在サービスの診断結果ではありません。</p>
          <p className="mt-1">計画エンジン: ARTEX（jiwoochris/artex-global, AGPL-3.0）／ AI 解説: Abliteration AI</p>
        </div>
      </footer>
    </div>
  );
}
