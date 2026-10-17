import React from 'react'
import ReactDOM from 'react-dom/client'
import './style.css'

function App() {
  return (
    <main className="shell">
      <div className="eyebrow">NetEvidence · 阶段 0</div>
      <h1>网络诊断的证据，从这里开始。</h1>
      <p>
        项目构建链已经就绪。下一阶段将接入 URL 输入、分层探测和结构化结果。
      </p>
      <section aria-label="规划的探测层">
        <span>DNS</span>
        <span>TCP</span>
        <span>TLS</span>
        <span>HTTP</span>
        <span>本机环境</span>
      </section>
      <small>当前页面不执行诊断，也不采集网络数据。</small>
    </main>
  )
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)
