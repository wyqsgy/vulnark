import React, { useState, useEffect, useRef } from 'react'
import { getTasks } from '../api'

const API_BASE = '/api'

export default function Reports() {
  const [tasks, setTasks] = useState([])
  const [loading, setLoading] = useState(true)

  // AI 流式报告状态
  const [aiTaskId, setAiTaskId] = useState(null)
  const [aiContent, setAiContent] = useState('')
  const [aiStatus, setAiStatus] = useState('') // '' | 'streaming' | 'done' | 'error'
  const aiBoxRef = useRef(null)

  useEffect(() => { loadTasks() }, [])

  // 流式输出时自动滚动到底部
  useEffect(() => {
    if (aiBoxRef.current) aiBoxRef.current.scrollTop = aiBoxRef.current.scrollHeight
  }, [aiContent])

  const loadTasks = async () => {
    try {
      const res = await getTasks({ limit: 100 })
      setTasks((res.data.data?.items || []).filter((t) => t.status === 'completed'))
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  const handleAiStream = async (taskId) => {
    setAiTaskId(taskId)
    setAiContent('')
    setAiStatus('streaming')
    try {
      const res = await fetch(`${API_BASE}/reports/ai-generate-stream/${taskId}`, { method: 'POST' })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const reader = res.body.getReader()
      const decoder = new TextDecoder()
      let buffer = ''
      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        buffer += decoder.decode(value, { stream: true })
        const lines = buffer.split('\n')
        buffer = lines.pop() || ''
        for (const line of lines) {
          if (!line.startsWith('data:')) continue
          try {
            const event = JSON.parse(line.slice(5))
            if (event.type === 'token') {
              setAiContent((prev) => prev + event.content)
            } else if (event.type === 'done') {
              setAiStatus('done')
            } else if (event.type === 'error') {
              setAiContent((prev) => prev + `\n\n[错误] ${event.error}`)
              setAiStatus('error')
            }
          } catch { /* skip malformed line */ }
        }
      }
      setAiStatus((s) => (s === 'streaming' ? 'done' : s))
    } catch (e) {
      setAiContent(`[错误] ${e.message || e}`)
      setAiStatus('error')
    }
  }

  if (loading) {
    return (
      <div className="terminal" style={{ height: '300px' }}>
        <div className="line prompt">$ 正在加载报告...</div>
        <div className="line cursor">_</div>
      </div>
    )
  }

  return (
    <div>
      <div className="sec-title" style={{ marginBottom: '24px' }}>扫描报告</div>

      {tasks.length === 0 ? (
        <div className="terminal" style={{ textAlign: 'center', padding: '60px 20px' }}>
          <div style={{ color: 'var(--text-dim)', fontSize: '14px' }}>
            暂无已完成任务的报告
          </div>
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: '12px' }}>
          {tasks.map((t) => (
            <div key={t.task_id} className="card" style={{ padding: '16px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '12px' }}>
                <div>
                  <div style={{ fontWeight: 600, fontSize: '14px', color: 'var(--text-bright)', marginBottom: '4px' }}>
                    {t.target?.substring(0, 30) || '未知目标'}
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--text-dim)' }}>
                    任务: {t.task_id}
                  </div>
                </div>
                <span className="badge" style={{ background: 'var(--success-subtle)', color: 'var(--success)' }}>
                  已完成
                </span>
              </div>

              <div style={{ display: 'flex', gap: '16px', marginBottom: '12px', fontSize: '12px', color: 'var(--text-secondary)' }}>
                <span>漏洞: <strong style={{ color: t.vuln_count > 0 ? 'var(--danger)' : 'var(--text-dim)' }}>{t.vuln_count || 0}</strong></span>
                <span>模块: {t.modules?.length || 0}</span>
              </div>

              <div style={{ display: 'flex', gap: '8px' }}>
                <a
                  href={`${API_BASE}/reports/${t.task_id}/html`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="btn btn-accent"
                  style={{ flex: 1, textAlign: 'center', textDecoration: 'none', fontSize: '12px' }}
                >
                  查看报告
                </a>
                <button
                  className="btn"
                  style={{ flex: 1, fontSize: '12px' }}
                  onClick={() => handleAiStream(t.task_id)}
                  disabled={aiStatus === 'streaming' && aiTaskId === t.task_id}
                >
                  {aiStatus === 'streaming' && aiTaskId === t.task_id ? '生成中...' : 'AI 流式报告'}
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {aiTaskId && (
        <div className="card" style={{ marginTop: '20px', padding: '16px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
            <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-bright)' }}>
              AI 流式报告 — {aiTaskId}
              {aiStatus === 'streaming' && <span style={{ color: 'var(--accent)', marginLeft: '8px' }}>▍生成中</span>}
              {aiStatus === 'done' && <span style={{ color: 'var(--success)', marginLeft: '8px' }}>✓ 完成</span>}
              {aiStatus === 'error' && <span style={{ color: 'var(--danger)', marginLeft: '8px' }}>✗ 出错</span>}
            </span>
            <button className="btn" style={{ fontSize: '11px', padding: '4px 10px' }} onClick={() => { setAiTaskId(null); setAiContent('') }}>
              关闭
            </button>
          </div>
          <pre
            ref={aiBoxRef}
            style={{
              maxHeight: '420px',
              overflowY: 'auto',
              whiteSpace: 'pre-wrap',
              fontSize: '12px',
              lineHeight: 1.7,
              color: 'var(--text-secondary)',
              background: 'var(--bg-terminal, #0d1117)',
              padding: '14px',
              borderRadius: '8px',
            }}
          >
            {aiContent || '正在连接 AI…'}
          </pre>
        </div>
      )}
    </div>
  )
}
