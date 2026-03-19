export default function AttackChainGraph({ attackChain = {} }) {
  const phases = attackChain.attack_phases || [];
  const path = attackChain.attack_path || "";
  const summary = attackChain.summary || "";
  const attackType = attackChain.attack_type || "";
  const confidence = attackChain.confidence ?? 0;

  if (phases.length === 0 && !path && !summary) {
    return (
      <div className="text-zinc-500 text-xs font-mono py-6 text-center">无数据</div>
    );
  }

  return (
    <div className="space-y-4">
      {summary && (
        <div className="bg-surface-elevated rounded-lg p-3 border border-surface-border">
          <p className="text-sm text-accent font-medium">摘要</p>
          <p className="text-zinc-400 text-sm mt-1">{summary}</p>
        </div>
      )}
      {attackType && (
        <p className="text-sm">
          <span className="text-zinc-400">攻击类型：</span>
          <span className="text-accent">{attackType}</span>
          {confidence > 0 && (
            <span className="text-zinc-400 ml-2">置信度：{(confidence * 100).toFixed(0)}%</span>
          )}
        </p>
      )}
      {path && (
        <div className="bg-surface-elevated rounded-lg p-3 border border-surface-border">
          <p className="text-sm text-zinc-400">攻击路径</p>
          <p className="text-zinc-200 text-sm mt-1">{path}</p>
        </div>
      )}
      {phases.length > 0 && (
        <div>
          <p className="text-sm text-zinc-200 font-semibold mb-2">攻击阶段（MITRE ATT&CK）</p>
          <div className="flex flex-wrap gap-2">
            {phases.map((p, i) => (
              <div
                key={i}
                className="bg-surface-elevated rounded-lg px-3 py-2 border border-surface-border text-sm"
              >
                <span className="text-accent">{p.phase}</span>
                {p.mitre_tactic && (
                  <span className="text-zinc-400 ml-2 text-xs">{p.mitre_tactic}</span>
                )}
                <p className="text-zinc-400 text-xs mt-1">{p.description}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
