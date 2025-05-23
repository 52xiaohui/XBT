export function getSignStatus(active) {
  if (!active) return '';
  const isActive = active.endTime > Date.now();
  if (isActive) {
    return active.endTime === 64060559999000 ? "进行中(手动结束)" : "进行中";
  }
  return "已结束";
}

export function getSignStatusIcon(active) {
  if (!active) return '';
  const isActive = active.endTime > Date.now();
  return isActive ? "check-circle" : "close-circle";
}

export function getSignStatusColor(active) {
  if (!active) return '';
  const isActive = active.endTime > Date.now();
  return isActive ? "var(--color-success)" : "var(--color-danger)";
}

export function getSignSource(active) {
  if (!active?.signRecord) return '';
  const source = active.signRecord.source;
  if (source === 'self') return '本人签到';
  if (source === 'xxt') return '学习通';
  if (source === 'agent') return active.signRecord.sourceName + '代签';
  if (source === 'none') return '未签到';
  return source;
}

export function getSignSubtitle(active) {
  const prefix = getSignStatus(active);
  if (!active?.signRecord) return prefix;
  
  if (active.signRecord.source === 'self') {
    return prefix + '(本人签到)';
  } else if (active.signRecord.source === 'xxt') {
    return prefix + '(学习通)';
  } else if (active.signRecord.source === 'agent') {
    return prefix + '(' + active.signRecord.sourceName + '代签)';
  }
  return prefix;
} 