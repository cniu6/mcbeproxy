export const emptyNodeFilter = () => ({ group: null, protocol: null, enabled: null, search: '' })
export function nodeGroupOptions(nodes) {
  const groups = [...new Set(nodes.map(n => String(n.group || '').trim()))].sort()
  return groups.map(group => ({ label: group || '未分类', value: group || '__ungrouped__' }))
}
export function filterNodes(nodes, filter = {}) {
  const search = String(filter.search || '').trim().toLowerCase()
  return nodes.filter(node => {
    const group = String(node.group || '').trim()
    if (filter.group && (filter.group === '__ungrouped__' ? group !== '' : group !== filter.group)) return false
    if (filter.protocol && node.type !== filter.protocol) return false
    if (filter.enabled != null && !!node.enabled !== filter.enabled) return false
    return !search || [node.name, node.server, node.group, node.type].some(v => String(v || '').toLowerCase().includes(search))
  })
}
