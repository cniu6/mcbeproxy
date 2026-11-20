export const emptyNodeFilter = () => ({ group: null, protocol: null, enabled: null, search: '' })
export function nodeGroupOptions(nodes) {
  const groups = [...new Set(nodes.map(n => String(n.group || '').trim()))].sort()
  return groups.map(group => ({ label: group || '未分类', value: group || '__ungrouped__' }))
}
export function filterNodes(nodes, filter = {}) {
  const search = String(filter.search || '').trim().toLowerCase()
  return nodes.filter(node => {
    const group = String(node.group || '').trim()
    // '_ungrouped' 是节点选择器历史使用的未分组取值，与 '__ungrouped__' 等价
    const ungrouped = filter.group === '__ungrouped__' || filter.group === '_ungrouped'
    if (filter.group && (ungrouped ? group !== '' : group !== filter.group)) return false
    if (filter.protocol && node.type !== filter.protocol) return false
    if (filter.enabled != null && !!node.enabled !== filter.enabled) return false
    // 仅过滤明确不支持 UDP 的节点；未探测（undefined）的节点保留，与各选择器原有语义一致
    if (filter.udpOnly && node.udp_available === false) return false
    return !search || [node.name, node.server, node.group, node.type].some(v => String(v || '').toLowerCase().includes(search))
  })
}
