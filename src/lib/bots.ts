export const TRADE_BOTS = [
  { key: 'myoous', label: 'Myoous Bot', username: 'myoous' },
]
export const DEFAULT_BOT_KEY = 'myoous'
export function getBotByKey(key) {
  return TRADE_BOTS.find(b => b.key === key)
}
