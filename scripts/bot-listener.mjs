import 'dotenv/config'
import { createClient } from '@supabase/supabase-js'

// Minimal embedded bot map to avoid importing TS from Node script
const TRADE_BOTS = [
  { key: 'myoous', label: 'Myoous Bot', username: 'myoous' },
]
const DEFAULT_BOT_KEY = 'myoous'
const getBotByKey = (key) => TRADE_BOTS.find(b => b.key === key)

const SUPABASE_URL = process.env.SUPABASE_URL
const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY
const BOT_KEY = process.env.BOT_KEY || DEFAULT_BOT_KEY
const SIM_MODE = (process.env.SIM_MODE || 'false').toLowerCase() === 'true'
const BOT_TOTP_SECRET = process.env.BOT_TOTP_SECRET
const ENABLE_INBOUND = (process.env.ENABLE_INBOUND || 'true').toLowerCase() === 'true'
const INBOUND_POLL_SECONDS = Number(process.env.INBOUND_POLL_SECONDS || '5')
const PENDING_POLL_SECONDS = Number(process.env.PENDING_POLL_SECONDS || '5')
const MAX_BOT_ROBUX = Number(process.env.MAX_BOT_ROBUX || '0')
const MAX_USER_ROBUX = Number(process.env.MAX_USER_ROBUX || '1000000000')

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  console.error('Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY in env')
  process.exit(1)
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false },
  realtime: { params: { eventsPerSecond: 5 } }
})
const privateSupabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
  auth: { persistSession: false },
  db: { schema: 'private' }
})


let BOT_ROBLOSECURITY = process.env.BOT_ROBLOSECURITY || null

const bot = getBotByKey(BOT_KEY)
if (!bot) {
  console.error(`Unknown BOT_KEY: ${BOT_KEY}`)
  process.exit(1)
}

async function loadBotCookieFromSupabase() {
  if (process.env.BOT_ROBLOSECURITY) {
    return process.env.BOT_ROBLOSECURITY
  }
  const { data, error } = await privateSupabase
    .from('bot_credentials')
    .select('roblosecurity')
    .eq('bot_key', BOT_KEY)
    .maybeSingle()

  if (error) {
    throw new Error(`Failed to load bot cookie: ${error.message}`)
  }

  return data?.roblosecurity || null
}

async function handleTradeInserted(row) {
  // row structure expected from trades table
  const { id, partner_username, give_ids, receive_ids, status, requester_user_id, expected_receive_robux = 0, expected_give_robux = 0, timeout_seconds = 120 } = row
  console.log(`[trade:${id}] incoming for ${partner_username} status=${status}`)
  console.log(`[trade:${id}] request summary: give_ids=${trunc(give_ids)} receive_ids=${trunc(receive_ids)} expGiveRobux=${expected_give_robux} expRecvRobux=${expected_receive_robux} timeout=${timeout_seconds}s`)
  if (partner_username?.toLowerCase() !== bot.username.toLowerCase()) {
    return // not for this bot
  }

  // TODO: Add matching rules and validation (e.g., max 4 items, value delta, etc.)
  const match = await simpleMatch(give_ids, receive_ids)
  if (!match.accept) {
    console.log(`[trade:${id}] rejected: ${match.reason}`)
    await updateTradeStatus(id, 'rejected', match.reason)
    return
  }

  if (SIM_MODE) {
    console.log(`[trade:${id}] SIM: searching simulated inbound trades...`)
    const foundSim = await findSimulatedInbound({ partner_username, give_ids, receive_ids })
    if (!foundSim) {
      console.log(`[trade:${id}] SIM: no matching inbound found`)
      await updateTradeStatus(id, 'rejected', 'no matching simulated inbound')
      return
    }
    await acceptSimulatedTrade(foundSim.id)
    console.log(`[trade:${id}] SIM: accepted simulated inbound ${foundSim.id}`)
  } else {
    if (!BOT_ROBLOSECURITY) {
      console.error('Bot Roblox cookie not set; configure it via the admin panel before sending trades')
      await updateTradeStatus(id, 'failed', 'bot not configured')
      return
    }
    console.log(`[trade:${id}] sending Roblox trade from bot to requester...`)
    try {
      const xcsrf = await getXcsrf(BOT_ROBLOSECURITY)
      console.log(`[trade:${id}] obtained X-CSRF token length=${xcsrf?.length || 0}`)
      // Map assetId -> userAssetId for both sides
      const requesterId = requester_user_id
      if (!requesterId) {
        await updateTradeStatus(id, 'rejected', 'missing requester_user_id')
        return
      }
      const selfId = await getSelfUserId(BOT_ROBLOSECURITY, xcsrf)
      console.log(`[trade:${id}] ids: selfId=${selfId} requesterId=${requesterId}`)
      // Correct mapping:
      // - User offers give_ids (their items)
      // - Bot offers receive_ids (bot's items)
      const [userUas, botUas] = await Promise.all([
        fetchUserAssetIdsForAssetIds(requesterId, give_ids, null, null),
        fetchUserAssetIdsForAssetIds(selfId, receive_ids, BOT_ROBLOSECURITY, xcsrf)
      ])

      if (botUas.missing.length) {
        console.warn(`[trade:${id}] bot missing UAIDs for assets: ${trunc(botUas.missing)}`)
        await updateTradeStatus(id, 'rejected', `bot missing assets: ${botUas.missing.join(',')}`)
        return
      }
      if (userUas.missing.length) {
        console.warn(`[trade:${id}] user missing UAIDs for assets: ${trunc(userUas.missing)}`)
        await updateTradeStatus(id, 'rejected', `user missing assets: ${userUas.missing.join(',')}`)
        return
      }
      console.log(`[trade:${id}] UAID mapping: userUAIDs=${userUas.ids.length} botUAIDs=${botUas.ids.length}`)

      const payload = {
        offers: [
          // User gives their items and any expected_give_robux to the bot
          { userId: requesterId, userAssetIds: userUas.ids, robux: expected_give_robux },
          // Bot gives its items and any expected_receive_robux to the user
          { userId: selfId, userAssetIds: botUas.ids, robux: expected_receive_robux }
        ]
      }
      console.log(`[trade:${id}] payload summary: user->{bot} uaids=${userUas.ids.length} robux=${expected_give_robux}; bot->{user} uaids=${botUas.ids.length} robux=${expected_receive_robux}`)
      const { tradeId } = await sendTrade(payload, BOT_ROBLOSECURITY, xcsrf, selfId)
      await updateTradeRow(id, { roblox_trade_id: tradeId, status: 'sent', reason: null })
      console.log(`[trade:${id}] sent trade id ${tradeId}`)
    } catch (err) {
      console.error(`[trade:${id}] send failed`, err)
      const raw = String(err?.message || err || '')
      
      // Check if cookie expired
      if (raw.includes('COOKIE_EXPIRED') || raw.includes('401')) {
        console.error('[CRITICAL] Bot cookie has EXPIRED!')
        console.error('Please update the bot cookie in Supabase (via the admin panel) and restart the bot.')
        await updateTradeStatus(id, 'failed', 'Bot cookie expired - needs update')
        process.exit(1) // Shutdown bot to prevent further failed attempts
      }
      
      // Preserve a concise reason for the UI (including Roblox 429 rate-limit message)
      await updateTradeStatus(id, 'failed', raw)
      return
    }
    // In send mode, we stop here with status 'sent'
    return
  }
  // SIM mode accepts immediately
  await updateTradeStatus(id, 'accepted', null)
}

// Guard to prevent duplicate parallel processing of the same trade id
const processingTrades = new Set()

async function updateTradeStatus(id, status, reason) {
  const { error } = await supabase.from('trades').update({ status, reason }).eq('id', id)
  if (error) console.error('Failed to update trade status', error)
}

async function updateTradeRow(id, fields) {
  const { error } = await supabase.from('trades').update(fields).eq('id', id)
  if (error) console.error('Failed to update trade row', error)
}

async function simpleMatch(giveIds, receiveIds) {
  // placeholder: ensure arrays and <= 4 items
  const g = Array.isArray(giveIds) ? giveIds : []
  const r = Array.isArray(receiveIds) ? receiveIds : []
  if (g.length === 0 || r.length === 0) return { accept: false, reason: 'empty selections' }
  if (g.length > 4 || r.length > 4) return { accept: false, reason: 'too many items' }
  // add more business logic here
  return { accept: true }
}

async function findSimulatedInbound({ partner_username, give_ids, receive_ids }) {
  const { data, error } = await supabase
    .from('sim_inbound_trades')
    .select('*')
    .eq('to_username', partner_username)
    .eq('status', 'open')
    .order('created_at', { ascending: false })
  if (error) { console.error('SIM: query error', error); return null }
  for (const row of data || []) {
    const giveMatch = sameMultiset(row.give_asset_ids || [], give_ids || [])
    const recvMatch = sameMultiset(row.receive_asset_ids || [], receive_ids || [])
    if (giveMatch && recvMatch) { console.log(`[SIM] matched inbound id ${row.id}`); return row }
  }
  return null

  function sameMultiset(a = [], b = []) {
    if (a.length !== b.length) return false
    const map = new Map()
    for (const x of a) map.set(x, (map.get(x) || 0) + 1)
    for (const y of b) {
      const c = map.get(y)
      if (!c) return false
      if (c === 1) map.delete(y)
      else map.set(y, c - 1)
    }
    return map.size === 0
  }
}

// --- Roblox helpers ---
async function getXcsrf(cookie) {
  const res = await fetch('https://auth.roblox.com/v2/logout', {
    method: 'POST',
    headers: { cookie: `.ROBLOSECURITY=${cookie}` }
  })
  
  // Check for expired/invalid cookie
  if (res.status === 401) {
    throw new Error('COOKIE_EXPIRED: Roblox cookie is invalid or expired (401 Unauthorized)')
  }
  
  const token = res.headers.get('x-csrf-token')
  if (!token) throw new Error('Failed to obtain X-CSRF token')
  return token
}

async function getSelfUserId(cookie, xcsrf) {
  const res = await fetch('https://users.roblox.com/v1/users/authenticated', {
    headers: {
      'x-csrf-token': xcsrf,
      cookie: `.ROBLOSECURITY=${cookie}`
    }
  })
  
  // Check for expired/invalid cookie
  if (res.status === 401) {
    throw new Error('COOKIE_EXPIRED: Roblox cookie is invalid or expired (401 Unauthorized)')
  }
  
  if (!res.ok) throw new Error(`Failed to get self user id (${res.status})`)
  const data = await res.json()
  return data.id
}

// Validate cookie is still valid
async function validateCookie(cookie) {
  try {
    const xcsrf = await getXcsrf(cookie)
    const userId = await getSelfUserId(cookie, xcsrf)
    return { valid: true, userId, xcsrf }
  } catch (error) {
    if (error.message.includes('COOKIE_EXPIRED')) {
      return { valid: false, error: 'Cookie expired or invalid', critical: true }
    }
    return { valid: false, error: error.message, critical: false }
  }
}

async function fetchCollectiblesWithUserAssetId(userId, cookie = null, xcsrf = null) {
  const out = []
  let cursor
  
  // Try the catalog API which the website might use
  try {
    console.log(`[inv] trying catalog API for user ${userId}...`)
    while (true) {
      const url = new URL(`https://catalog.roblox.com/v1/users/${userId}/items/collectibles`)
      url.searchParams.set('limit', '100')
      url.searchParams.set('sortOrder', 'Asc')
      if (cursor) url.searchParams.set('cursor', cursor)
      
      const res = await fetch(url, {
        headers: {
          accept: 'application/json',
          ...(cookie ? { cookie: `.ROBLOSECURITY=${cookie}` } : {}),
          ...(xcsrf ? { 'x-csrf-token': xcsrf } : {})
        }
      })
      
      if (!res.ok) {
        console.error(`[inv] catalog API failed ${res.status}, trying v1...`)
        return fetchCollectiblesV1(userId, cookie, xcsrf)
      }
      
      const data = await res.json()
      if (out.length === 0 && data.data && data.data[0]) {
        console.log('[inv] catalog API first item:', JSON.stringify(data.data[0], null, 2).slice(0, 500))
      }
      
      for (const it of data.data || []) {
        // Look for collectibleItemId, collectibleItemInstanceId, or instanceId fields
        const uuid = it.collectibleItemId || it.collectibleItemInstanceId || it.instanceId
        const assetId = it.assetId || it.id
        
        if (uuid && assetId) {
          out.push({ assetId: assetId, userAssetId: uuid })
        } else if (it.userAssetId && assetId) {
          out.push({ assetId: assetId, userAssetId: it.userAssetId })
        }
      }
      
      if (!data.nextPageCursor) break
      cursor = data.nextPageCursor
    }
    
    console.log(`[inv] catalog API: user ${userId} collectibles resolved: ${out.length}`)
    return out
  } catch (e) {
    console.error(`[inv] catalog API error:`, e)
    return fetchCollectiblesV1(userId, cookie, xcsrf)
  }
}

async function fetchCollectiblesV1(userId, cookie, xcsrf) {
  const out = []
  let cursor
  while (true) {
    const url = new URL(`https://inventory.roblox.com/v1/users/${userId}/assets/collectibles`)
    url.searchParams.set('limit', '100')
    if (cursor) url.searchParams.set('cursor', cursor)
    const res = await fetch(url, {
      headers: {
        accept: 'application/json',
        ...(cookie ? { cookie: `.ROBLOSECURITY=${cookie}` } : {}),
        ...(xcsrf ? { 'x-csrf-token': xcsrf } : {})
      }
    })
    if (!res.ok) break
    const data = await res.json()
    
    // Log first item to see what fields are available (including hold data)
    if (out.length === 0 && data.data && data.data[0]) {
      console.log('[inv] v1 API first item fields:', JSON.stringify(data.data[0], null, 2))
    }
    
    for (const it of data.data || []) {
      if (it.userAssetId) {
        const item = { assetId: it.assetId, userAssetId: it.userAssetId }
        // Check for hold expiration field
        if (it.holdExpiration) {
          item.holdExpiration = it.holdExpiration
          console.log(`[inv] item ${it.name} has hold: ${it.holdExpiration}`)
        }
        out.push(item)
      }
    }
    if (!data.nextPageCursor) break
    cursor = data.nextPageCursor
  }
  console.log(`[inv] v1 fallback: user ${userId} collectibles resolved: ${out.length}`)
  return out
}

// Convert numeric userAssetIds to UUID collectibleItemInstanceIds
async function resolveUserAssetIdsToUUIDs(userAssetIds, cookie, xcsrf) {
  // Use the ownership API to get collectible item instance UUIDs
  const uuids = []
  console.log(`[inv] resolving ${userAssetIds.length} userAssetIds to UUIDs...`)
  
  try {
    // Batch request to get item details
    const url = 'https://apis.roblox.com/marketplace-items/v1/items/details'
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        accept: 'application/json',
        'content-type': 'application/json',
        cookie: `.ROBLOSECURITY=${cookie}`,
        'x-csrf-token': xcsrf
      },
      body: JSON.stringify({
        itemIds: userAssetIds.map(id => String(id))
      })
    })
    
    if (res.ok) {
      const data = await res.json()
      console.log(`[inv] batch response:`, JSON.stringify(data, null, 2).slice(0, 500))
      // Map the responses back
      for (const uaid of userAssetIds) {
        const match = data.find(item => item.id === String(uaid) || item.instanceId === String(uaid))
        if (match && match.collectibleItemId) {
          uuids.push(match.collectibleItemId)
          console.log(`[inv] ${uaid} -> ${match.collectibleItemId}`)
        } else {
          console.warn(`[inv] ${uaid} no UUID found, using numeric`)
          uuids.push(String(uaid))
        }
      }
    } else {
      console.warn(`[inv] batch resolve failed ${res.status}, using numeric IDs`)
      return userAssetIds.map(String)
    }
  } catch (e) {
    console.error(`[inv] error batch resolving:`, e)
    return userAssetIds.map(String)
  }
  
  return uuids
}

async function fetchUserAssetIdsForAssetIds(userId, desiredAssetIds, cookie = null, xcsrf = null) {
  const items = await fetchCollectiblesWithUserAssetId(userId, cookie, xcsrf)
  const byAsset = new Map()
  for (const it of items) {
    const arr = byAsset.get(it.assetId) || []
    arr.push(it.userAssetId)
    byAsset.set(it.assetId, arr)
  }
  const ids = []
  const missing = []
  for (const aid of desiredAssetIds || []) {
    const list = byAsset.get(aid) || []
    if (list.length) ids.push(list.shift())
    else missing.push(aid)
  }
  
  // Convert numeric IDs to UUIDs if we have auth
  if (ids.length > 0 && cookie && xcsrf) {
    const uuids = await resolveUserAssetIdsToUUIDs(ids, cookie, xcsrf)
    return { ids: uuids, missing }
  }
  
  return { ids: ids.map(String), missing }
}

async function sendTrade(payload, cookie, xcsrf, userId) {
  // Use v1 API which accepts numeric userAssetIds
  console.log('[trade] sending trade to v1 endpoint...')
  console.log('[trade] v1 payload:', JSON.stringify(payload, null, 2))
  
  const res = await fetch('https://trades.roblox.com/v1/trades/send', {
    method: 'POST',
    headers: {
      'content-type': 'application/json;charset=UTF-8',
      'x-csrf-token': xcsrf,
      cookie: `.ROBLOSECURITY=${cookie}`,
      'accept': 'application/json, text/plain, */*',
      'accept-language': 'en-US,en;q=0.9',
      origin: 'https://www.roblox.com',
      referer: 'https://www.roblox.com/',
      'sec-fetch-site': 'same-site',
      'sec-fetch-mode': 'cors',
      'sec-fetch-dest': 'empty',
      'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36'
    },
    body: JSON.stringify(payload)
  })
  if (!res.ok) {
    // Handle Roblox challenge flow (403 with challenge headers)
    if (res.status === 403) {
      const chall = extractChallenge(res.headers)
      if (chall) {
        console.warn(`[challenge] ${chall.type} detected; attempting continue...`)
        // Get bound auth token from challenge response headers - try all variations
        let boundAuthToken = res.headers.get('x-bound-auth-token') || 
                            res.headers.get('X-Bound-Auth-Token') ||
                            res.headers.get('rblx-bound-auth-token')
        console.log('[challenge] bound auth token from 403 response:', boundAuthToken ? boundAuthToken.slice(0, 50) + '...' : 'missing')
        
        const { verificationToken, continueBoundAuthToken } = await continueChallenge(chall, cookie, xcsrf, userId, boundAuthToken)
        if (verificationToken) {
          // retry once with v2 endpoint, including challenge headers
          console.log('[trade] retrying trade send after challenge resolution...')
          
          // Build challenge metadata for retry
          const retryMetadata = {
            verificationToken: verificationToken,
            rememberDevice: false,
            challengeId: chall.twoFactorChallengeId || chall.id,
            actionType: 'Generic'
          }
          const retryMetadataBase64 = Buffer.from(JSON.stringify(retryMetadata)).toString('base64')
          
          const retryHeaders = {
            'content-type': 'application/json;charset=UTF-8',
            'x-csrf-token': xcsrf,
            cookie: `.ROBLOSECURITY=${cookie}`,
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'en-US,en;q=0.9',
            'rblx-challenge-id': chall.id,  // Use header challengeId
            'rblx-challenge-type': chall.type,
            'rblx-challenge-metadata': retryMetadataBase64,
            origin: 'https://www.roblox.com',
            referer: 'https://www.roblox.com/',
            'sec-fetch-site': 'same-site',
            'sec-fetch-mode': 'cors',
            'sec-fetch-dest': 'empty',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36'
          }
          
          // Add bound auth token if we have it
          if (continueBoundAuthToken) {
            retryHeaders['x-bound-auth-token'] = continueBoundAuthToken
            console.log('[trade] using bound auth token for retry')
          } else {
            console.warn('[trade] NO bound auth token for retry!')
          }
          
          console.log('[trade] retry headers:', Object.keys(retryHeaders).join(', '))
          console.log('[trade] retry v1 payload:', JSON.stringify(payload).slice(0, 500))
          
          const retry = await fetch('https://trades.roblox.com/v1/trades/send', {
            method: 'POST',
            headers: retryHeaders,
            body: JSON.stringify(payload)
          })
          if (retry.ok) {
            const data = await retry.json()
            return { tradeId: data.id }
          } else {
            const text = await retry.text()
            throw new Error(`sendTrade failed ${retry.status} after challenge: ${text.slice(0,300)}`)
          }
        } else {
          throw new Error('challenge continue failed')
        }
      }
    }
    const text = await res.text()
    throw new Error(`sendTrade failed ${res.status}: ${text.slice(0,300)}`)
  }
  const data = await res.json()
  return { tradeId: data.id }
}

async function getBoundAuthToken(cookie, xcsrf, userId) {
  try {
    const configUrl = `https://twostepverification.roblox.com/v1/users/${userId}/configuration`
    console.log('[auth] fetching bound auth token from:', configUrl)
    const res = await fetch(configUrl, {
      method: 'GET',
      headers: {
        'x-csrf-token': xcsrf,
        cookie: `.ROBLOSECURITY=${cookie}`,
        'accept': 'application/json, text/plain, */*',
        origin: 'https://www.roblox.com',
        referer: 'https://www.roblox.com/',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36'
      }
    })
    
    console.log('[auth] configuration response status:', res.status)
    const body = await res.text()
    console.log('[auth] configuration response body:', body.slice(0, 300))
    
    const token = res.headers.get('x-bound-auth-token')
    if (!token) {
      console.error('[auth] no bound auth token in configuration response')
      return null
    }
    console.log('[auth] bound auth token obtained')
    return token
  } catch (e) {
    console.error('[auth] error getting bound auth token:', e)
    return null
  }
}

async function getBoundAuthTokenWithChallenge(cookie, xcsrf, userId, challengeId) {
  try {
    const configUrl = `https://twostepverification.roblox.com/v1/users/${userId}/configuration?challengeId=${challengeId}&actionType=Generic`
    console.log('[auth] fetching bound auth token WITH challengeId:', configUrl)
    const res = await fetch(configUrl, {
      method: 'GET',
      headers: {
        'x-csrf-token': xcsrf,
        cookie: `.ROBLOSECURITY=${cookie}`,
        'accept': 'application/json, text/plain, */*',
        'accept-language': 'en-US,en;q=0.9',
        origin: 'https://www.roblox.com',
        referer: 'https://www.roblox.com/',
        'sec-fetch-site': 'same-site',
        'sec-fetch-mode': 'cors',
        'sec-fetch-dest': 'empty',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36'
      }
    })
    
    console.log('[auth] configuration (with challenge) response status:', res.status)
    const body = await res.text()
    console.log('[auth] configuration (with challenge) response body:', body.slice(0, 300))
    
    // Try multiple header name variations
    let token = res.headers.get('x-bound-auth-token') || 
                res.headers.get('X-Bound-Auth-Token') ||
                res.headers.get('rblx-bound-auth-token')
    
    if (!token) {
      console.log('[auth] no bound auth token found, checking all headers:')
      res.headers.forEach((value, key) => {
        console.log(`  ${key}: ${value.slice(0, 100)}`)
      })
      return null
    }
    
    console.log('[auth] bound auth token obtained (with challengeId), length:', token.length)
    console.log('[auth] token preview:', token.slice(0, 50) + '...')
    return token
  } catch (e) {
    console.error('[auth] error getting bound auth token with challenge:', e)
    return null
  }
}

function extractChallenge(headers) {
  const id = headers.get('x-roblox-challenge-id') || headers.get('rblx-challenge-id')
  const type = headers.get('x-roblox-challenge-type') || headers.get('rblx-challenge-type')
  const metadata = headers.get('x-roblox-challenge-metadata') || headers.get('rblx-challenge-metadata')
  
  // Decode the metadata to get the actual challengeId for 2FA verification
  let decodedMetadata = null
  let twoFactorChallengeId = null
  if (metadata) {
    try {
      const decoded = Buffer.from(metadata, 'base64').toString('utf-8')
      decodedMetadata = JSON.parse(decoded)
      twoFactorChallengeId = decodedMetadata.challengeId
      console.log('[challenge] header challengeId:', id)
      console.log('[challenge] decoded metadata challengeId (for 2FA):', twoFactorChallengeId)
    } catch (e) {
      console.error('[challenge] failed to decode metadata:', e)
    }
  }
  
  // Return both IDs: header id for continue, decoded id for 2FA verify
  if (id && type) {
    return { 
      id,  // Use header challengeId for challenge continue
      twoFactorChallengeId,  // Use decoded challengeId for 2FA verify
      type, 
      metadata, 
      decodedMetadata 
    }
  }
  return null
}

async function continueChallenge(chall, cookie, xcsrf, userId, boundAuthToken) {
  try {
    // If the challenge indicates two-step verification and a TOTP secret is available, solve it first
    let verificationToken = null
    if ((chall.type || '').toLowerCase().includes('twostep') && BOT_TOTP_SECRET) {
      console.log('[2sv] solving 2FA before challenge continuation')
      // Use the twoFactorChallengeId from decoded metadata for 2FA verification
      const verifyId = chall.twoFactorChallengeId || chall.id
      console.log('[2sv] using challengeId for verification:', verifyId)
      verificationToken = await solveTwoStepTotp(cookie, xcsrf, verifyId, userId, boundAuthToken)
      if (!verificationToken) {
        console.error('[2sv] failed to get verification token')
        return false
      }
      console.log('[2sv] got verification token:', verificationToken ? 'present' : 'missing')
    }

    // Get a fresh bound auth token for the continue request
    // Browser seems to get a new one between verify and continue
    console.log('[challenge] fetching fresh bound auth token for continue...')
    const continueBoundAuthToken = await getBoundAuthTokenWithChallenge(cookie, xcsrf, userId, chall.twoFactorChallengeId)
    if (!continueBoundAuthToken) {
      console.warn('[challenge] no bound auth token for continue, proceeding anyway')
    }

    // Build challengeMetadata matching browser format
    const metadata = {
      verificationToken: verificationToken || '',
      rememberDevice: false,
      challengeId: chall.twoFactorChallengeId || chall.id,  // Use decoded challengeId in metadata
      actionType: 'Generic'
    }
    
    const continueBody = {
      challengeId: chall.id,  // Use header challengeId for continue endpoint
      challengeType: chall.type,
      challengeMetadata: JSON.stringify(metadata)
    }
    console.log('[challenge] continuing with body:', JSON.stringify(continueBody).slice(0, 300))

    const continueHeaders = {
      'content-type': 'application/json;charset=UTF-8',
      'x-csrf-token': xcsrf,
      cookie: `.ROBLOSECURITY=${cookie}`,
      'accept': 'application/json, text/plain, */*',
      'accept-language': 'en-US,en;q=0.9',
      origin: 'https://www.roblox.com',
      referer: 'https://www.roblox.com/',
      'sec-fetch-site': 'same-site',
      'sec-fetch-mode': 'cors',
      'sec-fetch-dest': 'empty',
      'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36'
    }
    
    // Add bound auth token if we have it
    if (continueBoundAuthToken) {
      continueHeaders['x-bound-auth-token'] = continueBoundAuthToken
      console.log('[challenge] using bound auth token for continue')
    }

    const res = await fetch('https://apis.roblox.com/challenge/v1/continue', {
      method: 'POST',
      headers: continueHeaders,
      body: JSON.stringify(continueBody)
    })
    if (!res.ok) {
      const text = await res.text()
      console.error(`[challenge] continue failed ${res.status}: ${text.slice(0,300)}`)
      // Try once more after refreshing xcsrf
      if (res.status === 403) {
        try {
          const newX = await getXcsrf(cookie)
          const retry = await fetch('https://apis.roblox.com/challenge/v1/continue', {
            method: 'POST',
            headers: {
              'content-type': 'application/json',
              'x-csrf-token': newX,
              cookie: `.ROBLOSECURITY=${cookie}`,
              origin: 'https://www.roblox.com',
              referer: 'https://www.roblox.com/',
              'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36'
            },
            body: JSON.stringify({ challengeId: chall.id, challengeType: chall.type, challengeMetadata: chall.metadata || '' })
          })
          if (retry.ok) {
            console.log('[challenge] continue succeeded on retry')
            return { verificationToken, continueBoundAuthToken }
          }
          const rtext = await retry.text()
          console.error(`[challenge] continue retry failed ${retry.status}: ${rtext.slice(0,300)}`)
        } catch (e) {
          console.error('[challenge] continue retry error', e)
        }
      }
      return { verificationToken: null, continueBoundAuthToken: null }
    }
    console.log('[challenge] continue succeeded')
    
    // Return the verification token and the bound auth token we used for continue
    // The browser reuses the same bound auth token for the retry
    return { verificationToken, continueBoundAuthToken }
  } catch (e) {
    console.error('[challenge] continue error', e)
    return { verificationToken: null, continueBoundAuthToken: null }
  }
}

async function solveTwoStepTotp(cookie, xcsrf, challengeId, userId, boundAuthToken) {
  try {
    if (!BOT_TOTP_SECRET) {
      console.error('[2sv] BOT_TOTP_SECRET not configured')
      return null
    }
    const { authenticator } = await import('otplib')
    const code = authenticator.generate(BOT_TOTP_SECRET)
    console.log('[2sv] generated TOTP code:', code)
    console.log('[2sv] using bound auth token for verification')
    
    // Verify with the bound auth token we already have
    const url = `https://twostepverification.roblox.com/v1/users/${userId}/challenges/authenticator/verify`
    const requestBody = {
      challengeId: challengeId,
      actionType: 'Generic',
      code: code
    }
    console.log('[2sv] calling verify endpoint:', url)
    console.log('[2sv] request body:', JSON.stringify(requestBody))
    
    const res = await fetch(url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json;charset=UTF-8',
        'x-csrf-token': xcsrf,
        'x-bound-auth-token': boundAuthToken,
        cookie: `.ROBLOSECURITY=${cookie}`,
        'accept': 'application/json, text/plain, */*',
        'accept-language': 'en-US,en;q=0.9',
        origin: 'https://www.roblox.com',
        referer: 'https://www.roblox.com/',
        'sec-fetch-site': 'same-site',
        'sec-fetch-mode': 'cors',
        'sec-fetch-dest': 'empty',
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36'
      },
      body: JSON.stringify(requestBody)
    })
    
    const text = await res.text()
    console.log('[2sv] verify response status:', res.status)
    console.log('[2sv] verify response body:', text.slice(0, 500))
    
    if (!res.ok) {
      console.error(`[2sv] verify failed ${res.status}: ${text.slice(0,300)}`)
      return null
    }
    
    try {
      const result = JSON.parse(text)
      console.log('[2sv] verify succeeded, result keys:', Object.keys(result).join(', '))
      
      // Look for the verification token in the response
      const token = result.verificationToken || result.redemptionToken || result.token
      if (token) {
        console.log('[2sv] found verification token (length:', token.length, ')')
        return token
      }
      console.log('[2sv] no token found in response, returning full body')
      return text
    } catch {
      return text
    }
  } catch (e) {
    console.error('[2sv] error', e)
    return null
  }
}

async function acceptSimulatedTrade(id) {
  const { error } = await supabase.from('sim_inbound_trades').update({ status: 'accepted' }).eq('id', id)
  if (error) console.error('SIM: accept error', error)
}

async function main() {
  // Startup + config
  console.log(`Bot '${bot.label}' starting...`)
  BOT_ROBLOSECURITY = await loadBotCookieFromSupabase()
  console.log(`Config: SIM_MODE=${SIM_MODE} BOT_KEY=${BOT_KEY} BOT_COOKIE_PRESENT=${!!BOT_ROBLOSECURITY}`)

  // Validate bot cookie before doing anything in real mode
  if (!SIM_MODE) {
    if (!BOT_ROBLOSECURITY) {
      console.error('Bot Roblox cookie is missing. Use the admin panel to configure a cookie before running the bot.')
      process.exit(1)
    }
    const validation = await validateBotCookie(BOT_ROBLOSECURITY)
    if (!validation.ok) {
      console.error('Bot cookie validation failed:', validation.reason)
      console.error('Tip: Ensure you copied the full .ROBLOSECURITY value in the admin panel and that it has not expired.')
      process.exit(1)
    }
    console.log(`Cookie validated. Authenticated as userId=${validation.selfId}`)
  }

  console.log(`Bot '${bot.label}' listening for trades...`)
  // Initial backfill: fetch any pending trades for this bot
  const { data: pending, error } = await supabase
    .from('trades')
    .select('*')
    .eq('partner_username', bot.username)
    .eq('status', 'pending')
    .order('created_at', { ascending: true })

  if (error) console.error('Error loading pending trades', error)
  console.log(`Pending trades found: ${pending?.length || 0}`)
  for (const row of pending || []) {
    await handleTradeInserted(row)
  }

  // Realtime subscription to inserts
  const channel = supabase
    .channel('trades-inserts')
    .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'trades' }, payload => {
      const id = payload?.new?.id
      if (!id) return
      if (processingTrades.has(id)) return
      processingTrades.add(id)
      Promise.resolve(handleTradeInserted(payload.new))
        .catch(err => console.error('[pending] realtime handle error', err))
        .finally(() => processingTrades.delete(id))
    })
    .subscribe((status) => {
      console.log('Realtime status:', status)
    })

  // Start inbound polling loop (spontaneous handling of trades sent to bot)
  if (ENABLE_INBOUND) {
    console.log(`[inbound] polling enabled (every ${INBOUND_POLL_SECONDS}s)`)
    startInboundPollLoop().catch(err => console.error('[inbound] loop error', err))
  } else {
    console.log('[inbound] polling disabled by env')
  }

  // Start periodic pending backfill polling (fallback if realtime is disabled/missed)
  console.log(`[pending] backfill polling enabled (every ${PENDING_POLL_SECONDS}s) as realtime fallback`)
  startPendingBackfillLoop().catch(err => console.error('[pending] loop error', err))

  // Periodic cookie validation (every 30 minutes)
  if (!SIM_MODE && BOT_ROBLOSECURITY) {
    console.log('[cookie] validation enabled (every 30 minutes)')
    setInterval(async () => {
      console.log('[cookie] performing periodic validation...')
      const check = await validateCookie(BOT_ROBLOSECURITY)
      if (!check.valid) {
        console.error('[cookie] VALIDATION FAILED:', check.error)
        if (check.critical) {
          console.error('[cookie] CRITICAL: Cookie expired! Bot shutting down.')
          console.error('[cookie] Please update the bot cookie in Supabase (via the admin panel) and restart.')
          await supabase.removeChannel(channel)
          process.exit(1)
        }
      } else {
        console.log('[cookie] validation passed ✓')
      }
    }, 30 * 60 * 1000) // 30 minutes
  }

  // Keep process alive
  process.on('SIGINT', async () => {
    console.log('Shutting down...')
    await supabase.removeChannel(channel)
    process.exit(0)
  })
}

main().catch(err => {
  console.error(err)
  process.exit(1)
})


// --- helpers ---
async function validateBotCookie(cookie) {
  try {
    const xcsrf = await getXcsrf(cookie)
    if (!xcsrf) return { ok: false, reason: 'no x-csrf returned' }
    const selfId = await getSelfUserId(cookie, xcsrf)
    if (!selfId) return { ok: false, reason: 'no authenticated user id' }
    return { ok: true, selfId }
  } catch (err) {
    return { ok: false, reason: String(err?.message || err) }
  }
}

function trunc(arr, max = 10) {
  const a = Array.isArray(arr) ? arr : []
  if (a.length <= max) return JSON.stringify(a)
  return `${JSON.stringify(a.slice(0, max))}...(+${a.length - max})`
}

// --- Inbound polling and acceptance ---
async function startInboundPollLoop() {
  while (true) {
    try {
      await pollInboundOnce()
    } catch (e) {
      console.error('[inbound] poll error', e)
    }
    await sleepSeconds(INBOUND_POLL_SECONDS)
  }
}

async function pollInboundOnce() {
  if (!BOT_ROBLOSECURITY) return
  const xcsrf = await getXcsrf(BOT_ROBLOSECURITY)
  const userId = await getSelfUserId(BOT_ROBLOSECURITY, xcsrf)
  const list = await getInboundTrades(BOT_ROBLOSECURITY, xcsrf)
  if (!list?.data?.length) return
  for (const t of list.data) {
    const detail = await getTradeDetail(t.id, BOT_ROBLOSECURITY, xcsrf)
    if (!detail) continue
    const decision = shouldAcceptInbound(detail)
    if (decision.accept) {
      console.log(`[inbound] accepting trade ${t.id}: ${decision.reason || 'rule matched'}`)
      const ok = await acceptTrade(t.id, BOT_ROBLOSECURITY, xcsrf, userId)
      if (ok) console.log(`[inbound] accepted trade ${t.id}`)
      else console.warn(`[inbound] failed to accept ${t.id}`)
    } else {
      // Skip for now; could add decline later
      // console.log(`[inbound] skip trade ${t.id}: ${decision.reason}`)
    }
  }
}

function shouldAcceptInbound(detail) {
  try {
    const offers = detail.offers || []
    if (offers.length !== 2) return { accept: false, reason: 'unexpected offers' }
    // Identify sides (user vs bot) by which includes our UAIDs; not strictly needed for simple rules
    const a = offers[0]
    const b = offers[1]
    const totalA = (a.userAssets?.length || 0)
    const totalB = (b.userAssets?.length || 0)
    const robuxA = a.robux || 0
    const robuxB = b.robux || 0
    if (totalA > 4 || totalB > 4) return { accept: false, reason: 'too many items' }
    if (robuxA > MAX_USER_ROBUX || robuxB > MAX_BOT_ROBUX) return { accept: false, reason: 'robux limits' }
    return { accept: true }
  } catch {
    return { accept: false, reason: 'parse error' }
  }
}

async function getInboundTrades(cookie, xcsrf) {
  const res = await fetch('https://trades.roblox.com/v1/trades/inbound?limit=25', {
    headers: {
      'x-csrf-token': xcsrf,
      cookie: `.ROBLOSECURITY=${cookie}`,
      origin: 'https://www.roblox.com',
      referer: 'https://www.roblox.com/trades',
      'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36'
    }
  })
  if (!res.ok) { console.warn('[inbound] list failed', res.status); return null }
  return res.json()
}

async function getTradeDetail(tradeId, cookie, xcsrf) {
  const res = await fetch(`https://trades.roblox.com/v1/trades/${tradeId}`, {
    headers: {
      'x-csrf-token': xcsrf,
      cookie: `.ROBLOSECURITY=${cookie}`,
      origin: 'https://www.roblox.com',
      referer: 'https://www.roblox.com/trades',
      'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36'
    }
  })
  if (!res.ok) { console.warn('[inbound] detail failed', tradeId, res.status); return null }
  return res.json()
}

async function acceptTrade(tradeId, cookie, xcsrf, userId = null) {
  const res = await fetch(`https://trades.roblox.com/v1/trades/${tradeId}/accept`, {
    method: 'POST',
    headers: {
      'x-csrf-token': xcsrf,
      cookie: `.ROBLOSECURITY=${cookie}`,
      origin: 'https://www.roblox.com',
      referer: 'https://www.roblox.com/trades',
      'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36'
    }
  })
  if (res.ok) return true
  if (res.status === 403) {
    const chall = extractChallenge(res.headers)
    if (chall) {
      console.warn(`[challenge] accept ${tradeId}: ${chall.type}; continuing...`)
      // Get bound auth token if we have userId and challenge is 2FA
      let boundAuthToken = null
      if (userId && (chall.type || '').toLowerCase().includes('twostep')) {
        boundAuthToken = await getBoundAuthToken(cookie, xcsrf, userId)
      }
      const ok = await continueChallenge(chall, cookie, xcsrf, userId, boundAuthToken)
      if (ok) {
        const retry = await fetch(`https://trades.roblox.com/v1/trades/${tradeId}/accept`, {
          method: 'POST',
          headers: {
            'x-csrf-token': xcsrf,
            cookie: `.ROBLOSECURITY=${cookie}`,
            origin: 'https://www.roblox.com',
            referer: 'https://www.roblox.com/trades',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36'
          }
        })
        return retry.ok
      }
    }
  }
  const text = await res.text()
  console.error(`[inbound] accept failed ${res.status}: ${text.slice(0,300)}`)
  return false
}

function sleepSeconds(s) {
  return new Promise(resolve => setTimeout(resolve, s * 1000))
}

// --- Pending trades backfill polling ---
async function startPendingBackfillLoop() {
  while (true) {
    try {
      await pollPendingTradesOnce()
    } catch (e) {
      console.error('[pending] poll error', e)
    }
    await sleepSeconds(PENDING_POLL_SECONDS)
  }
}

async function pollPendingTradesOnce() {
  const { data, error } = await supabase
    .from('trades')
    .select('*')
    .eq('partner_username', bot.username)
    .eq('status', 'pending')
    .order('created_at', { ascending: true })

  if (error) {
    console.error('[pending] query error', error)
    return
  }
  if (!data || !data.length) return
  for (const row of data) {
    const id = row.id
    if (!id || processingTrades.has(id)) continue
    processingTrades.add(id)
    try {
      await handleTradeInserted(row)
    } catch (e) {
      console.error(`[pending] handle error for ${id}`, e)
    } finally {
      processingTrades.delete(id)
    }
  }
}
