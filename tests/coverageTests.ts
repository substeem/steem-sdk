import { isDeepStrictEqual } from 'node:util'
import {
  Transaction,
  chainTime,
  authority,
  PrivateKey,
  PublicKey,
  Signature,
  Memo,
  utils,
  callREST,
  config,
  callRPC,
  callRPCBatch,
  callWithQuorum,
  streamBlocks,
  streamBlockNumbers,
  streamOperations,
  Client,
  type AppliedOperation,
  type Block,
  type Operation,
  type Account
} from '../src/index.js'

// Test data
const testPrivateKey = '5JdeC9P7Pbd1uGdFVEsJ41EkEnADbbHGq6p1BwFxm6txNBsQnsw'
const testPublicKey = 'STM8m5UgaFAAYQRuaNejYdS8FVLVp9Ss3K1qAVk5de6F8s3HnVbvA'
const testUsername = 'testuser'

export const coverageTests = async () => {
  console.log('Running coverage tests...\n')

  let totalTests = 0
  let passedTests = 0

  // Helper function to run tests
  const runTest = async (name: string, testFn: () => boolean | Promise<boolean>) => {
    totalTests++
    try {
      const result = await testFn()
      if (result) {
        console.log(`✅ ${name}`)
        passedTests++
      } else {
        console.log(`❌ ${name}`)
      }
    } catch (error) {
      console.log(`❌ ${name}:`, error)
    }
  }

  // PrivateKey tests
  console.log('Testing PrivateKey...')

  await runTest('PrivateKey.fromString', () => {
    const key = PrivateKey.fromString(testPrivateKey)
    return key.toString() === testPrivateKey
  })

  await runTest('PrivateKey.from (string)', () => {
    const key = PrivateKey.from(testPrivateKey)
    return key.toString() === testPrivateKey
  })

  await runTest('PrivateKey.from (Uint8Array)', () => {
    const bytes = new Uint8Array([0x1, 0x2, 0x3])
    // Since it validates secp256k1, this should throw, but let's catch
    // Actually, the constructor checks, so invalid key throws
    try {
      new PrivateKey(bytes)
      return false // Should not reach here
    } catch {
      return true // Correctly throws
    }
  })

  await runTest('PrivateKey.fromSeed', () => {
    const seed = 'test seed phrase'
    const key = PrivateKey.fromSeed(seed)
    // Just check it creates without error
    return key instanceof PrivateKey
  })

  await runTest('PrivateKey.fromLogin', () => {
    const key = PrivateKey.fromLogin(testUsername, 'password123')
    return key instanceof PrivateKey
  })

  await runTest('PrivateKey.randomKey', () => {
    const key = PrivateKey.randomKey()
    return key instanceof PrivateKey
  })

  await runTest('PrivateKey.createPublic', () => {
    const privKey = PrivateKey.fromString(testPrivateKey)
    const pubKey = privKey.createPublic()
    return pubKey.toString() === testPublicKey
  })

  await runTest('PrivateKey.toString', () => {
    const key = PrivateKey.fromString(testPrivateKey)
    return key.toString() === testPrivateKey
  })

  await runTest('PrivateKey.inspect', () => {
    const key = PrivateKey.fromString(testPrivateKey)
    const inspectStr = key.inspect()
    return inspectStr.startsWith('PrivateKey: 5JdeC9...BsQnsw')
  })

  await runTest('PrivateKey.getSharedSecret', () => {
    const privKey = PrivateKey.fromString(testPrivateKey)
    const pubKey = PublicKey.fromString(testPublicKey)
    const secret = privKey.getSharedSecret(pubKey)
    return secret.length === 64
  })

  await runTest('PrivateKey.sign', () => {
    const privKey = PrivateKey.fromString(testPrivateKey)
    const message = new Uint8Array(32).fill(0)
    const sig = privKey.sign(message)
    return sig instanceof Signature
  })

  // PublicKey tests
  console.log('Testing PublicKey...')

  await runTest('PublicKey.fromString', () => {
    const key = PublicKey.fromString(testPublicKey)
    return key.toString() === testPublicKey
  })

  await runTest('PublicKey.from (string)', () => {
    const key = PublicKey.from(testPublicKey)
    return key.toString() === testPublicKey
  })

  await runTest('PublicKey.from (PublicKey instance)', () => {
    const key1 = PublicKey.fromString(testPublicKey)
    const key2 = PublicKey.from(key1)
    return key1 === key2
  })

  await runTest('PublicKey.verify', () => {
    const privKey = PrivateKey.fromString(testPrivateKey)
    const pubKey = privKey.createPublic()
    const message = new Uint8Array(32).fill(0)
    const sig = privKey.sign(message)
    return pubKey.verify(message, sig)
  })

  await runTest('PublicKey.toString', () => {
    const key = PublicKey.fromString(testPublicKey)
    return key.toString() === testPublicKey
  })

  await runTest('PublicKey.toJSON', () => {
    const key = PublicKey.fromString(testPublicKey)
    return key.toJSON() === testPublicKey
  })

  await runTest('PublicKey.inspect', () => {
    const key = PublicKey.fromString(testPublicKey)
    const inspectStr = key.inspect()
    return inspectStr === `PublicKey: ${testPublicKey}`
  })

  // Signature tests
  console.log('Testing Signature...')

  await runTest('Signature.from', () => {
    const privKey = PrivateKey.fromString(testPrivateKey)
    const message = new Uint8Array(32).fill(0)
    const sig = privKey.sign(message)
    const sigStr = sig.customToString()
    const reconstructed = Signature.from(sigStr)
    return reconstructed.customToString() === sigStr
  })

  await runTest('Signature.toBuffer', () => {
    const privKey = PrivateKey.fromString(testPrivateKey)
    const message = new Uint8Array(32).fill(0)
    const sig = privKey.sign(message)
    const buf = sig.toBuffer()
    return buf.length === 65
  })

  await runTest('Signature.customToString', () => {
    const privKey = PrivateKey.fromString(testPrivateKey)
    const message = new Uint8Array(32).fill(0)
    const sig = privKey.sign(message)
    const str = sig.customToString()
    return str.length === 130 && /^[0-9a-fA-F]+$/.test(str)
  })

  await runTest('Signature.getPublicKey', () => {
    const privKey = PrivateKey.fromString(testPrivateKey)
    const message = new Uint8Array(32).fill(0)
    const sig = privKey.sign(message)
    const recoveredPub = sig.getPublicKey(message)
    const expectedPub = privKey.createPublic()
    return recoveredPub.toString() === expectedPub.toString()
  })

  // Memo tests
  console.log('Testing Memo...')

  await runTest('Memo.encode (plaintext)', () => {
    const memo = 'This is a plain text memo'
    const encoded = Memo.encode(testPrivateKey, testPublicKey, memo)
    return encoded === memo
  })

  await runTest('Memo.encode (encrypted)', () => {
    const memo = '#This is an encrypted memo'
    const encoded = Memo.encode(testPrivateKey, testPublicKey, memo)
    return encoded.startsWith('#') && encoded !== memo
  })

  await runTest('Memo.decode (plaintext)', () => {
    const memo = 'Plain text memo'
    const decoded = Memo.decode(testPrivateKey, memo)
    return decoded === memo
  })

  // For encrypted, we need to encode first then decode
  await runTest('Memo.decode (encrypted)', () => {
    try {
      const original = '#Test encrypted message'
      const encoded = Memo.encode(testPrivateKey, testPublicKey, original)
      const decoded = Memo.decode(testPrivateKey, encoded)
      return decoded === original
    } catch (e) {
      console.error('Memo test error:', e)
      return false
    }
  })

  await runTest('Memo.encodeForAccount', async () => {
    const sender = PrivateKey.randomKey()
    const encoded = await Memo.encodeForAccount(sender, 'steemit', '#hello')
    const missing = await Memo.encodeForAccount(sender, 'no-such-acct-x1', '#x').catch(
      (e) => e.message
    )
    // the sender can decrypt too, which proves it used the account's memo key pair
    return (
      encoded.startsWith('#') &&
      encoded !== '#hello' &&
      Memo.decode(sender, encoded) === '#hello' &&
      missing === 'Account not found: no-such-acct-x1'
    )
  })

  // Utils tests
  console.log('Testing utils...')

  await runTest('utils.validateUsername (valid)', () => {
    const error = utils.validateUsername('alice')
    return error === null
  })

  await runTest('utils.validateUsername (invalid: empty)', () => {
    const error = utils.validateUsername('')
    return error !== null
  })

  await runTest('utils.validateUsername (invalid: too short)', () => {
    const error = utils.validateUsername('ab')
    return error !== null
  })

  await runTest('utils.validateUsername (invalid: too long)', () => {
    const error = utils.validateUsername('a'.repeat(17))
    return error !== null
  })

  await runTest('utils.validateUsername (invalid: starts with digit)', () => {
    const error = utils.validateUsername('1alice')
    return error !== null
  })

  await runTest('utils.validateUsername (invalid: uppercase)', () => {
    const error = utils.validateUsername('Alice')
    return error !== null
  })

  await runTest('utils.makeBitMaskFilter', () => {
    const filter = utils.makeBitMaskFilter([0, 1, 64])
    return Array.isArray(filter) && filter.length === 2
  })

  await runTest('utils.buildWitnessSetProperties', () => {
    const props = {
      key: testPublicKey,
      account_creation_fee: '3.000 STEEM',
      maximum_block_size: 65536
    }
    const result = utils.buildWitnessSetProperties('testuser', props)
    return (
      Array.isArray(result) &&
      result[0] === 'witness_set_properties' &&
      JSON.stringify(result[1]) ===
        '{"extensions":[],"owner":"testuser","props":[["account_creation_fee","b80b00000000000003535445454d0000"],["key","03fdf4907810a9f5d9462a1ae09feee5ab205d32798b0ffcc379442021f84c5bbf"],["maximum_block_size","00000100"]]}'
    )
  })

  console.log('Testing utils chain math...')

  // Snapshot of a powering-down account from condenser_api.get_accounts
  const stakeAccount = {
    vesting_shares: '177805832.499280 VESTS',
    delegated_vesting_shares: '619129.407589 VESTS',
    received_vesting_shares: '0.000000 VESTS',
    vesting_withdraw_rate: '12398735.810485 VESTS',
    to_withdraw: 161183565536299,
    withdrawn: 123987358104850,
    voting_manabar: { current_mana: 153710560566990, last_update_time: 1794864276 },
    downvote_manabar: { current_mana: 41196991820301, last_update_time: 1794864276 }
  }
  // The chain's max_rc for the same account is effective vests - delegated RC + creation adjustment
  const chainMaxMana = 152525900134202 + 12264087895977 - 2020748973

  await runTest('utils.parseAsset (string and NAI)', () => {
    const str = utils.parseAsset('1.500 STEEM')
    const nai = utils.parseAsset({ amount: '1500', precision: 3, nai: '@@000000013' })
    try {
      utils.parseAsset('abc')
      return false
    } catch {
      return (
        str.amount === 1.5 &&
        str.symbol === 'STEEM' &&
        nai.amount === 1.5 &&
        nai.symbol === 'SBD'
      )
    }
  })

  await runTest('utils.vestsToSP and utils.spToVests', async () => {
    const props = await callRPC('condenser_api.get_dynamic_global_properties')
    const sp = await utils.vestsToSP(props.total_vesting_shares)
    const fund = utils.parseAsset(props.total_vesting_fund_steem).amount
    // the cached props may be a block apart from ours
    return (
      Math.abs(sp / fund - 1) < 1e-4 &&
      Math.abs((await utils.spToVests(await utils.vestsToSP(1000))) - 1000) < 1e-9
    )
  })

  await runTest('utils mana matches chain values', async () => {
    const at = (seconds: number) => (1794864276 + seconds) * 1000
    const up = await utils.getVotingMana(stakeAccount, at(0))
    const down = await utils.getDownvoteMana(stakeAccount, at(0))
    const rc = await utils.getRCMana(
      { max_rc: 100, rc_manabar: { current_mana: 50, last_update_time: 1794864276 } },
      at(43200)
    )
    return (
      up.max === chainMaxMana &&
      up.current === 153710560566990 &&
      // one hour regenerates max / 120
      (await utils.getVotingMana(stakeAccount, at(3600))).current === 155083793627666 &&
      (await utils.getVotingMana(stakeAccount, at(432000))).percentage === 100 &&
      down.max === 41196991820301 &&
      down.percentage === 100 &&
      rc.current === 60 &&
      rc.percentage === 60
    )
  })

  await runTest('utils helpers fetch by name with one cached request', async () => {
    // A fake node, so the request count does not depend on live nodes failing over
    const realFetch = globalThis.fetch
    const requests: string[] = []
    globalThis.fetch = async (_input: string | URL | Request, init?: RequestInit) => {
      const { id, method, params } = JSON.parse(String(init?.body))
      requests.push(method)
      const result =
        method === 'rc_api.find_rc_accounts'
          ? {
              rc_accounts: [{ max_rc: 100, rc_manabar: { current_mana: 100, last_update_time: 0 } }]
            }
          : params[0][0] === 'cache-test-ok'
            ? [stakeAccount]
            : []
      return Response.json({ jsonrpc: '2.0', id, result })
    }
    try {
      const [up, down] = await Promise.all([
        utils.getVotingMana('cache-test-ok'),
        utils.getDownvoteMana('cache-test-ok')
      ])
      const again = await utils.getEffectiveVests('cache-test-ok')
      const rc = await utils.getRCMana('cache-test-ok')
      const missing = await utils.getVotingMana('cache-test-no').catch((e) => e.message)
      return (
        // one get_accounts shared by three helpers, one rc_api call, one lookup that finds nothing
        requests.join() ===
          'condenser_api.get_accounts,rc_api.find_rc_accounts,condenser_api.get_accounts' &&
        up.max === chainMaxMana &&
        down.max === Math.floor(chainMaxMana * 0.25) &&
        Math.abs(again * 1e6 - chainMaxMana) < 1 &&
        rc.max === 100 &&
        missing === 'Account not found: cache-test-no'
      )
    } finally {
      globalThis.fetch = realFetch
    }
  })

  await runTest('utils.getVoteRShares matches an on-chain vote', async () => {
    // A 5.34% vote by a powering-down account; the chain gave it 636980901 rshares
    const voter = {
      vesting_shares: '692587.108537 VESTS',
      delegated_vesting_shares: '0.000000 VESTS',
      received_vesting_shares: '0.000000 VESTS',
      vesting_withdraw_rate: '49346.564795 VESTS',
      to_withdraw: 641505342326,
      withdrawn: 246732823975,
      voting_manabar: { current_mana: 642553562841, last_update_time: 1794864393 },
      downvote_manabar: { current_mana: 160810135935, last_update_time: 1794864393 }
    }
    return (
      (await utils.getVoteRShares(voter, 534)) === 636980901 &&
      (await utils.getVoteRShares(voter, -534)) === -636980901 &&
      // below the dust threshold a vote adds nothing
      (await utils.getVoteRShares(voter, 1)) === 0
    )
  })

  await runTest('utils.getVoteValue', async () => {
    const fund = await callRPC('condenser_api.get_reward_fund', ['post'])
    const price = await callRPC('condenser_api.get_current_median_history_price')
    // a full vote: 2% of max mana minus dust, as a share of the pool, in SBD
    const rshares = Math.ceil(chainMaxMana * 0.02) - 50_000_000
    const expected =
      ((rshares * utils.parseAsset(fund.reward_balance).amount) / Number(fund.recent_claims)) *
      (utils.parseAsset(price.base).amount / utils.parseAsset(price.quote).amount)
    // the cached fund may be a block apart from ours
    return Math.abs((await utils.getVoteValue(stakeAccount)) / expected - 1) < 1e-3
  })

  await runTest('utils.formatReputation', () => {
    return (
      Math.floor(utils.formatReputation('225722985673795')) === 73 &&
      utils.formatReputation(0) === 25 &&
      utils.formatReputation(-1234567890123) < 0
    )
  })

  await runTest('utils.createPermlink', () => {
    const permlink = utils.createPermlink('Héllo, Wörld — Café!')
    const reply = utils.createPermlink()
    return (
      /^hello-world-cafe-[0-9a-f]{12}$/.test(permlink) &&
      /^[0-9a-f]{12}$/.test(reply) &&
      reply !== utils.createPermlink()
    )
  })

  await runTest('utils mana fullAt', async () => {
    const now = 1794864276 * 1000
    const up = await utils.getVotingMana(stakeAccount, now)
    const secondsToFull = ((chainMaxMana - 153710560566990) * 432000) / chainMaxMana
    const full = await utils.getDownvoteMana(stakeAccount, now)
    return (
      Math.abs(up.fullAt.getTime() - (now + secondsToFull * 1000)) < 1 &&
      full.fullAt.getTime() === now
    )
  })

  await runTest('utils price, APR, and account value', async () => {
    const sbd = await utils.steemToSbd(1)
    const spApr = await utils.getSpApr()
    const sbdApr = await utils.getSbdApr()
    return (
      sbd > 0 &&
      Math.abs((await utils.sbdToSteem(sbd)) - 1) < 1e-12 &&
      spApr > 0 &&
      spApr < 10 &&
      sbdApr >= 0 &&
      sbdApr <= 100
    )
  })

  await runTest('utils social operations', () => {
    const json = (op: [string, { id: string; json: string }]) => `${op[1].id} ${op[1].json}`
    return (
      json(utils.follow('a', 'b')) ===
        'follow ["follow",{"follower":"a","following":"b","what":["blog"]}]' &&
      json(utils.unfollow('a', 'b')) ===
        'follow ["follow",{"follower":"a","following":"b","what":[]}]' &&
      json(utils.mute('a', 'b')) ===
        'follow ["follow",{"follower":"a","following":"b","what":["ignore"]}]' &&
      json(utils.blacklist('a', 'b')) ===
        'follow ["follow",{"follower":"a","following":"b","what":["blacklist"]}]' &&
      json(utils.unblacklist('a', 'b')) ===
        'follow ["follow",{"follower":"a","following":"b","what":["unblacklist"]}]' &&
      json(utils.followBlacklist('a', 'b')) ===
        'follow ["follow",{"follower":"a","following":"b","what":["follow_blacklist"]}]' &&
      json(utils.unfollowMuted('a', 'b')) ===
        'follow ["follow",{"follower":"a","following":"b","what":["unfollow_muted"]}]' &&
      json(utils.reblog('a', 'b', 'p')) ===
        'follow ["reblog",{"account":"a","author":"b","permlink":"p"}]' &&
      json(utils.subscribe('a', 'steem-1')) === 'community ["subscribe",{"community":"steem-1"}]' &&
      json(utils.unsubscribe('a', 'steem-1')) ===
        'community ["unsubscribe",{"community":"steem-1"}]' &&
      utils.follow('a', 'b')[1].required_posting_auths[0] === 'a'
    )
  })

  await runTest('utils key helpers', () => {
    const keys = utils.generateKeys('alice', 'P5Kexample')
    const posting = PrivateKey.fromLogin('alice', 'P5Kexample', 'posting')
    const password = utils.createPassword()
    const pub = keys.publicKeys.owner
    const corrupted = pub.slice(0, -1) + (pub.endsWith('x') ? 'y' : 'x')
    return (
      keys.privateKeys.posting === posting.toString() &&
      keys.publicKeys.posting === posting.createPublic().toString() &&
      keys.owner.key_auths[0][0] === pub &&
      keys.memo_key === keys.publicKeys.memo &&
      password.startsWith('P5') &&
      utils.isValidWif(password.slice(1)) &&
      !utils.isValidWif('5Jbad') &&
      utils.isValidPublicKey(pub) &&
      !utils.isValidPublicKey(corrupted) &&
      !utils.isValidPublicKey('junk')
    )
  })

  // Transaction additional tests
  console.log('Testing Transaction extras...')

  await runTest('Transaction.sign & verify', async () => {
    const trx = new Transaction()
    await trx.addOperation('transfer', {
      from: 'testuser',
      to: 'alice',
      amount: '1.000 STEEM',
      memo: 'test'
    })
    const privKey = PrivateKey.fromString(testPrivateKey)
    trx.sign(privKey)
    return privKey
      .createPublic()
      .verify(trx.digest().digest, Signature.from(trx.transaction!.signatures[0]))
  })

  await runTest('Transaction.digest', async () => {
    const trx = new Transaction()
    await trx.addOperation('transfer', {
      from: 'testuser',
      to: 'alice',
      amount: '1.000 STEEM',
      memo: 'test'
    })
    const digest = trx.digest()
    return digest.digest.length === 32 && typeof digest.txId === 'string'
  })

  await runTest('Transaction.addSignature', async () => {
    const trx = new Transaction()
    await trx.addOperation('transfer', {
      from: 'testuser',
      to: 'alice',
      amount: '1.000 STEEM',
      memo: 'test'
    })
    const signature = '1f6a9a9c4e6a8b7...2d00' // 130 char hex
    const paddedSig = signature.padEnd(130, '0')
    const signed = trx.addSignature(paddedSig)
    return signed.signatures.includes(paddedSig)
  })

  console.log('Testing API calls...')

  await runTest('callRPC(condenser_api.get_accounts)', async () => {
    try {
      const res = await callRPC('condenser_api.get_accounts', [['substeem.app']])
      return res[0].name === 'substeem.app'
    } catch {
      return false
    }
  })

  await runTest('callRPC() failover', async () => {
    const temp = config.nodes
    try {
      config.nodes = ['https://bad-url-very-very-bad-url', 'https://another-bad-url', ...temp]
      const res = await callRPC('condenser_api.get_accounts', [['substeem.app']])
      return res[0].name === 'substeem.app'
    } catch {
      return false
    } finally {
      config.nodes = temp
    }
  })

  await runTest('callRPCBatch() returns results in params order', async () => {
    const blocks = await callRPCBatch('condenser_api.get_block', [[3], [1], [2]])
    return blocks.map((b) => parseInt(b.block_id.slice(0, 8), 16)).join() === '3,1,2'
  })

  await runTest('callWithQuorum(condenser_api.get_accounts)', async () => {
    try {
      const res = await callWithQuorum('condenser_api.get_accounts', [['substeem.app']])
      return res[0].name === 'substeem.app'
    } catch {
      return false
    }
  })

  await runTest('callWithQuorum() failover', async () => {
    const temp = config.nodes
    try {
      config.nodes = [
        'https://bad-url-very-very-bad-url',
        'https://another-bad-urla',
        'https://another-bad-urlb',
        'https://another-bad-urlc',
        ...temp
      ]
      const res = await callWithQuorum('condenser_api.get_accounts', [['substeem.app']])
      return res[0].name === 'substeem.app'
    } catch {
      return false
    } finally {
      config.nodes = temp
    }
  })

  console.log('Testing Client...')

  await runTest('Client.database.getDynamicGlobalProperties', async () => {
    const client = new Client()
    const props = await client.database.getDynamicGlobalProperties()
    return typeof props.head_block_number === 'number' && props.head_block_number > 0
  })

  await runTest('Client.database.getAccounts', async () => {
    const client = new Client()
    const accounts = await client.database.getAccounts(['substeem.app'])
    return accounts.length === 1 && accounts[0].name === 'substeem.app'
  })

  await runTest('Client.database.getVestingDelegations', async () => {
    const client = new Client()
    const delegations = await client.database.getVestingDelegations('steemit', '', 1)
    return Array.isArray(delegations)
  })

  await runTest('Client.broadcast.sign', async () => {
    const client = new Client()
    const privKey = PrivateKey.fromString(testPrivateKey)
    const rawTx = {
      expiration: '2026-11-19T12:00:00',
      extensions: [],
      operations: [
        [
          'vote',
          {
            voter: 'alice',
            author: 'bob',
            permlink: 'test',
            weight: 10000
          }
        ]
      ],
      ref_block_num: 1234,
      ref_block_prefix: 5678,
      signatures: []
    }
    const signed = client.broadcast.sign(rawTx, privKey)
    return Array.isArray(signed.signatures) && signed.signatures.length === 1
  })

  await runTest('Client instance keeps isolated nodes without mutating config.nodes', async () => {
    const originalNodes = [...config.nodes]
    const isolatedClient = new Client('https://api.moecki.online')
    const isolatedNodesMatch =
      isolatedClient.nodes.length === 1 && isolatedClient.nodes[0] === 'https://api.moecki.online'
    const configUntouched = isDeepStrictEqual(config.nodes, originalNodes)
    const props = await isolatedClient.database.getDynamicGlobalProperties()
    return isolatedNodesMatch && configUntouched && props.head_block_number > 0
  })

  console.log('Testing streamBlocks...')

  await runTest('streamBlockNumbers() yields a past range in order and stops', async () => {
    const nums: number[] = []
    for await (const num of streamBlockNumbers({ from: 90000000, to: 90000044 })) {
      nums.push(num)
    }
    return nums.length === 45 && nums.every((num, i) => num === 90000000 + i)
  })

  await runTest('streamBlockNumbers() follows new blocks', async () => {
    const nums: number[] = []
    for await (const num of streamBlockNumbers()) {
      nums.push(num)
      if (nums.length === 2) break
    }
    return nums[1] === nums[0] + 1
  })

  await runTest('streamBlocks() yields a past range in order and stops', async () => {
    const blocks: Block[] = []
    for await (const block of streamBlocks({ from: 90000000, to: 90000049 })) {
      blocks.push(block)
    }
    return (
      blocks.length === 50 &&
      blocks.every(
        (b, i) =>
          b.block_num === 90000000 + i &&
          parseInt(b.block_id.slice(0, 8), 16) === b.block_num &&
          (i === 0 || b.previous === blocks[i - 1].block_id)
      )
    )
  })

  await runTest('streamBlocks() follows new blocks', async () => {
    const nums = []
    for await (const block of streamBlocks()) {
      nums.push(block.block_num)
      if (nums.length === 2) break
    }
    return nums[1] === nums[0] + 1
  })

  await runTest('streamOperations() matches block operations plus virtual ones', async () => {
    const range = { from: 90000000, to: 90000004 }
    const blockOps: Operation[] = []
    for await (const block of streamBlocks(range)) {
      for (const tx of block.transactions) blockOps.push(...tx.operations)
    }
    const ops: AppliedOperation[] = []
    for await (const op of streamOperations(range)) ops.push(op)
    const virtualOps: AppliedOperation[] = []
    for await (const op of streamOperations({ ...range, only_virtual: true })) virtualOps.push(op)
    // On Steem, virtual operations have trx_id === '0000000000000000000000000000000000000000'
    const isVirtual = (o: AppliedOperation) =>
      o.trx_id === '0000000000000000000000000000000000000000' || !!o.virtual_op
    const real = ops.filter((o) => o.trx_id !== '0000000000000000000000000000000000000000')
    const c1 = isDeepStrictEqual(
      real.map((o) => o.op),
      blockOps
    )
    const c2 = virtualOps.length === ops.length - real.length
    const c3 = virtualOps.every((o) => o.trx_id === '0000000000000000000000000000000000000000')
    const c4 = new Set(ops.map((o) => o.block)).size === 5
    return c1 && c2 && c3 && c4
  })

  await runTest(
    'streamOperations() with operation filter yields only matching operations',
    async () => {
      const range = { from: 90000000, to: 90000004 }
      const filteredOps: AppliedOperation[] = []
      for await (const op of streamOperations('producer_reward', range)) {
        filteredOps.push(op)
      }
      return (
        filteredOps.length > 0 && filteredOps.every((o) => o.op[0] === 'producer_reward')
      )
    }
  )

  console.log('Testing chainTime and authority helpers...')

  await runTest('chainTime parses ISO with and without Z', () => {
    const t1 = chainTime('2026-11-19T06:00:00Z')
    const t2 = chainTime('2026-11-19T06:00:00')
    return t1 === t2 && t1 === 1795068000000
  })

  await runTest('authority.hasAccountAuthority', () => {
    const mockAccount: any = {
      name: 'alice',
      posting: {
        weight_threshold: 1,
        account_auths: [['substeem.app', 1]],
        key_auths: []
      }
    }
    const has = authority.hasAccountAuthority(mockAccount, 'posting', 'substeem.app')
    const notHas = authority.hasAccountAuthority(mockAccount, 'posting', 'other.app')
    return has === true && notHas === false
  })

  await runTest('authority.grantAccountAuthority sorts alphabetically', () => {
    const mockAccount: any = {
      name: 'alice',
      posting: {
        weight_threshold: 1,
        account_auths: [['zebra.app', 1]],
        key_auths: []
      }
    }
    const [opName, op] = authority.grantAccountAuthority(mockAccount, 'posting', 'alpha.app', 1)
    if (opName !== 'account_update2' || !op.posting) return false
    const auths = op.posting.account_auths
    return (
      auths.length === 2 &&
      auths[0][0] === 'alpha.app' &&
      auths[1][0] === 'zebra.app'
    )
  })

  await runTest('authority.revokeAccountAuthority with lockout check', () => {
    const mockAccount: any = {
      name: 'alice',
      active: {
        weight_threshold: 1,
        account_auths: [['alpha.app', 1], ['zebra.app', 1]],
        key_auths: []
      }
    }
    const [opName, op] = authority.revokeAccountAuthority(mockAccount, 'active', 'alpha.app')
    if (opName !== 'account_update2' || !op.active) return false
    const auths = op.active.account_auths
    const ok = auths.length === 1 && auths[0][0] === 'zebra.app'

    // Verify lockout error thrown if last remaining auth is removed
    let threw = false
    try {
      const emptyAccount: any = {
        name: 'alice',
        active: {
          weight_threshold: 1,
          account_auths: [['only.app', 1]],
          key_auths: []
        }
      }
      authority.revokeAccountAuthority(emptyAccount, 'active', 'only.app')
    } catch {
      threw = true
    }
    return ok && threw
  })

  console.log('Testing message signing, verification and getKeyRole...')

  await runTest('utils.signMessage and utils.verifyMessage', async () => {
    const privKey = PrivateKey.fromString(testPrivateKey)
    const pubKey = privKey.createPublic()
    const msg = 'Login to Substeem at ' + Date.now()
    const sig = utils.signMessage(msg, privKey)

    const validWithPub = await utils.verifyMessage(msg, sig, pubKey)
    const validWithStr = await utils.verifyMessage(msg, sig, pubKey.toString())
    const invalidWithAlteredMsg = await utils.verifyMessage(msg + 'x', sig, pubKey)

    const mockAccount: any = {
      name: 'testuser',
      memo_key: pubKey.toString(),
      posting: {
        weight_threshold: 1,
        account_auths: [],
        key_auths: [[pubKey.toString(), 1]]
      }
    }
    const validWithAccount = await utils.verifyMessage(msg, sig, mockAccount, 'posting')
    const validWithMemo = await utils.verifyMessage(msg, sig, mockAccount, 'memo')

    return (
      validWithPub &&
      validWithStr &&
      !invalidWithAlteredMsg &&
      validWithAccount &&
      validWithMemo
    )
  })

  await runTest('utils.getKeyRole', async () => {
    const privKey = PrivateKey.fromString(testPrivateKey)
    const pubKey = privKey.createPublic()
    const otherKey = PrivateKey.randomKey().createPublic()

    const mockAccount: any = {
      name: 'testuser',
      memo_key: pubKey.toString(),
      posting: {
        weight_threshold: 1,
        account_auths: [],
        key_auths: [[pubKey.toString(), 1]]
      },
      active: {
        weight_threshold: 1,
        account_auths: [],
        key_auths: []
      },
      owner: {
        weight_threshold: 1,
        account_auths: [],
        key_auths: []
      }
    }

    const postingRole = await utils.getKeyRole(mockAccount, pubKey)
    const noneRole = await utils.getKeyRole(mockAccount, otherKey)

    return (postingRole === 'posting' || postingRole === 'memo') && noneRole === null
  })

  console.log('Testing commentOptions with alphabetical beneficiary sorting...')

  await runTest('utils.commentOptions beneficiary sorting', () => {
    const [opName, op] = utils.commentOptions('author', 'permlink', {
      beneficiaries: [
        { account: 'zebra', weight: 500 },
        { account: 'alpha', weight: 1000 },
        { account: 'beta', weight: 500 }
      ]
    })
    if (opName !== 'comment_options') return false
    const beneficiaries = op.extensions[0][1].beneficiaries
    return (
      beneficiaries.length === 3 &&
      beneficiaries[0].account === 'alpha' &&
      beneficiaries[1].account === 'beta' &&
      beneficiaries[2].account === 'zebra'
    )
  })

  console.log('Testing accountExists, getProfile, and getRequiredRole...')

  await runTest('utils.accountExists', async () => {
    const invalid = await utils.accountExists('INVALID_NAME!')
    const exists = await utils.accountExists('steemit')
    return invalid === false && exists === true
  })

  await runTest('utils.getProfile', async () => {
    const mockAccount: any = {
      posting_json_metadata: JSON.stringify({
        profile: {
          name: 'Steemit Team',
          about: 'Building Steem'
        }
      })
    }
    const profile = await utils.getProfile(mockAccount)
    return profile.name === 'Steemit Team' && profile.about === 'Building Steem'
  })

  await runTest('utils.getRequiredRole', () => {
    const p1 = utils.getRequiredRole('vote') === 'posting'
    const p2 = utils.getRequiredRole('comment') === 'posting'
    const p3 = utils.getRequiredRole('custom_json') === 'posting'
    const a1 = utils.getRequiredRole('transfer') === 'active'
    const a2 = utils.getRequiredRole('delegate_vesting_shares') === 'active'
    const o1 = utils.getRequiredRole('account_update') === 'owner'
    const o2 = utils.getRequiredRole('change_recovery_account') === 'owner'
    return p1 && p2 && p3 && a1 && a2 && o1 && o2
  })

  console.log(`\nCoverage tests completed: ${passedTests}/${totalTests} passed`)
  if (passedTests !== totalTests) {
    throw new Error(`${totalTests - passedTests} coverage test(s) failed`)
  }
}
