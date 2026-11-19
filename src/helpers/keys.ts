import { secp256k1 } from '@noble/curves/secp256k1.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { config } from '../config.js'
import { Authority, Account, ExtendedAccount } from '../types.js'
import { KeyRole, PrivateKey } from './PrivateKey.js'
import { PublicKey } from './PublicKey.js'
import { Signature } from './Signature.js'
import { callRPC } from './call.js'

const ROLES: KeyRole[] = ['owner', 'active', 'posting', 'memo']

/** A random master password in the format Steem wallets use ("P5..."); store it safely */
export const createPassword = (): string => 'P' + PrivateKey.randomKey().toString()

/**
 * Derives an account's keys from its master password, the same way Steem wallets do.
 * Returns the private keys to give the user, the public keys, and the `owner`, `active`,
 * `posting`, and `memo_key` fields for `create_claimed_account`, `account_create`, or `account_update`.
 */
export const generateKeys = (username: string, password: string) => {
  const privateKeys = {} as Record<KeyRole, string>
  const publicKeys = {} as Record<KeyRole, string>
  for (const role of ROLES) {
    const key = PrivateKey.fromLogin(username, password, role)
    privateKeys[role] = key.toString()
    publicKeys[role] = key.createPublic().toString()
  }
  const authority = (key: string): Authority => ({
    weight_threshold: 1,
    account_auths: [],
    key_auths: [[key, 1]]
  })
  return {
    privateKeys,
    publicKeys,
    owner: authority(publicKeys.owner),
    active: authority(publicKeys.active),
    posting: authority(publicKeys.posting),
    memo_key: publicKeys.memo
  }
}

/** True if `wif` is a valid private key (checks format and checksum) */
export const isValidWif = (wif: string): boolean => {
  try {
    PrivateKey.fromString(wif)
    return true
  } catch {
    return false
  }
}

/** True if `key` is a valid public key for this chain (checks prefix, checksum, and curve point) */
export const isValidPublicKey = (key: string): boolean => {
  try {
    const publicKey = PublicKey.fromString(key)
    secp256k1.Point.fromBytes(publicKey.key)
    // Re-encoding recomputes the checksum, so a mismatch means a corrupted key
    return key.startsWith(config.address_prefix) && publicKey.toString() === key
  } catch {
    return false
  }
}

/**
 * Sign an arbitrary text message using a private key (compatible with Steem Keychain requestSignBuffer).
 * Hashes UTF-8 message bytes with SHA256, signs with ECDSA secp256k1, and returns a 130-char hex string.
 *
 * @param message Arbitrary string message to sign
 * @param key PrivateKey instance or WIF string
 * @returns 130-character hex signature
 */
export const signMessage = (message: string, key: PrivateKey | string): string => {
  const privateKey = typeof key === 'string' ? PrivateKey.fromString(key) : key
  const hash = sha256(new TextEncoder().encode(message))
  return privateKey.sign(hash).customToString()
}

/**
 * Verify a message signature against a public key or Steem account.
 * Recovers the public key from the 130-character hex signature and verifies match.
 *
 * @param message Original text message
 * @param signature 130-character hex signature returned from signMessage or Keychain
 * @param accountOrKey PublicKey, public key string ('STM...'), account username, or Account object
 * @param role Authority role to check against when verifying an account ('posting' by default)
 * @returns Promise resolving to true if valid, false otherwise
 */
export const verifyMessage = async (
  message: string,
  signature: string,
  accountOrKey: string | PublicKey | Account | ExtendedAccount,
  role: KeyRole = 'posting'
): Promise<boolean> => {
  try {
    const hash = sha256(new TextEncoder().encode(message))
    const sig = Signature.from(signature)
    const recoveredKey = sig.getPublicKey(hash).toString()

    if (accountOrKey instanceof PublicKey) {
      return recoveredKey === accountOrKey.toString()
    }

    if (typeof accountOrKey === 'string') {
      if (accountOrKey.startsWith(config.address_prefix)) {
        return recoveredKey === accountOrKey
      }
      const accounts = await callRPC<ExtendedAccount[]>('condenser_api.get_accounts', [
        [accountOrKey]
      ])
      if (!accounts || accounts.length === 0) return false
      accountOrKey = accounts[0]
    }

    const account = accountOrKey as Account | ExtendedAccount
    if (role === 'memo') {
      const memo = String(account.memo_key)
      return memo === recoveredKey
    }

    const authority = account[role]
    if (!authority || !authority.key_auths) return false

    return authority.key_auths.some(([authKey]) => {
      const authStr = typeof authKey === 'string' ? authKey : authKey.toString()
      return authStr === recoveredKey
    })
  } catch {
    return false
  }
}

/**
 * Identify the key role ('owner' | 'active' | 'posting' | 'memo' | null) of a key for an account.
 *
 * @param accountOrName Account object or Steem username
 * @param key PrivateKey, PublicKey, or key string
 * @returns Key role name or null if key does not belong to the account
 */
export const getKeyRole = async (
  accountOrName: string | Account | ExtendedAccount,
  key: string | PublicKey | PrivateKey
): Promise<KeyRole | null> => {
  let pubKeyStr: string
  if (key instanceof PrivateKey) {
    pubKeyStr = key.createPublic().toString()
  } else if (key instanceof PublicKey) {
    pubKeyStr = key.toString()
  } else if (typeof key === 'string') {
    if (key.startsWith(config.address_prefix)) {
      pubKeyStr = key
    } else {
      pubKeyStr = PrivateKey.fromString(key).createPublic().toString()
    }
  } else {
    return null
  }

  let account: Account | ExtendedAccount
  if (typeof accountOrName === 'string') {
    const accounts = await callRPC<ExtendedAccount[]>('condenser_api.get_accounts', [
      [accountOrName]
    ])
    if (!accounts || accounts.length === 0) return null
    account = accounts[0]
  } else {
    account = accountOrName
  }

  if (account.memo_key) {
    const memoStr = String(account.memo_key)
    if (memoStr === pubKeyStr) return 'memo'
  }

  const checkRole = (role: 'posting' | 'active' | 'owner'): boolean => {
    const auth = account[role]
    if (!auth || !auth.key_auths) return false
    return auth.key_auths.some(([k]) => {
      const kStr = typeof k === 'string' ? k : k.toString()
      return kStr === pubKeyStr
    })
  }

  if (checkRole('posting')) return 'posting'
  if (checkRole('active')) return 'active'
  if (checkRole('owner')) return 'owner'

  return null
}
