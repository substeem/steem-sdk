import { Serializer } from './serializer.js'
import { ByteBuffer } from './ByteBuffer.js'
import { PublicKey } from './PublicKey.js'
import { Asset } from './Asset.js'
import { bytesToHex, randomBytes } from '@noble/hashes/utils.js'
import { callRPC } from './call.js'
import type {
  CommentOptionsOperation,
  Beneficiary,
  Account,
  ExtendedAccount,
  OperationName
} from '../types.js'
import type { KeyRole } from './PrivateKey.js'

export * from './chainMath.js'
export * from './keys.js'
export * from './social.js'
export * from './authority.js'

/** Constant-time comparison of two Uint8Arrays to prevent timing attacks */
export const equalBytes = (a: Uint8Array, b: Uint8Array): boolean => {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i]
  }
  return diff === 0
}

export interface WitnessProps {
  account_creation_fee?: string
  account_subsidy_budget?: number
  account_subsidy_decay?: number
  key: PublicKey | string
  maximum_block_size?: number
  new_signing_key?: PublicKey | string | null
  sbd_exchange_rate?: { base: string; quote: string }
  sbd_interest_rate?: number
  url?: string
}

/** Return null for a valid username */
export const validateUsername = (username: string): null | string => {
  let suffix = 'Account name should '
  if (!username) {
    return suffix + 'not be empty.'
  }
  const length = username.length
  if (length < 3) {
    return suffix + 'be longer.'
  }
  if (length > 16) {
    return suffix + 'be shorter.'
  }
  if (/\./.test(username)) {
    suffix = 'Each account segment should '
  }
  const ref = username.split('.')
  const len = ref.length
  for (let i = 0; i < len; i++) {
    const label = ref[i]
    if (!/^[a-z]/.test(label)) {
      return suffix + 'start with a lowercase letter.'
    }
    if (!/^[a-z0-9-]*$/.test(label)) {
      return suffix + 'have only lowercase letters, digits, or dashes.'
    }
    if (!/[a-z0-9]$/.test(label)) {
      return suffix + 'end with a lowercase letter or digit.'
    }
    if (!(label.length >= 3)) {
      return suffix + 'be longer'
    }
  }
  return null
}

export const operations = {
  vote: 0,
  comment: 1,
  transfer: 2,
  transfer_to_vesting: 3,
  withdraw_vesting: 4,
  limit_order_create: 5,
  limit_order_cancel: 6,
  feed_publish: 7,
  convert: 8,
  account_create: 9,
  account_update: 10,
  witness_update: 11,
  account_witness_vote: 12,
  account_witness_proxy: 13,
  pow: 14,
  custom: 15,
  report_over_production: 16,
  delete_comment: 17,
  custom_json: 18,
  comment_options: 19,
  set_withdraw_vesting_route: 20,
  limit_order_create2: 21,
  claim_account: 22,
  create_claimed_account: 23,
  request_account_recovery: 24,
  recover_account: 25,
  change_recovery_account: 26,
  escrow_transfer: 27,
  escrow_dispute: 28,
  escrow_release: 29,
  pow2: 30,
  escrow_approve: 31,
  transfer_to_savings: 32,
  transfer_from_savings: 33,
  cancel_transfer_from_savings: 34,
  custom_binary: 35,
  decline_voting_rights: 36,
  reset_account: 37,
  set_reset_account: 38,
  claim_reward_balance: 39,
  delegate_vesting_shares: 40,
  account_create_with_delegation: 41,
  witness_set_properties: 42,
  account_update2: 43,
  create_proposal: 44,
  update_proposal_votes: 45,
  remove_proposal: 46,
  update_proposal: 47,
  collateralized_convert: 48,
  recurrent_transfer: 49,
  // virtual ops
  fill_convert_request: 50,
  author_reward: 51,
  curation_reward: 52,
  comment_reward: 53,
  liquidity_reward: 54,
  interest: 55,
  fill_vesting_withdraw: 56,
  fill_order: 57,
  shutdown_witness: 58,
  fill_transfer_from_savings: 59,
  hardfork: 60,
  comment_payout_update: 61,
  return_vesting_delegation: 62,
  comment_benefactor_reward: 63,
  producer_reward: 64,
  clear_null_account_balance: 65,
  proposal_pay: 66,
  sps_fund: 67,
  hardfork_steem: 68,
  hardfork_steem_restore: 69,
  delayed_voting: 70,
  consolidate_treasury_balance: 71,
  effective_comment_vote: 72,
  ineffective_delete_comment: 73,
  sps_convert: 74,
  expired_account_notification: 75,
  changed_recovery_account: 76,
  transfer_to_vesting_completed: 77,
  pow_reward: 78,
  vesting_shares_split: 79,
  account_created: 80,
  fill_collateralized_convert_request: 81,
  system_warning: 82,
  fill_recurrent_transfer: 83,
  failed_recurrent_transfer: 84,
  limit_order_cancelled: 85,
  producer_missed: 86,
  proposal_fee: 87,
  collateralized_convert_immediate_conversion: 88,
  escrow_approved: 89,
  escrow_rejected: 90,
  proxy_cleared: 91,
  declined_voting_rights: 92
}

/**
 * Make bitmask filter to be used with get_account_history call
 */
export const makeBitMaskFilter = (allowedOperations: number[]): any[] => {
  return allowedOperations
    .reduce(reduceFunction, [BigInt(0), BigInt(0)])
    .map((value: bigint) => (value !== BigInt(0) ? value.toString() : null))
}
const reduceFunction = (
  [low, high]: [bigint, bigint],
  allowedOperation: number
): [bigint, bigint] => {
  if (allowedOperation < 64) {
    return [low | (BigInt(1) << BigInt(allowedOperation)), high]
  } else {
    return [low, high | (BigInt(1) << BigInt(allowedOperation - 64))]
  }
}

export const buildWitnessSetProperties = (
  owner: string,
  props: WitnessProps
): ['witness_set_properties', { extensions: never[]; owner: string; props: any }] => {
  const data = {
    extensions: [],
    owner,
    props: <any>[]
  }
  for (const key of Object.keys(props)) {
    let type
    switch (key) {
      case 'key':
      case 'new_signing_key':
        type = Serializer.PublicKey
        break
      case 'account_subsidy_budget':
      case 'account_subsidy_decay':
      case 'maximum_block_size':
        type = Serializer.UInt32
        break
      case 'sbd_interest_rate':
        type = Serializer.UInt16
        break
      case 'url':
        type = Serializer.String
        break
      case 'sbd_exchange_rate':
        type = Serializer.Price
        break
      case 'account_creation_fee':
        type = Serializer.Asset
        break
      default:
        throw new Error(`Unknown witness prop: ${key}`)
    }
    data.props.push([key, serialize(type, props[key])])
  }
  data.props.sort((a: any, b: any) => a[0].localeCompare(b[0]))
  return ['witness_set_properties', data]
}

const serialize = (serializer: any, data: any) => {
  const buffer = new ByteBuffer(ByteBuffer.DEFAULT_CAPACITY, ByteBuffer.LITTLE_ENDIAN)
  serializer(buffer, data)
  buffer.flip()
  // `props` values must be hex
  return bytesToHex(new Uint8Array(buffer.toBuffer()))
}

/**
 * Makes a permlink from a title with a random suffix, e.g. `"hello-world-3f9a1c0b7e2d"`.
 * Without a title (e.g. for replies), returns only the random part.
 */
export const createPermlink = (title = ''): string => {
  const slug = title
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '') // strip accents: "café" -> "cafe"
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .slice(0, 200)
    .replace(/^-+|-+$/g, '')
  const suffix = bytesToHex(randomBytes(6))
  return slug ? `${slug}-${suffix}` : suffix
}

export interface CommentOptionsConfig {
  max_accepted_payout?: string | Asset
  percent_steem_dollars?: number
  allow_votes?: boolean
  allow_curation_rewards?: boolean
  extensions?: any[]
  beneficiaries?: Array<{ account: string; weight: number }>
}

/**
 * Builds a `comment_options` operation.
 * Automatically sorts beneficiaries alphabetically by account name as required by Steem consensus.
 *
 * @param author Author account name
 * @param permlink Post or comment permlink
 * @param options Comment options configuration
 * @returns Tuple of `['comment_options', CommentOptionsOperation]`
 */
export const commentOptions = (
  author: string,
  permlink: string,
  options: CommentOptionsConfig = {}
): ['comment_options', CommentOptionsOperation] => {
  const extensions: any[] = options.extensions ? [...options.extensions] : []

  if (options.beneficiaries && options.beneficiaries.length > 0) {
    const sortedBeneficiaries: Beneficiary[] = [...options.beneficiaries].sort((a, b) =>
      a.account.localeCompare(b.account)
    )
    extensions.push([0, { beneficiaries: sortedBeneficiaries }])
  }

  const op: CommentOptionsOperation = {
    author,
    permlink,
    max_accepted_payout: options.max_accepted_payout ?? '1000000.000 SBD',
    percent_steem_dollars: options.percent_steem_dollars ?? 10000,
    allow_votes: options.allow_votes ?? true,
    allow_curation_rewards: options.allow_curation_rewards ?? true,
    extensions
  }

  return ['comment_options', op]
}

/**
 * Check if a Steem account exists on the blockchain.
 * Returns false immediately if username fails validation without making an RPC call.
 *
 * @param username Account name to verify
 * @returns Promise resolving to true if account exists, false otherwise
 */
export const accountExists = async (username: string): Promise<boolean> => {
  if (!username || validateUsername(username) !== null) return false
  try {
    const accounts = await callRPC<any[]>('condenser_api.get_accounts', [[username]])
    return Array.isArray(accounts) && accounts.length > 0
  } catch {
    return false
  }
}

/**
 * Retrieves the user profile object from an account or username.
 * Safely parses `posting_json_metadata` or `json_metadata` and extracts the profile object.
 *
 * @param accountOrName Account object or Steem username
 * @returns Profile dictionary or empty object if none found
 */
export const getProfile = async (
  accountOrName: string | Account | ExtendedAccount
): Promise<Record<string, any>> => {
  let account: any
  if (typeof accountOrName === 'string') {
    const accounts = await callRPC<any[]>('condenser_api.get_accounts', [[accountOrName]])
    if (!accounts || accounts.length === 0) return {}
    account = accounts[0]
  } else {
    account = accountOrName
  }

  for (const field of ['posting_json_metadata', 'json_metadata']) {
    if (account && account[field]) {
      try {
        const parsed =
          typeof account[field] === 'string' ? JSON.parse(account[field]) : account[field]
        if (parsed && typeof parsed.profile === 'object' && parsed.profile !== null) {
          return parsed.profile
        }
      } catch {
        // continue
      }
    }
  }
  return {}
}

/**
 * Returns the required signing role ('posting', 'active', or 'owner') for a given operation name.
 *
 * @param operationName The operation name (e.g., 'vote', 'transfer', 'account_update')
 * @returns Required KeyRole
 */
export const getRequiredRole = (operationName: OperationName): KeyRole => {
  switch (operationName) {
    case 'vote':
    case 'comment':
    case 'delete_comment':
    case 'custom_json':
    case 'claim_reward_balance':
      return 'posting'

    case 'account_update':
    case 'account_create':
    case 'change_recovery_account':
    case 'recover_account':
    case 'reset_account':
    case 'set_reset_account':
      return 'owner'

    default:
      return 'active'
  }
}
