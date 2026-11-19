import type { Account, ExtendedAccount, AccountUpdate2Operation, Authority } from '../types.js'

/**
 * Checks whether an account has granted authority to a specific account for a given role.
 *
 * @param account The account object to inspect
 * @param role The authority role to check ('owner', 'active', or 'posting')
 * @param authorizedAccount The account username to look for in account_auths
 * @returns True if authorizedAccount exists with weight >= 1
 */
export const hasAccountAuthority = (
  account: Account | ExtendedAccount,
  role: 'owner' | 'active' | 'posting',
  authorizedAccount: string
): boolean => {
  const auth = account[role]
  if (!auth || !auth.account_auths) return false
  return auth.account_auths.some(([acc, weight]) => acc === authorizedAccount && weight >= 1)
}

/**
 * Builds an `account_update2` operation granting authority to an account.
 * Automatically sorts `account_auths` alphabetically by username to satisfy Steem consensus rules.
 *
 * @param account The account object to update
 * @param role The authority role to grant ('owner', 'active', or 'posting')
 * @param authorizedAccount The account username to authorize
 * @param weight The authority weight to grant (default: 1)
 * @returns Tuple of `['account_update2', AccountUpdate2Operation]` ready for transaction inclusion
 */
export const grantAccountAuthority = (
  account: Account | ExtendedAccount,
  role: 'owner' | 'active' | 'posting',
  authorizedAccount: string,
  weight: number = 1
): ['account_update2', AccountUpdate2Operation] => {
  const currentAuth = account[role]
  const currentAccountAuths: [string, number][] = currentAuth?.account_auths
    ? [...currentAuth.account_auths]
    : []

  const index = currentAccountAuths.findIndex(([a]) => a === authorizedAccount)
  if (index >= 0) {
    currentAccountAuths[index] = [authorizedAccount, weight]
  } else {
    currentAccountAuths.push([authorizedAccount, weight])
  }

  // Steem consensus rule: account_auths MUST be sorted alphabetically by account name
  currentAccountAuths.sort((a, b) => a[0].localeCompare(b[0]))

  const updatedAuthority: Authority = {
    weight_threshold: currentAuth?.weight_threshold ?? 1,
    account_auths: currentAccountAuths,
    key_auths: currentAuth?.key_auths ? [...currentAuth.key_auths] : []
  }

  const op: AccountUpdate2Operation = {
    account: account.name,
    json_metadata: '',
    posting_json_metadata: '',
    extensions: [],
    [role]: updatedAuthority
  }

  return ['account_update2', op]
}

/**
 * Builds an `account_update2` operation revoking authority from an account.
 * Automatically sorts remaining `account_auths` and enforces lockout prevention.
 *
 * @param account The account object to update
 * @param role The authority role to revoke ('owner', 'active', or 'posting')
 * @param authorizedAccount The account username to revoke
 * @returns Tuple of `['account_update2', AccountUpdate2Operation]` ready for transaction inclusion
 * @throws Error if revoking leaves an owner or active role with zero authorities (lockout prevention)
 */
export const revokeAccountAuthority = (
  account: Account | ExtendedAccount,
  role: 'owner' | 'active' | 'posting',
  authorizedAccount: string
): ['account_update2', AccountUpdate2Operation] => {
  const currentAuth = account[role]
  const filteredAccountAuths: [string, number][] = currentAuth?.account_auths
    ? currentAuth.account_auths.filter(([a]) => a !== authorizedAccount)
    : []

  filteredAccountAuths.sort((a, b) => a[0].localeCompare(b[0]))

  const currentKeyAuths: Authority['key_auths'] = currentAuth?.key_auths
    ? [...currentAuth.key_auths]
    : []

  // Lockout prevention check: do not allow removing authority if no keys or accounts remain
  if (filteredAccountAuths.length === 0 && currentKeyAuths.length === 0) {
    throw new Error(
      `Cannot revoke authority: removing '${authorizedAccount}' leaves role '${role}' with no valid authorities.`
    )
  }

  const updatedAuthority: Authority = {
    weight_threshold: currentAuth?.weight_threshold ?? 1,
    account_auths: filteredAccountAuths,
    key_auths: currentKeyAuths
  }

  const op: AccountUpdate2Operation = {
    account: account.name,
    json_metadata: '',
    posting_json_metadata: '',
    extensions: [],
    [role]: updatedAuthority
  }

  return ['account_update2', op]
}
