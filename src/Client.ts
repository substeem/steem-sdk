import { callRPC } from './helpers/call.js'
import { config } from './config.js'
import { Transaction } from './Transaction.js'
import { PrivateKey } from './helpers/PrivateKey.js'
import type {
  ExtendedAccount,
  DynamicGlobalProperties,
  VestingDelegation,
  Operation,
  BroadcastResult
} from './types.js'

export interface ClientOptions {
  timeout?: number
  retry?: number
  chainId?: string
  addressPrefix?: string
}

export class DatabaseAPI {
  constructor(private client: Client) {}

  /**
   * Return extended accounts by username list.
   */
  async getAccounts(names: string[]): Promise<ExtendedAccount[]> {
    return callRPC<ExtendedAccount[]>(
      'condenser_api.get_accounts',
      [names],
      this.client.timeout,
      this.client.retry,
      this.client.nodes
    )
  }

  /**
   * Return dynamic global properties.
   */
  async getDynamicGlobalProperties(): Promise<DynamicGlobalProperties> {
    return callRPC<DynamicGlobalProperties>(
      'condenser_api.get_dynamic_global_properties',
      [],
      this.client.timeout,
      this.client.retry,
      this.client.nodes
    )
  }

  /**
   * Return active vesting delegations from an account.
   */
  async getVestingDelegations(
    account: string,
    from: string = '',
    limit: number = 1000
  ): Promise<VestingDelegation[]> {
    return callRPC<VestingDelegation[]>(
      'condenser_api.get_vesting_delegations',
      [account, from, limit],
      this.client.timeout,
      this.client.retry,
      this.client.nodes
    )
  }

  /**
   * Generic database/condenser_api call.
   */
  async call<T = any>(method: string, params: any[] | object = []): Promise<T> {
    return callRPC<T>(method, params, this.client.timeout, this.client.retry, this.client.nodes)
  }
}

export class BroadcastAPI {
  constructor(private client: Client) {}

  /**
   * Sign and broadcast a list of operations with private key(s).
   */
  async sendOperations(
    operations: Operation[],
    key: PrivateKey | PrivateKey[]
  ): Promise<BroadcastResult> {
    const tx = new Transaction({
      chainId: this.client.chainId,
      nodes: this.client.nodes
    })
    await tx.create(operations)
    const keys = Array.isArray(key) ? key : [key]
    for (const k of keys) {
      tx.sign(k)
    }
    return tx.broadcast()
  }

  /**
   * Sign a transaction object with private key (compatibility wrapper).
   */
  sign(transaction: any, key: PrivateKey | PrivateKey[]): any {
    const tx = new Transaction({
      transaction,
      chainId: this.client.chainId,
      nodes: this.client.nodes
    })
    const keys = Array.isArray(key) ? key : [key]
    for (const k of keys) {
      tx.sign(k)
    }
    return tx.transaction
  }
}

/**
 * High-level Steem RPC client providing familiar database and broadcast namespaces.
 * Maintains isolated instance-scoped node and timeout configuration without mutating global state.
 */
export class Client {
  readonly database: DatabaseAPI
  readonly broadcast: BroadcastAPI
  nodes: string[]
  timeout: number
  retry: number
  chainId?: string
  addressPrefix?: string

  constructor(address?: string | string[], options: ClientOptions = {}) {
    if (address) {
      this.nodes = Array.isArray(address) ? [...address] : [address]
    } else {
      this.nodes = [...config.nodes]
    }
    this.timeout = options.timeout ?? config.timeout
    this.retry = options.retry ?? config.retry
    this.chainId = options.chainId
    this.addressPrefix = options.addressPrefix

    this.database = new DatabaseAPI(this)
    this.broadcast = new BroadcastAPI(this)
  }

  /**
   * Call any API method directly (e.g. client.call('condenser_api', 'get_accounts', [['steemit']]))
   */
  async call<T = any>(api: string, method: string, params: any[] | object = []): Promise<T> {
    const fullMethod = api ? `${api}.${method}` : method
    return callRPC<T>(fullMethod, params, this.timeout, this.retry, this.nodes)
  }
}
