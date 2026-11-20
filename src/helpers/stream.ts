import { AppliedOperation, Block, AnyOperation } from '../types.js'
import { callRPC, callRPCBatch } from './call.js'
import { sleep } from './sleep.js'

/** Blocks fetched per request while catching up */
const BATCH_SIZE = 20
/** Wait between polls once caught up; Steem makes a block every 3s */
const POLL_INTERVAL = 1000

export interface StreamOptions {
  /** First block to stream. Default: the last irreversible block */
  from?: number
  /** Last block to stream; the stream ends after it. Default: never ends */
  to?: number
  /** Optional custom node URLs for RPC requests during streaming */
  nodes?: string[]
}

export interface StreamOperationsOptions extends StreamOptions {
  /** As in `get_ops_in_block`: true streams only virtual operations, false streams all. Default: false */
  only_virtual?: boolean
  /** Filter by operation types, e.g. 'transfer' or ['transfer', 'vote'] */
  filter?: string | string[]
}

/**
 * Yields `[blockNum, data]` for each irreversible block in order, with no gaps or duplicates.
 * `fetchBatch` returns null for blocks the node does not have yet; those are fetched again.
 */
async function* followChain<T>(
  { from, to = Infinity, nodes }: StreamOptions,
  fetchBatch: (nums: number[]) => Promise<(T | null)[]>
): AsyncGenerator<[number, T]> {
  let lib = (
    await callRPC<{ last_irreversible_block_num: number }>(
      'condenser_api.get_dynamic_global_properties',
      [],
      undefined,
      undefined,
      nodes
    )
  ).last_irreversible_block_num
  let next = from ?? lib
  if (!Number.isInteger(next) || next < 1) {
    throw new Error('from must be a block number >= 1')
  }
  while (next <= to) {
    if (next > lib) {
      await sleep(POLL_INTERVAL)
      lib = (
        await callRPC<{ last_irreversible_block_num: number }>(
          'condenser_api.get_dynamic_global_properties',
          [],
          undefined,
          undefined,
          nodes
        )
      ).last_irreversible_block_num
      continue
    }
    const count = Math.min(Math.min(lib, to) - next + 1, BATCH_SIZE)
    const results = await fetchBatch(Array.from({ length: count }, (_, i) => next + i))
    for (const result of results) {
      if (result === null) {
        // The node we hit is behind the one that reported `lib`; retry from here
        await sleep(POLL_INTERVAL)
        break
      }
      yield [next++, result]
    }
  }
}

/**
 * Streams irreversible block numbers in order, with no gaps or duplicates, without fetching the blocks.
 * Same catch-up, stop, and resume behavior as `streamBlocks`.
 *
 * @example
 * ```typescript
 * import { streamBlockNumbers } from '@substeem/steem-sdk'
 *
 * for await (const num of streamBlockNumbers()) {
 *   console.log(num)
 * }
 * ```
 */
export async function* streamBlockNumbers(options: StreamOptions = {}): AsyncGenerator<number> {
  for await (const [num] of followChain(options, async (nums) => nums)) {
    yield num
  }
}

/**
 * Streams irreversible blocks in order, with no gaps or duplicates.
 * Catches up on past blocks in batches, then follows the chain as new blocks become irreversible.
 * Steem blocks become irreversible within a few seconds, so this is close to real time.
 *
 * Stop by `break`ing out of the loop. On network failure the stream throws;
 * resume with `from: lastBlock.block_num + 1`.
 *
 * @example
 * ```typescript
 * import { streamBlocks } from '@substeem/steem-sdk'
 *
 * for await (const block of streamBlocks()) {
 *   console.log(block.block_num, block.transactions.length)
 * }
 * ```
 */
export async function* streamBlocks(options: StreamOptions = {}): AsyncGenerator<Block> {
  const blocks = followChain(options, (nums) =>
    callRPCBatch<Block | null>(
      'condenser_api.get_block',
      nums.map((num) => [num]),
      undefined,
      undefined,
      options.nodes
    )
  )
  for await (const [num, block] of blocks) {
    block.block_num = num
    yield block
  }
}

/**
 * Streams the operations of irreversible blocks in chain order, with no gaps or duplicates.
 * Includes virtual operations (rewards, order fills, interest, ...) like `get_ops_in_block` does.
 * Supports type-safe filtering by operation name(s).
 *
 * @example
 * ```typescript
 * import { streamOperations, type TransferOperation } from '@substeem/steem-sdk'
 *
 * // Stream all operations
 * for await (const { block, trx_id, op } of streamOperations()) {
 *   if (op[0] === 'transfer') console.log(block, trx_id, op[1].from, op[1].amount)
 * }
 *
 * // Type-safe filtered stream
 * for await (const { op } of streamOperations<['transfer', TransferOperation]>('transfer')) {
 *   console.log(op[1].to, op[1].amount)
 * }
 * ```
 */
export function streamOperations(
  options?: StreamOperationsOptions
): AsyncGenerator<AppliedOperation<AnyOperation>>

export function streamOperations<T extends AnyOperation = AnyOperation>(
  filter: string | string[],
  options?: StreamOperationsOptions
): AsyncGenerator<AppliedOperation<T>>

export async function* streamOperations<T extends AnyOperation = AnyOperation>(
  filterOrOptions?: string | string[] | StreamOperationsOptions,
  maybeOptions?: StreamOperationsOptions
): AsyncGenerator<AppliedOperation<T>> {
  let filterSet: Set<string> | undefined
  let opts: StreamOperationsOptions = {}

  if (typeof filterOrOptions === 'string') {
    filterSet = new Set([filterOrOptions])
    opts = maybeOptions ?? {}
  } else if (Array.isArray(filterOrOptions)) {
    filterSet = new Set(filterOrOptions)
    opts = maybeOptions ?? {}
  } else if (filterOrOptions && typeof filterOrOptions === 'object') {
    opts = filterOrOptions
    if (opts.filter) {
      filterSet = new Set(Array.isArray(opts.filter) ? opts.filter : [opts.filter])
    }
  }

  const { only_virtual = false, nodes, ...range } = opts

  const blocks = followChain({ ...range, nodes }, async (nums) => {
    const lists = await callRPCBatch<AppliedOperation[]>(
      'condenser_api.get_ops_in_block',
      nums.map((num) => [num, only_virtual]),
      undefined,
      undefined,
      nodes
    )
    // Every block has a producer_reward virtual op, so an empty list means the node lacks the block yet
    return lists.map((ops) => (ops.length ? ops : null))
  })

  for await (const [, ops] of blocks) {
    for (const applied of ops) {
      if (!filterSet || filterSet.has(applied.op[0])) {
        yield applied as AppliedOperation<T>
      }
    }
  }
}
