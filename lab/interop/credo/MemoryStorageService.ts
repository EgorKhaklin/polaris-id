/**
 * A process-lifetime StorageService for the Credo holder agent.
 *
 * Credo 0.6 ships no in-memory storage: the Agent constructor refuses to start without a
 * StorageService and its error names three options, "the AskarModule, DrizzleStorageModule,
 * or implement your own". Askar needs a native library fetched by an install script, so this
 * harness takes the third option. It implements Credo's exported `StorageService` interface
 * and nothing else; it touches no Credo internals. Records are kept as JSON and
 * re-hydrated through Credo's own JsonTransformer, as a persistent store would.
 */
import {
  type AgentContext,
  type BaseRecord,
  type BaseRecordConstructor,
  JsonTransformer,
  type Query,
  type QueryOptions,
  RecordDuplicateError,
  RecordNotFoundError,
  type StorageService,
} from '@credo-ts/core'

type Stored = { type: string; value: Record<string, unknown>; tags: Record<string, unknown> }

// biome-ignore lint/suspicious/noExplicitAny: generic over every record type, as the interface is
export class MemoryStorageService<T extends BaseRecord<any, any, any> = BaseRecord<any, any, any>>
  implements StorageService<T>
{
  public supportsCursorPagination = false
  private records = new Map<string, Stored>()

  private key(type: string, id: string) {
    return `${type}\u0000${id}`
  }

  async save(_ctx: AgentContext, record: T) {
    record.updatedAt = new Date()
    const k = this.key(record.type, record.id)
    if (this.records.has(k)) {
      throw new RecordDuplicateError(`record ${record.id} already exists`, { recordType: record.type })
    }
    this.records.set(k, { type: record.type, value: JsonTransformer.toJSON(record), tags: record.getTags() })
  }

  async update(_ctx: AgentContext, record: T) {
    record.updatedAt = new Date()
    const k = this.key(record.type, record.id)
    if (!this.records.has(k)) {
      throw new RecordNotFoundError(`record ${record.id} not found`, { recordType: record.type })
    }
    this.records.set(k, { type: record.type, value: JsonTransformer.toJSON(record), tags: record.getTags() })
  }

  async delete(ctx: AgentContext, record: T) {
    await this.deleteById(ctx, record.constructor as BaseRecordConstructor<T>, record.id)
  }

  async deleteById(_ctx: AgentContext, cls: BaseRecordConstructor<T>, id: string) {
    if (!this.records.delete(this.key(cls.type, id))) {
      throw new RecordNotFoundError(`record ${id} not found`, { recordType: cls.type })
    }
  }

  async getById(_ctx: AgentContext, cls: BaseRecordConstructor<T>, id: string): Promise<T> {
    const stored = this.records.get(this.key(cls.type, id))
    if (!stored) throw new RecordNotFoundError(`record ${id} not found`, { recordType: cls.type })
    return this.hydrate(stored, cls)
  }

  async getAll(_ctx: AgentContext, cls: BaseRecordConstructor<T>): Promise<T[]> {
    return [...this.records.values()].filter((r) => r.type === cls.type).map((r) => this.hydrate(r, cls))
  }

  async findByQuery(
    _ctx: AgentContext,
    cls: BaseRecordConstructor<T>,
    query: Query<T>,
    options?: QueryOptions
  ): Promise<T[]> {
    const hits = [...this.records.values()]
      .filter((r) => r.type === cls.type && matches(r.tags, query as Record<string, unknown>))
      .map((r) => this.hydrate(r, cls))
    const offset = options?.offset ?? 0
    return options?.limit !== undefined ? hits.slice(offset, offset + options.limit) : hits.slice(offset)
  }

  private hydrate(stored: Stored, cls: BaseRecordConstructor<T>): T {
    const record = JsonTransformer.fromJSON(stored.value, cls) as T
    record.replaceTags(stored.tags as never)
    return record
  }
}

function matches(tags: Record<string, unknown>, query: Record<string, unknown>): boolean {
  const { $and, $or, $not, ...simple } = query as {
    $and?: Record<string, unknown>[]
    $or?: Record<string, unknown>[]
    $not?: Record<string, unknown>
  }
  for (const [name, wanted] of Object.entries(simple)) {
    if (wanted === undefined) continue
    const have = tags[name]
    if (Array.isArray(wanted)) {
      if (!Array.isArray(have) || !wanted.every((w) => have.includes(w))) return false
    } else if (wanted === null) {
      if (have !== undefined && have !== null) return false
    } else if (Array.isArray(have)) {
      if (!have.includes(wanted)) return false
    } else if (have !== wanted) {
      return false
    }
  }
  if ($and && !$and.every((q) => matches(tags, q))) return false
  if ($or && $or.length > 0 && !$or.some((q) => matches(tags, q))) return false
  if ($not && matches(tags, $not)) return false
  return true
}
