## scx-nest整体架构
在调度器中，Nest 被划分为多个集合（如 Primary Nest 和 Reserve Nest），这些集合在调度过程中扮演了不同的角色，目的是优化任务分配、核心复用和性能

### Primary Nest（主集合）
- 作用
  - Primary Nest 是当前活跃或最近活跃的核心集合，调度器优先选择其中的核心进行任务分配
  - 它的设计目的是实现核心复用，尽量减少任务被分配到长时间未使用的核心，以保持核心的高频率运行（“保持核心温暖”）
- 特点
  - 动态调整大小，随任务数量的变化而增加或减少
  - 当某个核心在一段时间内未被任务使用（超过 p_remove_ns），就会从 Primary Nest 移出，以保持集合的紧凑性
  - 如果任务需要一个核心但 Primary Nest 中没有空闲核心，则会尝试使用 Reserve Nest 或 CFS 默认策略
  - 主要负责高频任务的调度和核心复用

### Reserve Nest（备用集合）
- 作用
  - Reserve Nest 是一个次级核心集合，用于存储较少使用或最近刚从 Primary Nest 移出的核心
  - 当 Primary Nest 无法提供合适的核心时，Reserve Nest 提供后备选择，减少任务分散到系统中其他完全空闲的核心
- 特点
  - 有固定的最大大小限制（r_max，例如最多 5 个核心）
  - 如果任务频繁寻找核心但未能在 Primary Nest 中分配到空闲核心，则可能触发 Reserve Nest 的扩展
  - 核心从 Primary Nest 降级后通常会进入 Reserve Nest，而不是直接变成空闲核心
  - 提供灵活性，避免频繁降级核心导致性能抖动，任务负载变化的情况下，Reserve Nest 减少核心频繁进入深度空闲状态

### Idle Mask（空闲核心集合）
- 作用
  - 统计和跟踪系统中完全空闲的核心，但不直接用于任务分配
  - 用于支持调度器判断是否需要扩展 Primary Nest 或 Reserve Nest
- 特点
  - 如果启用了寻找完全空闲核心的策略（find_fully_idle），调度器可能会将某些任务分配到空闲核心，以追求更高的整体性能
  - 仅在必要时被使用，例如当 Primary 和 Reserve Nest 都没有合适的核心时

### Other Mask（其他核心集合）
- 作用
  - 包括不属于 Primary Nest 和 Reserve Nest 的核心，通常被用作最后的选择
  - 当 Primary 和 Reserve Nest 无法满足需求时，任务会被分配到这些核心
- 特点
  - 这些核心可能较长时间未被使用，初始频率较低
  - 频繁使用 Other Mask 会导致核心复用效率降低

### 大体流程
- 任务分配优先级
  - 优先尝试在 Primary Nest 中寻找空闲核心
  - 如果 Primary Nest 无法满足要求，则检查 Reserve Nest
  - 如果 Reserve Nest 也无法满足，则可能尝试完全空闲核心（Idle Mask）或其他默认策略（如 CFS 分配）
- 动态调整
  - Primary Nest 缩减: 如果核心长时间未使用（超过 p_remove_ns），则会从 Primary Nest 降级到 Reserve Nest
  - Reserve Nest 限制: 如果 Reserve Nest 达到最大容量（r_max），多余的核心将被移除
  - 任务饥饿处理: 如果任务频繁无法分配到核心（超过 r_impatient），会扩大 Primary Nest 的范围以解决拥塞













