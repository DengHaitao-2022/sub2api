<template>
  <Teleport to="body">
    <div v-if="show" class="fixed inset-0 z-50">
      <div class="absolute inset-0 bg-black/30 backdrop-blur-[1px]" @click="close" />

      <aside class="absolute right-0 top-0 flex h-full w-full max-w-6xl flex-col bg-white shadow-2xl dark:bg-dark-900">
        <header class="border-b border-gray-200 px-6 py-4 dark:border-dark-700">
          <div class="flex items-start justify-between gap-4">
            <div class="min-w-0 flex-1">
              <div class="flex items-center gap-3">
                <div class="flex h-10 w-10 items-center justify-center rounded-lg bg-primary-50 text-primary-600 dark:bg-primary-500/10 dark:text-primary-300">
                  <Icon name="shield" size="sm" />
                </div>
                <div class="min-w-0">
                  <h2 class="truncate text-base font-semibold text-gray-900 dark:text-white">审计详情</h2>
                  <p class="mt-1 truncate font-mono text-xs text-gray-500 dark:text-gray-400">
                    {{ detail?.event?.request_id || detail?.index.request_id || auditId || '-' }}
                  </p>
                </div>
              </div>

              <div class="mt-3 flex flex-wrap gap-2">
                <span class="inline-flex items-center rounded-full bg-gray-100 px-2.5 py-1 text-xs font-medium text-gray-700 dark:bg-dark-800 dark:text-gray-300">
                  Audit {{ detail?.index.audit_id || auditId || '-' }}
                </span>
                <span
                  class="inline-flex items-center rounded-full px-2.5 py-1 text-xs font-medium"
                  :class="statusToneClass"
                >
                  {{ statusSummary }}
                </span>
                <span class="inline-flex items-center rounded-full bg-gray-100 px-2.5 py-1 text-xs font-medium text-gray-700 dark:bg-dark-800 dark:text-gray-300">
                  {{ event.model || detail?.index.model || 'unknown model' }}
                </span>
                <span class="inline-flex items-center rounded-full bg-gray-100 px-2.5 py-1 text-xs font-medium text-gray-700 dark:bg-dark-800 dark:text-gray-300">
                  {{ formatDateTime(event.ts || detail?.index.created_at) }}
                </span>
              </div>
            </div>

            <button class="btn btn-ghost h-10 w-10 p-0" title="关闭" @click="close">
              <Icon name="x" size="sm" />
            </button>
          </div>
        </header>

        <div class="border-b border-gray-200 px-6 dark:border-dark-700">
          <div class="flex gap-2 overflow-x-auto py-2">
            <button
              v-for="tab in tabs"
              :key="tab.key"
              class="tab whitespace-nowrap"
              :class="{ 'tab-active': activeTab === tab.key }"
              @click="activeTab = tab.key"
            >
              {{ tab.label }}
            </button>
          </div>
        </div>

        <main class="min-h-0 flex-1 overflow-auto px-6 py-5">
          <div v-if="loading" class="py-12 text-center text-sm text-gray-500 dark:text-gray-400">加载中...</div>

          <div
            v-else-if="error"
            class="rounded-lg border border-rose-200 bg-rose-50 p-4 text-sm text-rose-700 dark:border-rose-500/30 dark:bg-rose-500/10 dark:text-rose-300"
          >
            {{ error }}
          </div>

          <template v-else-if="detail">
            <section v-if="activeTab === 'overview'" class="space-y-5">
              <div class="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-4">
                <div class="rounded-lg border border-gray-200 bg-white p-4 dark:border-dark-700 dark:bg-dark-900">
                  <div class="text-xs font-medium text-gray-500 dark:text-gray-400">状态</div>
                  <div class="mt-2 text-2xl font-semibold" :class="statusHeadlineClass">{{ statusCodeValue || '-' }}</div>
                  <div class="mt-1 text-xs text-gray-500 dark:text-gray-400">{{ event.error_type || detail.index.error_type || 'no error type' }}</div>
                </div>
                <div class="rounded-lg border border-gray-200 bg-white p-4 dark:border-dark-700 dark:bg-dark-900">
                  <div class="text-xs font-medium text-gray-500 dark:text-gray-400">总耗时</div>
                  <div class="mt-2 text-2xl font-semibold text-gray-900 dark:text-white">{{ formatMs(event.duration_ms) }}</div>
                  <div class="mt-1 text-xs text-gray-500 dark:text-gray-400">route attempts {{ detail.index.attempt_count || 0 }}</div>
                </div>
                <div class="rounded-lg border border-gray-200 bg-white p-4 dark:border-dark-700 dark:bg-dark-900">
                  <div class="text-xs font-medium text-gray-500 dark:text-gray-400">首 token</div>
                  <div class="mt-2 text-2xl font-semibold text-gray-900 dark:text-white">{{ formatMs(event.time_to_first_token_ms) }}</div>
                  <div class="mt-1 text-xs text-gray-500 dark:text-gray-400">failover {{ detail.index.has_failover ? 'yes' : 'no' }}</div>
                </div>
                <div class="rounded-lg border border-gray-200 bg-white p-4 dark:border-dark-700 dark:bg-dark-900">
                  <div class="text-xs font-medium text-gray-500 dark:text-gray-400">Usage</div>
                  <div class="mt-2 text-2xl font-semibold text-gray-900 dark:text-white">{{ usageSummary }}</div>
                  <div class="mt-1 text-xs text-gray-500 dark:text-gray-400">
                    in {{ formatBytes(detail.index.input_size) }} / out {{ formatBytes(detail.index.output_size) }}
                  </div>
                </div>
              </div>

              <div class="rounded-lg border border-gray-200 bg-white p-5 dark:border-dark-700 dark:bg-dark-900">
                <div class="mb-4 text-sm font-semibold text-gray-900 dark:text-white">请求元数据</div>
                <div class="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
                  <AuditInfoRow label="Audit ID" :value="detail.index.audit_id" mono />
                  <AuditInfoRow label="Request ID" :value="event.request_id || detail.index.request_id" mono />
                  <AuditInfoRow label="Client Request ID" :value="event.client_request_id || detail.index.client_request_id" mono />
                  <AuditInfoRow label="用户" :value="event.user_id || detail.index.user_id || '-'" />
                  <AuditInfoRow label="API Key" :value="event.api_key_id || detail.index.api_key_id || '-'" />
                  <AuditInfoRow label="账号" :value="accountLabel" />
                  <AuditInfoRow label="分组" :value="event.group_id || detail.index.group_id || '-'" />
                  <AuditInfoRow label="平台" :value="event.platform || detail.index.platform || '-'" />
                  <AuditInfoRow label="模型" :value="event.model || detail.index.model || '-'" />
                  <AuditInfoRow label="入口 Endpoint" :value="event.inbound_endpoint || detail.index.inbound_endpoint || '-'" mono />
                  <AuditInfoRow label="上游 Endpoint" :value="event.upstream_endpoint || detail.index.upstream_endpoint || '-'" mono />
                  <AuditInfoRow label="请求路径" :value="event.path || detail.index.path || '-'" mono />
                  <AuditInfoRow label="请求方法" :value="event.method || detail.index.method || '-'" />
                  <AuditInfoRow label="客户端 IP" :value="event.client_ip || '-'" mono />
                  <AuditInfoRow label="User Agent" :value="event.user_agent || '-'" />
                  <AuditInfoRow label="输入 tokens" :value="event.usage?.input_tokens ?? '-'" />
                  <AuditInfoRow label="输出 tokens" :value="event.usage?.output_tokens ?? '-'" />
                  <AuditInfoRow label="时间" :value="event.ts || detail.index.created_at" mono />
                </div>
              </div>
            </section>

            <AuditBodyPanel
              v-else-if="activeTab === 'input'"
              title="Input"
              :record="event.input"
              :capture-mode="inputCaptureMode"
            />

            <AuditBodyPanel
              v-else-if="activeTab === 'output'"
              title="Output"
              :record="event.output"
              :capture-mode="outputCaptureMode"
            />

            <section v-else-if="activeTab === 'route'" class="space-y-3">
              <div
                v-if="!event.attempts || event.attempts.length === 0"
                class="rounded-lg border border-gray-200 bg-white p-5 text-sm text-gray-500 dark:border-dark-700 dark:bg-dark-900 dark:text-gray-400"
              >
                暂无上游尝试链路
              </div>

              <div
                v-for="attempt in event.attempts"
                v-else
                :key="`${attempt.attempt}-${attempt.account_id}-${attempt.selected_at_ms}`"
                class="rounded-lg border border-gray-200 bg-white p-5 dark:border-dark-700 dark:bg-dark-900"
              >
                <div class="flex flex-wrap items-center justify-between gap-3">
                  <div class="flex items-center gap-2">
                    <span class="inline-flex rounded-full bg-primary-50 px-2.5 py-1 text-xs font-medium text-primary-700 dark:bg-primary-500/10 dark:text-primary-300">
                      Attempt {{ attempt.attempt }}
                    </span>
                    <span
                      class="inline-flex rounded-full px-2.5 py-1 text-xs font-medium"
                      :class="attemptStatusClass(attempt.status_code)"
                    >
                      {{ attempt.status_code || '-' }}
                    </span>
                  </div>
                  <div class="text-xs text-gray-500 dark:text-gray-400">{{ formatMs(attempt.duration_ms) }}</div>
                </div>

                <div class="mt-4 grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
                  <AuditInfoRow label="账号" :value="[attempt.account_name, attempt.account_id ? `#${attempt.account_id}` : ''].filter(Boolean).join(' ') || '-'" />
                  <AuditInfoRow label="平台" :value="attempt.platform || '-'" />
                  <AuditInfoRow label="上游" :value="attempt.upstream_endpoint || '-'" mono />
                  <AuditInfoRow label="结果" :value="attempt.result || '-'" />
                  <AuditInfoRow label="选中耗时" :value="formatMs(attempt.selected_at_ms)" />
                  <AuditInfoRow label="错误类型" :value="attempt.error_type || '-'" mono />
                  <AuditInfoRow label="错误信息" :value="attempt.error_message || '-'" />
                </div>
              </div>
            </section>

            <section v-else-if="activeTab === 'error'" class="space-y-4">
              <div class="rounded-lg border border-gray-200 bg-white p-5 dark:border-dark-700 dark:bg-dark-900">
                <div class="grid grid-cols-1 gap-3 md:grid-cols-2">
                  <AuditInfoRow label="Error Type" :value="event.error_type || detail.index.error_type || '-'" mono />
                  <AuditInfoRow label="Status Code" :value="statusCodeValue || '-'" />
                  <AuditInfoRow label="Error Message" :value="event.error_message || '-'" />
                  <AuditInfoRow label="Final Upstream Status" :value="detail.index.final_upstream_status_code || '-'" />
                </div>
              </div>

              <div class="rounded-lg border border-gray-200 bg-gray-50 px-4 py-3 text-sm text-gray-600 dark:border-dark-700 dark:bg-dark-800 dark:text-gray-300">
                输入和输出全文请分别查看上方的 <span class="font-medium">Input</span> 与 <span class="font-medium">Output</span> 标签页。
              </div>
            </section>

            <section v-else class="space-y-4">
              <div class="rounded-lg border border-gray-200 bg-white p-5 dark:border-dark-700 dark:bg-dark-900">
                <div class="mb-4 text-sm font-semibold text-gray-900 dark:text-white">采集与安全</div>
                <div class="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
                  <AuditInfoRow label="Capture Mode" :value="detail.index.capture_mode || '-'" />
                  <AuditInfoRow label="Sampled" :value="detail.index.sampled" />
                  <AuditInfoRow label="Input Hash" :value="detail.index.input_hash || event.input?.sha256 || '-'" mono />
                  <AuditInfoRow label="Output Hash" :value="detail.index.output_hash || event.output?.sha256 || '-'" mono />
                  <AuditInfoRow label="Input Truncated" :value="detail.index.input_truncated" />
                  <AuditInfoRow label="Output Truncated" :value="detail.index.output_truncated" />
                  <AuditInfoRow label="JSONL 文件" :value="detail.index.file_path || '-'" mono />
                  <AuditInfoRow label="文件偏移" :value="detail.index.file_offset ?? '-'" mono />
                  <AuditInfoRow label="行字节数" :value="detail.index.line_bytes ?? '-'" mono />
                </div>
              </div>

              <div class="rounded-lg border border-gray-200 bg-white p-5 dark:border-dark-700 dark:bg-dark-900">
                <div class="mb-4 flex items-center justify-between gap-3">
                  <div class="text-sm font-semibold text-gray-900 dark:text-white">访问记录</div>
                  <div class="text-xs text-gray-500 dark:text-gray-400">{{ accessLogs.length }} entries</div>
                </div>

                <div v-if="accessLogs.length === 0" class="text-sm text-gray-500 dark:text-gray-400">暂无访问记录</div>

                <div v-else class="space-y-3">
                  <div
                    v-for="log in accessLogs"
                    :key="log.id"
                    class="rounded-lg border border-gray-200 bg-gray-50 p-4 dark:border-dark-700 dark:bg-dark-800"
                  >
                    <div class="flex flex-wrap items-center gap-2 text-sm text-gray-800 dark:text-gray-200">
                      <span class="font-medium">#{{ log.operator_id }}</span>
                      <span class="rounded-full bg-white px-2 py-0.5 text-xs dark:bg-dark-900">{{ log.action }}</span>
                      <span class="font-mono text-xs text-gray-500 dark:text-gray-400">{{ log.created_at }}</span>
                    </div>
                    <div class="mt-2 break-words text-xs text-gray-500 dark:text-gray-400">
                      {{ log.viewed_fields?.join(', ') || '-' }} · {{ log.ip_address || '-' }} · {{ log.user_agent || '-' }}
                    </div>
                  </div>
                </div>
              </div>
            </section>
          </template>
        </main>
      </aside>
    </div>
  </Teleport>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'

import { adminAuditAPI, type GatewayAuditAccessLog, type GatewayAuditDetail, type GatewayAuditEvent } from '@/api/admin/audit'
import AuditBodyPanel from '@/components/admin/audit/AuditBodyPanel.vue'
import AuditInfoRow from '@/components/admin/audit/AuditInfoRow.vue'
import Icon from '@/components/icons/Icon.vue'

const props = defineProps<{
  show: boolean
  auditId?: string | null
}>()

const emit = defineEmits<{
  'update:show': [value: boolean]
}>()

type DrawerTab = 'overview' | 'input' | 'output' | 'route' | 'error' | 'security'

const loading = ref(false)
const error = ref('')
const detail = ref<GatewayAuditDetail | null>(null)
const accessLogs = ref<GatewayAuditAccessLog[]>([])
const activeTab = ref<DrawerTab>('overview')

const tabs = [
  { key: 'overview', label: '概览' },
  { key: 'input', label: 'Input' },
  { key: 'output', label: 'Output' },
  { key: 'route', label: '路由' },
  { key: 'error', label: '错误' },
  { key: 'security', label: '安全' },
] as const

const event = computed<GatewayAuditEvent>(() => detail.value?.event || ({} as GatewayAuditEvent))

const accountLabel = computed(() => {
  const e = event.value
  if (!e.account_id && !e.account_name) {
    return detail.value?.index.account_id || '-'
  }
  return [e.account_name, e.account_id ? `#${e.account_id}` : '', e.account_platform].filter(Boolean).join(' ')
})

const statusCodeValue = computed(() => event.value.status_code || detail.value?.index.status_code || 0)

const statusSummary = computed(() => {
  if (!statusCodeValue.value) {
    return 'no status'
  }
  return `${statusCodeValue.value} ${event.value.error_type || detail.value?.index.error_type || 'completed'}`
})

const statusHeadlineClass = computed(() => {
  if (statusCodeValue.value >= 500) {
    return 'text-rose-600 dark:text-rose-400'
  }
  if (statusCodeValue.value >= 400) {
    return 'text-amber-600 dark:text-amber-400'
  }
  return 'text-emerald-600 dark:text-emerald-400'
})

const statusToneClass = computed(() => {
  if (statusCodeValue.value >= 500) {
    return 'bg-rose-100 text-rose-700 dark:bg-rose-500/10 dark:text-rose-300'
  }
  if (statusCodeValue.value >= 400) {
    return 'bg-amber-100 text-amber-700 dark:bg-amber-500/10 dark:text-amber-300'
  }
  if (statusCodeValue.value > 0) {
    return 'bg-emerald-100 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-300'
  }
  return 'bg-gray-100 text-gray-700 dark:bg-dark-800 dark:text-gray-300'
})

const usageSummary = computed(() => {
  const usage = event.value.usage
  if (!usage || (!usage.input_tokens && !usage.output_tokens)) {
    return '-'
  }
  return `${usage.input_tokens || 0} / ${usage.output_tokens || 0}`
})

const inputCaptureMode = computed(() => splitCaptureModes(detail.value?.index.capture_mode).input)
const outputCaptureMode = computed(() => splitCaptureModes(detail.value?.index.capture_mode).output)

watch(
  () => [props.show, props.auditId] as const,
  async ([show, auditId]) => {
    if (!show || !auditId) {
      return
    }
    loading.value = true
    error.value = ''
    detail.value = null
    accessLogs.value = []
    activeTab.value = 'overview'
    try {
      detail.value = await adminAuditAPI.getDetail(auditId)
      accessLogs.value = await adminAuditAPI.accessLogs({ audit_id: auditId, limit: 20 })
    } catch (err: any) {
      error.value = err?.message || '审计详情加载失败'
    } finally {
      loading.value = false
    }
  },
  { immediate: true }
)

const close = () => emit('update:show', false)

function formatMs(value?: number | null): string {
  if (value == null || value === 0) {
    return '-'
  }
  if (value < 1000) {
    return `${value}ms`
  }
  return `${(value / 1000).toFixed(2)}s`
}

function formatBytes(value?: number | null): string {
  if (!value || value <= 0) {
    return '0 B'
  }
  const units = ['B', 'KB', 'MB', 'GB']
  let size = value
  let unitIndex = 0
  while (size >= 1024 && unitIndex < units.length - 1) {
    size /= 1024
    unitIndex++
  }
  return `${size >= 10 || unitIndex === 0 ? size.toFixed(0) : size.toFixed(1)} ${units[unitIndex]}`
}

function formatDateTime(value?: string | Date | null): string {
  if (!value) {
    return '-'
  }
  const date = value instanceof Date ? value : new Date(value)
  if (Number.isNaN(date.getTime())) {
    return String(value)
  }
  return date.toLocaleString()
}

function splitCaptureModes(value?: string | null): { input: string; output: string } {
  const [input = 'preview', output = 'preview'] = (value || '').split('/')
  return {
    input: input || 'preview',
    output: output || 'preview',
  }
}

function attemptStatusClass(statusCode?: number): string {
  if (!statusCode) {
    return 'bg-gray-100 text-gray-700 dark:bg-dark-800 dark:text-gray-300'
  }
  if (statusCode >= 500) {
    return 'bg-rose-100 text-rose-700 dark:bg-rose-500/10 dark:text-rose-300'
  }
  if (statusCode >= 400) {
    return 'bg-amber-100 text-amber-700 dark:bg-amber-500/10 dark:text-amber-300'
  }
  return 'bg-emerald-100 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-300'
}
</script>
