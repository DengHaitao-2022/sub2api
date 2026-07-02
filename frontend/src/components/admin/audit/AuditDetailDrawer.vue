<template>
  <Teleport to="body">
    <div v-if="show" class="fixed inset-0 z-50">
      <div class="absolute inset-0 bg-black/30" @click="close" />
      <aside class="absolute right-0 top-0 flex h-full w-full max-w-4xl flex-col bg-white shadow-2xl dark:bg-dark-900">
        <header class="flex items-start justify-between border-b border-gray-200 px-5 py-4 dark:border-dark-700">
          <div class="min-w-0">
            <div class="flex items-center gap-2">
              <Icon name="shield" size="sm" class="text-primary-500" />
              <h2 class="text-base font-semibold text-gray-900 dark:text-white">审计详情</h2>
            </div>
            <p class="mt-1 truncate font-mono text-xs text-gray-500 dark:text-gray-400">
              {{ detail?.event?.request_id || detail?.index.request_id || auditId || '-' }}
            </p>
          </div>
          <button class="btn btn-ghost p-2" title="关闭" @click="close">
            <Icon name="x" size="sm" />
          </button>
        </header>

        <div class="border-b border-gray-200 px-5 dark:border-dark-700">
          <div class="flex gap-2 overflow-x-auto py-2">
            <button v-for="tab in tabs" :key="tab.key" class="tab whitespace-nowrap" :class="{ 'tab-active': activeTab === tab.key }" @click="activeTab = tab.key">
              {{ tab.label }}
            </button>
          </div>
        </div>

        <main class="min-h-0 flex-1 overflow-auto px-5 py-4">
          <div v-if="loading" class="py-10 text-center text-sm text-gray-500 dark:text-gray-400">加载中...</div>
          <div v-else-if="error" class="rounded border border-rose-200 bg-rose-50 p-3 text-sm text-rose-700 dark:border-rose-500/30 dark:bg-rose-500/10 dark:text-rose-300">
            {{ error }}
          </div>
          <template v-else-if="detail">
            <section v-if="activeTab === 'overview'" class="grid grid-cols-1 gap-3 md:grid-cols-2">
              <InfoRow label="Audit ID" :value="detail.index.audit_id" mono />
              <InfoRow label="Request ID" :value="event.request_id || detail.index.request_id" mono />
              <InfoRow label="Client Request ID" :value="event.client_request_id || detail.index.client_request_id" mono />
              <InfoRow label="用户" :value="event.user_id || detail.index.user_id || '-'" />
              <InfoRow label="API Key" :value="event.api_key_id || detail.index.api_key_id || '-'" />
              <InfoRow label="账号" :value="accountLabel" />
              <InfoRow label="分组" :value="event.group_id || detail.index.group_id || '-'" />
              <InfoRow label="平台" :value="event.platform || detail.index.platform" />
              <InfoRow label="模型" :value="event.model || detail.index.model" />
              <InfoRow label="入口" :value="event.inbound_endpoint || detail.index.inbound_endpoint" mono />
              <InfoRow label="上游" :value="event.upstream_endpoint || detail.index.upstream_endpoint" mono />
              <InfoRow label="路径" :value="event.path || detail.index.path" mono />
              <InfoRow label="状态码" :value="event.status_code || detail.index.status_code" />
              <InfoRow label="总耗时" :value="formatMs(event.duration_ms)" />
              <InfoRow label="首 token" :value="formatMs(event.time_to_first_token_ms)" />
              <InfoRow label="时间" :value="event.ts || detail.index.created_at" mono />
            </section>

            <BodyPanel v-else-if="activeTab === 'input'" title="Input" :record="event.input" />
            <BodyPanel v-else-if="activeTab === 'output'" title="Output" :record="event.output" />

            <section v-else-if="activeTab === 'route'" class="space-y-3">
              <div v-if="!event.attempts || event.attempts.length === 0" class="rounded border border-gray-200 p-4 text-sm text-gray-500 dark:border-dark-700 dark:text-gray-400">
                暂无上游尝试链路
              </div>
              <div v-for="attempt in event.attempts" v-else :key="`${attempt.attempt}-${attempt.account_id}`" class="rounded border border-gray-200 p-3 dark:border-dark-700">
                <div class="flex items-center justify-between gap-3">
                  <div class="font-medium text-gray-900 dark:text-white">Attempt {{ attempt.attempt }}</div>
                  <div class="text-xs text-gray-500 dark:text-gray-400">{{ formatMs(attempt.selected_at_ms) }}</div>
                </div>
                <div class="mt-2 grid grid-cols-1 gap-2 md:grid-cols-2">
                  <InfoRow label="账号" :value="[attempt.account_name, attempt.account_id ? `#${attempt.account_id}` : ''].filter(Boolean).join(' ') || '-'" />
                  <InfoRow label="平台" :value="attempt.platform || '-'" />
                  <InfoRow label="上游" :value="attempt.upstream_endpoint || '-'" mono />
                  <InfoRow label="结果" :value="attempt.result || '-'" />
                  <InfoRow label="状态码" :value="attempt.status_code || '-'" />
                  <InfoRow label="耗时" :value="formatMs(attempt.duration_ms)" />
                  <InfoRow label="错误类型" :value="attempt.error_type || '-'" mono />
                  <InfoRow label="错误信息" :value="attempt.error_message || '-'" />
                </div>
              </div>
            </section>

            <section v-else-if="activeTab === 'error'" class="space-y-3">
              <InfoRow label="Error Type" :value="event.error_type || detail.index.error_type || '-'" mono />
              <InfoRow label="Error Message" :value="event.error_message || '-'" />
              <InfoRow label="Status Code" :value="event.status_code || detail.index.status_code || '-'" />
              <BodyPanel title="Output Preview" :record="event.output" compact />
            </section>

            <section v-else class="grid grid-cols-1 gap-3 md:grid-cols-2">
              <InfoRow label="Capture Mode" :value="detail.index.capture_mode || '-'" />
              <InfoRow label="Sampled" :value="detail.index.sampled ? 'yes' : 'no'" />
              <InfoRow label="Input Hash" :value="detail.index.input_hash || event.input?.sha256 || '-'" mono />
              <InfoRow label="Output Hash" :value="detail.index.output_hash || event.output?.sha256 || '-'" mono />
              <InfoRow label="Input Truncated" :value="detail.index.input_truncated ? 'yes' : 'no'" />
              <InfoRow label="Output Truncated" :value="detail.index.output_truncated ? 'yes' : 'no'" />
              <div class="md:col-span-2">
                <div class="mb-2 text-xs font-medium text-gray-500 dark:text-gray-400">访问记录</div>
                <div v-if="accessLogs.length === 0" class="rounded border border-gray-200 p-3 text-sm text-gray-500 dark:border-dark-700 dark:text-gray-400">暂无访问记录</div>
                <div v-else class="space-y-2">
                  <div v-for="log in accessLogs" :key="log.id" class="rounded border border-gray-200 p-3 text-xs dark:border-dark-700">
                    <div class="flex flex-wrap items-center gap-2 text-gray-700 dark:text-gray-300">
                      <span class="font-medium">#{{ log.operator_id }}</span>
                      <span>{{ log.action }}</span>
                      <span class="font-mono text-gray-500">{{ log.created_at }}</span>
                    </div>
                    <div class="mt-1 break-words text-gray-500">{{ log.viewed_fields?.join(', ') || '-' }} · {{ log.ip_address || '-' }}</div>
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
import { computed, defineComponent, h, ref, watch } from 'vue'
import Icon from '@/components/icons/Icon.vue'
import { adminAuditAPI, type GatewayAuditAccessLog, type GatewayAuditBodyRecord, type GatewayAuditDetail, type GatewayAuditEvent } from '@/api/admin/audit'

const props = defineProps<{
  show: boolean
  auditId?: string | null
}>()

const emit = defineEmits<{
  'update:show': [value: boolean]
}>()

const loading = ref(false)
const error = ref('')
const detail = ref<GatewayAuditDetail | null>(null)
const accessLogs = ref<GatewayAuditAccessLog[]>([])
const activeTab = ref<'overview' | 'input' | 'output' | 'route' | 'error' | 'security'>('overview')

const tabs = [
  { key: 'overview', label: '概览' },
  { key: 'input', label: 'Input' },
  { key: 'output', label: 'Output' },
  { key: 'route', label: '路由' },
  { key: 'error', label: '错误' },
  { key: 'security', label: '安全' }
] as const

const event = computed<GatewayAuditEvent>(() => detail.value?.event || {} as GatewayAuditEvent)
const accountLabel = computed(() => {
  const e = event.value
  if (!e.account_id && !e.account_name) return detail.value?.index.account_id || '-'
  return [e.account_name, e.account_id ? `#${e.account_id}` : '', e.account_platform].filter(Boolean).join(' ')
})

watch(
  () => [props.show, props.auditId] as const,
  async ([show, auditId]) => {
    if (!show || !auditId) return
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

const formatMs = (value?: number | null) => {
  if (value == null || value === 0) return '-'
  if (value < 1000) return `${value}ms`
  return `${(value / 1000).toFixed(2)}s`
}

const stringifyBody = (value: unknown): string => {
  if (value == null) return ''
  if (typeof value === 'string') return value
  try {
    return JSON.stringify(value, null, 2)
  } catch {
    return String(value)
  }
}

const copyText = async (value: string) => {
  if (!value) return
  await navigator.clipboard?.writeText(value)
}

const InfoRow = defineComponent({
  props: {
    label: { type: String, required: true },
    value: { type: [String, Number, Boolean], default: '-' },
    mono: { type: Boolean, default: false }
  },
  setup(rowProps) {
    return () => h('div', { class: 'min-w-0 border-b border-gray-100 pb-2 dark:border-dark-700' }, [
      h('div', { class: 'text-xs font-medium text-gray-500 dark:text-gray-400' }, rowProps.label),
      h('div', {
        class: [
          'mt-1 break-words text-sm text-gray-900 dark:text-white',
          rowProps.mono ? 'font-mono' : ''
        ]
      }, rowProps.value == null || rowProps.value === '' ? '-' : String(rowProps.value))
    ])
  }
})

const BodyPanel = defineComponent({
  props: {
    title: { type: String, required: true },
    record: { type: Object as () => GatewayAuditBodyRecord | undefined, default: undefined },
    compact: { type: Boolean, default: false }
  },
  setup(panelProps) {
    return () => {
      const record = panelProps.record
      const body = stringifyBody(record?.body)
      return h('section', { class: 'space-y-3' }, [
        h('div', { class: 'grid grid-cols-1 gap-3 md:grid-cols-2' }, [
          h(InfoRow, { label: `${panelProps.title} Hash`, value: record?.sha256 || '-', mono: true }),
          h(InfoRow, { label: 'Size', value: record?.size_bytes ?? 0 }),
          h(InfoRow, { label: 'Truncated', value: record?.truncated ? 'yes' : 'no' }),
          h(InfoRow, { label: 'Content Type', value: record?.content_type || '-' })
        ]),
        h('div', { class: 'overflow-hidden rounded border border-gray-200 dark:border-dark-700' }, [
          h('div', { class: 'flex items-center justify-between border-b border-gray-200 px-3 py-2 dark:border-dark-700' }, [
            h('span', { class: 'text-sm font-medium text-gray-700 dark:text-gray-300' }, panelProps.title),
            h('button', {
              class: 'btn btn-ghost px-2 py-1 text-xs',
              disabled: !body,
              onClick: () => copyText(body)
            }, '复制')
          ]),
          h('pre', {
            class: [
              'overflow-auto whitespace-pre-wrap break-words bg-gray-50 p-3 font-mono text-xs text-gray-800 dark:bg-dark-950 dark:text-gray-200',
              panelProps.compact ? 'max-h-72' : 'max-h-[60vh]'
            ]
          }, body || '-')
        ])
      ])
    }
  }
})
</script>
