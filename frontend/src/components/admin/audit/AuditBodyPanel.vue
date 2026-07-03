<template>
  <section class="space-y-4">
    <div class="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1fr)_320px]">
      <div class="overflow-hidden rounded-lg border border-gray-200 bg-white dark:border-dark-700 dark:bg-dark-900">
        <div class="flex flex-wrap items-center gap-2 border-b border-gray-200 px-4 py-3 dark:border-dark-700">
          <div class="flex min-w-0 flex-1 items-center gap-3">
            <div class="flex h-9 w-9 items-center justify-center rounded-lg bg-primary-50 text-primary-600 dark:bg-primary-500/10 dark:text-primary-300">
              <Icon :name="title.toLowerCase().includes('input') ? 'arrowDown' : 'arrowUp'" size="sm" />
            </div>
            <div class="min-w-0">
              <div class="truncate text-sm font-semibold text-gray-900 dark:text-white">{{ title }}</div>
              <div class="mt-0.5 text-xs text-gray-500 dark:text-gray-400">{{ bodySummary }}</div>
            </div>
          </div>

          <div
            v-if="hasStructuredView"
            class="inline-flex h-9 items-center rounded-lg border border-gray-200 bg-gray-50 p-1 dark:border-dark-700 dark:bg-dark-800"
          >
            <button
              type="button"
              class="rounded-md px-3 py-1.5 text-xs font-medium transition"
              :class="viewMode === 'formatted'
                ? 'bg-white text-gray-900 shadow-sm dark:bg-dark-900 dark:text-white'
                : 'text-gray-500 hover:text-gray-900 dark:text-gray-400 dark:hover:text-white'"
              @click="viewMode = 'formatted'"
            >
              格式化
            </button>
            <button
              type="button"
              class="rounded-md px-3 py-1.5 text-xs font-medium transition"
              :class="viewMode === 'raw'
                ? 'bg-white text-gray-900 shadow-sm dark:bg-dark-900 dark:text-white'
                : 'text-gray-500 hover:text-gray-900 dark:text-gray-400 dark:hover:text-white'"
              @click="viewMode = 'raw'"
            >
              原始
            </button>
          </div>

          <button
            type="button"
            class="btn btn-ghost h-9 px-3 text-xs"
            @click="wrapLines = !wrapLines"
          >
            <Icon :name="wrapLines ? 'chevronDown' : 'chevronRight'" size="xs" class="mr-1" />
            {{ wrapLines ? '自动换行' : '单行滚动' }}
          </button>

          <button
            type="button"
            class="btn btn-ghost h-9 px-3 text-xs"
            :disabled="!copyValue"
            @click="copyCurrentContent"
          >
            <Icon name="copy" size="xs" class="mr-1" />
            复制
          </button>
        </div>

        <div
          v-if="notice"
          class="border-b px-4 py-3 text-sm"
          :class="noticeClass"
        >
          {{ notice }}
        </div>

        <div v-if="!hasBody" class="px-4 py-12 text-center text-sm text-gray-500 dark:text-gray-400">
          {{ emptyStateText }}
        </div>

        <div v-else class="bg-gray-50 dark:bg-dark-950">
          <div class="grid min-w-full grid-cols-[auto_minmax(0,1fr)]">
            <template v-for="(line, index) in activeLines" :key="`${index}-${line.text}`">
              <div class="select-none border-r border-gray-200 px-3 py-0.5 text-right text-[11px] leading-6 text-gray-400 dark:border-dark-700 dark:text-gray-500">
                {{ index + 1 }}
              </div>
              <pre
                class="overflow-visible px-4 py-0.5 text-[13px] leading-6 text-gray-800 dark:text-gray-100"
                :class="[
                  wrapLines ? 'whitespace-pre-wrap break-words' : 'whitespace-pre overflow-x-auto',
                  viewMode === 'formatted' && hasStructuredView ? 'font-mono' : 'font-mono'
                ]"
              ><code v-if="line.html" v-html="line.html" /><code v-else>{{ line.text || ' ' }}</code></pre>
            </template>
          </div>
        </div>
      </div>

      <div class="space-y-3">
        <div class="rounded-lg border border-gray-200 bg-white p-4 dark:border-dark-700 dark:bg-dark-900">
          <div class="mb-3 flex flex-wrap gap-2">
            <span class="inline-flex items-center rounded-full bg-gray-100 px-2.5 py-1 text-xs font-medium text-gray-700 dark:bg-dark-800 dark:text-gray-300">
              {{ modeLabel }}
            </span>
            <span class="inline-flex items-center rounded-full bg-gray-100 px-2.5 py-1 text-xs font-medium text-gray-700 dark:bg-dark-800 dark:text-gray-300">
              {{ payloadLabel }}
            </span>
            <span
              class="inline-flex items-center rounded-full px-2.5 py-1 text-xs font-medium"
              :class="record?.truncated
                ? 'bg-amber-100 text-amber-700 dark:bg-amber-500/10 dark:text-amber-300'
                : 'bg-emerald-100 text-emerald-700 dark:bg-emerald-500/10 dark:text-emerald-300'"
            >
              {{ record?.truncated ? '已截断' : '未截断' }}
            </span>
          </div>

          <div class="grid grid-cols-1 gap-3">
            <AuditInfoRow label="内容类型" :value="record?.content_type || '-'" mono />
            <AuditInfoRow label="大小" :value="formatBytes(record?.size_bytes || 0)" />
            <AuditInfoRow label="行数" :value="lineCount" />
            <AuditInfoRow label="Hash" :value="record?.sha256 || '-'" mono />
          </div>
        </div>

        <div
          v-if="hasBody && previewSnippet"
          class="rounded-lg border border-gray-200 bg-white p-4 dark:border-dark-700 dark:bg-dark-900"
        >
          <div class="mb-2 text-xs font-medium text-gray-500 dark:text-gray-400">首屏摘要</div>
          <div class="line-clamp-6 text-sm text-gray-700 dark:text-gray-300">
            {{ previewSnippet }}
          </div>
        </div>
      </div>
    </div>
  </section>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'

import type { GatewayAuditBodyRecord } from '@/api/admin/audit'
import Icon from '@/components/icons/Icon.vue'
import AuditInfoRow from './AuditInfoRow.vue'

type ViewMode = 'formatted' | 'raw'

const props = defineProps<{
  title: string
  record?: GatewayAuditBodyRecord
  captureMode?: string
}>()

const viewMode = ref<ViewMode>('formatted')
const wrapLines = ref(true)

const normalizedCaptureMode = computed(() => {
  const mode = props.captureMode?.trim().toLowerCase()
  return mode || 'preview'
})

const bodyValue = computed(() => props.record?.body)

const structuredValue = computed<unknown | undefined>(() => {
  const value = bodyValue.value
  if (value == null || value === '') {
    return undefined
  }
  if (typeof value === 'string') {
    const trimmed = value.trim()
    if (!trimmed) {
      return undefined
    }
    try {
      return JSON.parse(trimmed)
    } catch {
      return undefined
    }
  }
  if (typeof value === 'object') {
    return value
  }
  return undefined
})

const hasStructuredView = computed(() => structuredValue.value !== undefined)

watch(hasStructuredView, (structured) => {
  if (!structured) {
    viewMode.value = 'raw'
  } else if (viewMode.value !== 'formatted' && viewMode.value !== 'raw') {
    viewMode.value = 'formatted'
  }
}, { immediate: true })

const payloadLabel = computed(() => {
  if (structuredValue.value !== undefined) {
    return Array.isArray(structuredValue.value) ? 'JSON Array' : 'JSON Object'
  }
  if (typeof bodyValue.value === 'string' && bodyValue.value !== '') {
    return 'Text'
  }
  return 'No Body'
})

const modeLabel = computed(() => ({
  none: '未采集',
  hash: '仅 Hash',
  preview: 'Preview',
  full: 'Full',
}[normalizedCaptureMode.value] || normalizedCaptureMode.value))

const formattedText = computed(() => {
  if (structuredValue.value !== undefined) {
    try {
      return JSON.stringify(structuredValue.value, null, 2)
    } catch {
      return String(structuredValue.value)
    }
  }
  if (typeof bodyValue.value === 'string') {
    return bodyValue.value
  }
  if (bodyValue.value == null) {
    return ''
  }
  return String(bodyValue.value)
})

const rawText = computed(() => {
  const value = bodyValue.value
  if (typeof value === 'string') {
    return value
  }
  if (value == null) {
    return ''
  }
  try {
    return JSON.stringify(value)
  } catch {
    return String(value)
  }
})

const activeText = computed(() => {
  if (!hasStructuredView.value) {
    return rawText.value
  }
  return viewMode.value === 'formatted' ? formattedText.value : rawText.value
})

const copyValue = computed(() => activeText.value)

const hasBody = computed(() => {
  if (props.record == null) {
    return false
  }
  if (bodyValue.value == null) {
    return false
  }
  if (typeof bodyValue.value === 'string') {
    return bodyValue.value.length > 0
  }
  return true
})

const lineCount = computed(() => {
  if (!activeText.value) {
    return 0
  }
  return activeText.value.split('\n').length
})

const bodySummary = computed(() => {
  const parts = [payloadLabel.value]
  if (props.record?.size_bytes) {
    parts.push(formatBytes(props.record.size_bytes))
  }
  if (lineCount.value > 0) {
    parts.push(`${lineCount.value} lines`)
  }
  return parts.join(' · ')
})

const previewSnippet = computed(() => {
  const text = formattedText.value.trim()
  if (!text) {
    return ''
  }
  return text.length > 320 ? `${text.slice(0, 320)}...` : text
})

const emptyStateText = computed(() => {
  if (normalizedCaptureMode.value === 'none') {
    return '当前配置未采集正文内容。'
  }
  if (normalizedCaptureMode.value === 'hash') {
    return '当前仅记录 hash 与大小，没有保存正文。'
  }
  return '没有可展示的正文内容。'
})

const notice = computed(() => {
  if (normalizedCaptureMode.value === 'none') {
    return '当前 capture mode 为 none，审计不会保存正文内容。'
  }
  if (normalizedCaptureMode.value === 'hash') {
    return '当前 capture mode 为 hash，仅保留指纹与大小，便于校验但不可回看正文。'
  }
  if (props.record?.truncated) {
    return '该内容在写入审计时已按字节上限截断，以下不是完整原文。'
  }
  if (normalizedCaptureMode.value !== 'full') {
    return `当前展示的是 ${normalizedCaptureMode.value} 模式下采集到的内容片段。`
  }
  return '这里展示的是审计中保存的完整正文；敏感字段仍会按照脱敏规则处理。'
})

const noticeClass = computed(() => {
  if (props.record?.truncated || normalizedCaptureMode.value === 'preview') {
    return 'border-amber-200 bg-amber-50 text-amber-800 dark:border-amber-500/20 dark:bg-amber-500/10 dark:text-amber-200'
  }
  if (normalizedCaptureMode.value === 'none' || normalizedCaptureMode.value === 'hash') {
    return 'border-slate-200 bg-slate-50 text-slate-700 dark:border-dark-700 dark:bg-dark-800 dark:text-slate-300'
  }
  return 'border-emerald-200 bg-emerald-50 text-emerald-800 dark:border-emerald-500/20 dark:bg-emerald-500/10 dark:text-emerald-200'
})

type CodeLine = {
  text: string
  html?: string
}

const activeLines = computed<CodeLine[]>(() => {
  const lines = activeText.value.split('\n')
  const highlightJson = hasStructuredView.value
  return lines.map((line) => ({
    text: line,
    html: highlightJson ? highlightJSONLine(line) : undefined,
  }))
})

const copyCurrentContent = async () => {
  if (!copyValue.value) {
    return
  }
  await navigator.clipboard?.writeText(copyValue.value)
}

function formatBytes(value: number): string {
  if (!Number.isFinite(value) || value <= 0) {
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

function escapeHTML(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
}

function highlightJSONLine(line: string): string {
  return escapeHTML(line).replace(
    /("(?:\\u[\da-fA-F]{4}|\\[^u]|[^\\"])*"(?:\s*:)?|\btrue\b|\bfalse\b|\bnull\b|-?\d+(?:\.\d+)?(?:[eE][+\-]?\d+)?)/g,
    (token) => {
      let cls = 'text-slate-700 dark:text-slate-300'
      if (token.startsWith('"')) {
        cls = token.endsWith(':')
          ? 'text-sky-700 dark:text-sky-300'
          : 'text-emerald-700 dark:text-emerald-300'
      } else if (token === 'true' || token === 'false') {
        cls = 'text-violet-700 dark:text-violet-300'
      } else if (token === 'null') {
        cls = 'text-amber-700 dark:text-amber-300'
      } else {
        cls = 'text-fuchsia-700 dark:text-fuchsia-300'
      }
      return `<span class="${cls}">${token}</span>`
    }
  )
}
</script>
