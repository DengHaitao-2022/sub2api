<template>
  <div class="min-w-0 border-b border-gray-100 pb-2 dark:border-dark-700">
    <div class="text-xs font-medium text-gray-500 dark:text-gray-400">{{ label }}</div>
    <div
      class="mt-1 break-words text-sm text-gray-900 dark:text-white"
      :class="mono ? 'font-mono' : ''"
    >
      {{ displayValue }}
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = withDefaults(defineProps<{
  label: string
  value?: string | number | boolean | null
  mono?: boolean
}>(), {
  value: '-',
  mono: false
})

const displayValue = computed(() => {
  if (props.value == null || props.value === '') {
    return '-'
  }
  if (typeof props.value === 'boolean') {
    return props.value ? 'yes' : 'no'
  }
  return String(props.value)
})
</script>
