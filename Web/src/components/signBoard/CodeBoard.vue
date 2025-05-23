<template>
  <div style="padding: 8px;">
    <var-input variant="outlined" placeholder="请输入签到码" type="number" v-model="code" />
  </div>
  <div class="confirm-btn" v-ripple :style="{ backgroundColor: buttonColor }" @click="confirm">
    签到
  </div>
</template>
<script setup>
import { Snackbar } from '@varlet/ui';
import { computed, ref } from 'vue';

const props = defineProps({
  signCallBack: {
    type: Function,
    default: (data) => { },
  }
})

const code = ref('');

const verified = computed(() => {
  return code.value.length <= 8 && code.value.length >= 4;
});

const buttonColor = computed(() => {
  return verified.value ? 'var(--color-primary)' : 'grey';
});

function confirm() {
  if (!verified.value) {
    Snackbar.warning('请输入4-8位签到码');
    return;
  };
  props.signCallBack({ signCode: code.value });
}

</script>
<style scoped>
.confirm-btn {
  width: 100%;
  height: 40px;
  display: flex;
  justify-content: center;
  align-items: center;
  color: white;
}
</style>