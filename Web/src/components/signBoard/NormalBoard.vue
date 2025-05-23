<template>
  <div class="confirm-btn" v-ripple :style="{ backgroundColor: buttonColor }" @click="confirm">
    签到
  </div>
</template>
<script setup>

const props = defineProps({
  signCallBack: {
    type: Function,
    default: (data) => { },
  }
})


function confirm() {
  props.signCallBack({});
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
  background-color: var(--color-primary);
}
</style>