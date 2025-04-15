<template>
  <div class="landscape" v-if="isLandscape">
    <div class="portrait" :style="{ width: contentWidth }">
      <div class="contentBackground" style="border-radius: 8px;">
        <RouterView />
      </div>
    </div>
  </div>
  <div class="contentBackground" v-else>
    <RouterView />
  </div>

</template>

<script setup>
import { onMounted, ref } from 'vue';

let isLandscape = ref(false)
let contentWidth = ref(0)

const portraitRadio = 9 / 16;

// Chrome / Safari 100vh bug fix
function setBodyHeight() {
  document.body.style.height = `${window.innerHeight}px`;
  isLandscape.value = window.innerWidth > window.innerHeight;
  contentWidth.value = `${window.innerHeight * portraitRadio}px`;
}
onMounted(() => {
  window.addEventListener('resize', setBodyHeight)
  setBodyHeight()
})
</script>

<style scoped>
.landscape {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 100%;
  width: 100%;
  background-image: linear-gradient(45deg, #fbc2eb 0%, #a6c1ee 100%)
}

.portrait {
  height: 100%;
  padding: 16px;
  box-sizing: border-box;
  filter: drop-shadow(2px 2px 10px rgba(0, 0, 0, 0.2));
}

.contentBackground {
  width: 100%;
  height: 100%;
  background-color: #fff;
  contain: paint;
}
</style>
