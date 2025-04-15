<template>
  <div class="screen">
    <div class="body">
      <div class="content">
        <RouterView />
      </div>
    </div>
    <var-bottom-navigation v-model:active="active">
      <var-bottom-navigation-item v-for="(item, index) in actives" :key="index" :name="item.name" :icon="item.icon"
        :label="item.label" />
    </var-bottom-navigation>
  </div>

</template>

<script setup>
import { computed, ref, watch } from 'vue';
import { useRouter } from 'vue-router';

const actives = [
  {
    name: 'sign-lobby',
    icon: 'home',
    label: '签到',
  },
  {
    name: 'user-lobby',
    icon: 'account-circle',
    label: '用户',
  }
]

let router = useRouter();

const active = ref('sign-lobby');

watch(active, (newVal) => {
  router.push({ name: newVal });
});
</script>

<style scoped>
.screen {
  display: flex;
  flex-direction: column;
  height: 100%;
  width: 100%;
}

.body {
  flex: 1;
  border-bottom: 1px solid #e0e0e0;
  overflow: auto;
}

.content {
  display: flex;
  flex-direction: column;
  padding: 8px;
  gap: 8px;
  height: fit-content;
}
</style>