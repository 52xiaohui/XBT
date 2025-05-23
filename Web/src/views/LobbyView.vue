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
import { computed, ref, watch, onMounted } from 'vue';
import { useRouter, useRoute } from 'vue-router';

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
];

const router = useRouter();
const route = useRoute();

const active = ref(route.name); // 初始化为当前路由名称

// 监听 active 的变化并更新路由
watch(active, (newVal) => {
  if (newVal !== route.name) {
    router.push({ name: newVal });
  }
});

// 监听路由变化并更新 active
watch(
  () => route.name,
  (newRouteName) => {
    if (newRouteName !== active.value) {
      active.value = newRouteName;
    }
  }
);

// 确保初始值同步
onMounted(() => {
  active.value = route.name;
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