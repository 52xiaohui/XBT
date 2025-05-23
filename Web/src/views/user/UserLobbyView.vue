<template>
  <var-button @click="routeToLogin" type="primary" round icon-container
    style="width: 48px;height: 48px;position: absolute;bottom: 66px;right: 16px;">
    <var-icon name="plus" />
  </var-button>
  <template v-if="currentUser != null">
    <h2>当前用户</h2>
    <var-paper elevation="2" class="paper">
      <var-cell :title="currentUser.name"
        :description="currentUser.mobile.substring(0, 3) + '****' + currentUser.mobile.substring(7, 11)">
        <template #icon>
          <var-image width="42px" height="42px" fit="cover" radius="4" style="margin-right: 8px;"
            :src="proxyImage(currentUser.avatar)" />
        </template>
        <template #extra>
          <div class="cell-extra">
            <var-button text type="primary" @click.stop @click="logout(currentUser.uid)">退出登录</var-button>
          </div>
        </template>
      </var-cell>
    </var-paper>
    <template v-if="otherUserList.length > 0">
      <h2>其他用户</h2>
      <var-paper elevation="2" class="paper" v-for="(user, index) in otherUserList" :key="user.mobile">
        <var-cell :title="user.name" :description="user.mobile.substring(0, 3) + '****' + user.mobile.substring(7, 11)">
          <template #icon>
            <var-image width="42px" height="42px" fit="cover" radius="4" style="margin-right: 8px;"
              :src="proxyImage(user.avatar)" />
          </template>
          <template #extra>
            <div class="cell-extra">
              <var-button text type="primary" @click="changeCurrentUser(user.uid)">切换</var-button>
              <var-button text type="primary" @click="removeUser(user.uid)">删除</var-button>
            </div>
          </template>
        </var-cell>
      </var-paper>
    </template>
  </template>
</template>
<script setup>
import router from '@/router';
import { useUserStore } from '@/stores/UserStore';
import { proxyImage } from '@/utils/constants';
import { Dialog, Snackbar } from '@varlet/ui';
import { storeToRefs } from 'pinia';
import { onBeforeMount, onMounted, watch } from 'vue';

const userStore = useUserStore();
const currentUser = storeToRefs(userStore).currentUser;
const otherUserList = storeToRefs(userStore).otherUserList;

function routeToLogin() {
  router.push({ name: 'user-login' })
}

async function changeCurrentUser(uid) {
  const resp = await Dialog({
    title: '请选择',
    message: '是否切换至该用户？',
  })
  if (resp !== 'confirm') {
    return;
  }
  userStore.changeCurrentUser(uid);
  router.push({ path: '/' })
  Snackbar.success('切换成功');
}

async function removeUser(uid) {
  const resp = await Dialog({
    title: '请选择',
    message: '是否删除该用户？',
  })
  if (resp !== 'confirm') {
    return;
  }
  userStore.removeUser(uid);
  Snackbar.success('删除成功');
}

async function logout(uid) {
  const resp = await Dialog({
    title: '请选择',
    message: '是否退出登录？',
  })
  if (resp !== 'confirm') {
    return;
  }
  userStore.removeUser(uid);
  router.push({ path: '/' })
  Snackbar.success('退出登录成功');
}

watch(currentUser, (newVal)=>{
  if (newVal == null) {
    router.push({ name: 'user-login' })
    Snackbar.warning('请先登录')
  }
}, { immediate: true })

</script>
<style scoped></style>