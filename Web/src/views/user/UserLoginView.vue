<template>
  <div class="bg">
    <div class="card">
      <div class="title">
        学不通
      </div>
      <var-input variant="outlined" size="small" placeholder="手机号" v-model="mobile" style="width: 100%;"
        blur-color="rbga(0,0,0,0.9)" />
      <var-input variant="outlined" size="small" type="password" placeholder="密码" v-model="password"
        style="width: 100%;" blur-color="rbga(0,0,0,0.9)" />
      <p style="font-weight: lighter;">注册即代表同意本网站收集您的第三方网站隐私信息。其中包括:
        姓名，手机号，密码，课程信息等。您的密码将仅用于登录第三方网站，已经过非对称加密处理，本网站保证您的密码不会进行明文存储以及传输。</p>
      <var-button :loading="loading" block type="primary" @click="onLogin">登录 / 注册</var-button>
    </div>
  </div>
</template>
<script setup>
import router from '@/router';
import { useUserStore } from '@/stores/UserStore';
import api from '@/utils/api';
import { encodeToken } from '@/utils/encrypt';
import { Snackbar } from '@varlet/ui';
import { ref } from 'vue';

const mobile = ref('');
const password = ref('');

const loading = ref(false);

async function onLogin() {
  const _mobile = mobile.value;
  const _password = password.value;
  if (!_mobile || !_password) {
    Snackbar.error('手机号或密码不能为空');
    return;
  }
  if (!/^\d{11}$/.test(_mobile)) {
    Snackbar.warning('手机号格式错误');
    return;
  }
  if (_password.length < 6) {
    Snackbar.warning('密码长度不能小于6位');
    return;
  }

  loading.value = true;
  const token = await encodeToken(_mobile, _password);
  const resp = (await api.post('login', { token: token })).data;

  if (!resp.suc) {
    Snackbar.error(resp.msg);
    loading.value = false;
    return;
  }

  const userStore = useUserStore();
  userStore.addUser({
    uid: resp.data.uid,
    name: resp.data.name,
    avatar: resp.data.avatar,
    mobile: _mobile,
    token: token,
  })
  loading.value = false;
  router.push({ path: '/' });
  Snackbar.success('登录成功');
}

</script>
<style scoped>
.bg {
  background-image: linear-gradient(120deg, #89f7fe 0%, #66a6ff 100%);
  height: 100%;
  width: 100%;
  display: flex;
  justify-content: center;
  align-items: center;
}

.card {
  width: 80%;
  background-color: rgba(255, 255, 255, 0.4);
  border: 2px solid rgba(255, 255, 255, 1);
  border-radius: 16px;
  padding: 32px;
  box-sizing: border-box;
  display: flex;
  align-items: center;
  justify-content: center;
  box-shadow: 2px 2px 16px rgba(0, 0, 0, 0.2);
  flex-direction: column;
  gap: 16px;
}

.title {
  font-size: 48px;
  font-weight: bold;
}
</style>