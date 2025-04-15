import axios from 'axios';
import { useRouter } from 'vue-router';
import { baseURL, version } from './constants';
import { localJson } from './localJson';

// 忽略 token 的 URL 列表
const IGNORE_TOKEN_URLS = ['/login'];


// 跳转到登录页
const redirectToLogin = () => {
  let router = useRouter();
  router.push({name: 'user-login'})
; // 假设是单页应用的登录路径
};

// 创建 axios 实例
export const api = axios.create({
  baseURL: baseURL, // 替换为你的 API 地址
  timeout: 60000,
});

// 请求拦截器
api.interceptors.request.use(async (config) => {
  // 添加版本号
  config.headers['version'] = version;

  // 检查是否忽略 token
  const shouldIgnore = IGNORE_TOKEN_URLS.some(url => config.url.includes(url));
  if (shouldIgnore) {
    return config;
  }

  // 获取 token
  const token = localJson.get('token');

  if (!token) {
    redirectToLogin();
    // 中断请求
    return Promise.reject(new Error('未登录'));
  }

  // 添加 token
  config.headers['token'] = token;
  return config;
}, error => {
  return Promise.reject(error);
});

export default api;
