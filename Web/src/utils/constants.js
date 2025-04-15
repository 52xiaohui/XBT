// signModule.js

import { config_baseURL, config_locationPreset, config_version } from "@/config";

// baseURL 初始化
export let baseURL = '';
export const version = config_version;

export async function initBaseURL() {
  const storedURL = localStorage.getItem('base_url');
  baseURL = storedURL ?? config_baseURL;
}

// 默认签到限制数量
export const activesLimit = 5;

export const SignType = {
  normal: { id: 0, name: "普通签到", icon: "check-circle-outline" },
  photo: { id: 1, name: "照片签到", icon: "camera-outline" },
  qrCode: { id: 2, name: "二维码签到", icon: "qrcode-scan" },
  gesture: { id: 3, name: "手势签到", icon: "close-box-outline" },
  location: { id: 4, name: "位置签到", icon: "map-marker-radius-outline" },
  code: { id: 5, name: "签到码签到", icon: "code-json" },

  fromId(id) {
    return Object.values(SignType).find(type => type.id === id);
  }
};

// 位置预设数组
export const locationPreset = config_locationPreset;
