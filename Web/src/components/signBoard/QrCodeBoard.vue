<template>
  <div class="bg">
    <video ref="video" id="video" autoplay>
    </video>
    <div class="tip">{{ form.tipMsg }}</div>
  </div>

</template>
<script setup>
import { ref, onUnmounted, reactive, onMounted } from 'vue'
import { BrowserMultiFormatReader } from '@zxing/library'
import { Snackbar } from '@varlet/ui'

const props = defineProps({
  signCallBack: {
    type: Function,
    default: (data) => { },
  }
})

const form = reactive({
  tipMsg: '尝试识别中...'
})


function onScaned(text) {
  if (!text.includes("mobilelearn.chaoxing.com")) {
    form.tipMsg = '请扫描学习通二维码'
    return
  }
  const enc = text.split('&enc=')[1].split('&')[0];
  const c = text.split('&c=')[1].split('&')[0];
  form.tipMsg = '扫码成功'
  props.signCallBack({ enc, c })
}


const codeReader = new BrowserMultiFormatReader()
const openScan = () => {
  codeReader
    .getVideoInputDevices()
    .then(async (videoInputDevices) => {
      form.tipMsg = '正在调用摄像头...'
      let firstDeviceId = videoInputDevices[0].deviceId
      // 获取第一个摄像头设备的名称
      const videoInputDeviceslablestr = JSON.stringify(videoInputDevices[0].label)
      if (videoInputDevices.length > 1) {
        if (videoInputDeviceslablestr.indexOf('back') > -1) {
          firstDeviceId = videoInputDevices[0].deviceId
        } else {
          firstDeviceId = videoInputDevices[1].deviceId
        }
      }
      decodeFromInputVideoFunc(firstDeviceId)
    })
    .catch((err) => {
      form.tipMsg = '请检查摄像头(权限)是否正常'
    })
}

const decodeFromInputVideoFunc = (firstDeviceId) => {
  codeReader.reset() // 重置
  codeReader.decodeFromInputVideoDeviceContinuously(firstDeviceId, 'video', (result, err) => {
    form.tipMsg = '正在尝试识别...' // 提示信息
    if (result) {
      onScaned(result.getText())
    }
    if (err && !err) {
      form.tipMsg = '识别失败'
    }
  })
}
//销毁组件
onUnmounted(() => {
  codeReader.reset();
  codeReader.stopContinuousDecode();
})

onMounted(() => {
  openScan() // 调用扫码方法
})

</script>
<style scoped>
.bg {
  aspect-ratio: 1;
  width: 100%;
  position: relative;
}

#video {
  object-fit: cover;
  width: 100%;
  height: 100%;
}

.tip {
  position: absolute;
  top: 88%;
  left: 50%;
  transform: translate(-50%, -50%);
  color: white;
  font-size: 20px;
  text-align: center;
  text-shadow: 1px 1px 5px rgba(0, 0, 0, 1);
  z-index: 111;
}
</style>