<template>
  <div class="bg" :style="{ opacity: display ? 1 : 0, pointerEvents: display ? 'auto' : 'none' }">
    <div class="container">
      <var-button size="large" type="success" round icon-container text class="closeButton">
        <var-icon name="window-close" color="rgba(66, 66, 66, 0.88)" @click="onCloseButton" />
      </var-button>
      <h2>签到进度</h2>
      <var-cell v-for="node, i in timeLineNodes" :title="node.title" style="padding: 0">
        <template #description>
          <div class="description">{{ node.subtitle }}</div>
        </template>
        <template #icon>
          <div class="circle" :style="{ backgroundColor: node.bgColor }">
            <div class="circleContent" :style="{ color: node.textColor }">
              <var-loading v-if="i == timeLineIndex" size="mini" color="white" />
              <template v-else>{{ i || '?' }}</template>
            </div>
          </div>
        </template>
        <template #extra>
          <div class="cell-extra" style="margin-right: 16px;">
            {{ node.time }}
          </div>
        </template>
      </var-cell>
    </div>
  </div>
</template>
<script setup>
import { useUserStore } from '@/stores/UserStore';
import api from '@/utils/api';
import { Snackbar } from '@varlet/ui';
import { getCurrentInstance, onMounted, onUnmounted, ref, watch } from 'vue';

const timeLineNodes = ref([]);
const timeLineIndex = ref(-1);
const startTime = ref(Date.now());
const userStore = useUserStore();
const isMounting = ref(false);

const props = defineProps({
  display: {
    type: Boolean,
    default: false,
  },
  data: {
    type: Object,
    default: () => ({}),
  },
})

const emit = defineEmits(['closeDialog']);

function addNode(title, extraData = {}, textColor = 'white', bgColor = 'var(--color-primary)') {
  timeLineNodes.value.push({
    "title": title,
    "subtitle": '等待中',
    'time': '',
    'textColor': textColor,
    'bgColor': bgColor,
    extraData
  })
}

function doneNode(subtitle, textColor = 'white', bgColor = 'var(--color-primary)') {
  timeLineNodes.value[timeLineIndex.value].subtitle = subtitle;
  timeLineNodes.value[timeLineIndex.value].time = ((Date.now() - startTime.value) / 1000).toFixed(2) + 's';
  timeLineNodes.value[timeLineIndex.value].textColor = textColor;
  timeLineNodes.value[timeLineIndex.value].bgColor = bgColor;
  timeLineIndex.value++;
}

function getCurrentNode() {
  if (timeLineIndex.value >= timeLineNodes.value.length) {
    return null;
  }
  return timeLineNodes.value[timeLineIndex.value];
}

async function startSignProgress() {
  // 第一步，获取自己和同学的签到状态  
  addNode("查询: 签到状态")
  startTime.value = Date.now();
  timeLineIndex.value = 0;
  const resp = (await api.post('getSignStateFromDataBase', {
    activeId: props.data.fixedParams.activeId,
    classmates: props.data.classmates.map((v) => v.uid),
  })).data;
  if (!resp.suc) {
    Snackbar.error("错误: " + resp.msg)
    return;
  }
  const firstSubtitle = [];
  for (const student of [userStore.currentUser, ...props.data.classmates]) {
    if (resp.data[student.uid].suc) { // 签到过
      firstSubtitle.push(`${student.name}: 已签到(${resp.data[student.uid].comment})`);
    } else { // 需要签到
      addNode((userStore.currentUser.uid == student.uid ? "签到: " : "代签: ") + student.name, {
        uid: student.uid,
        name: student.name,
        mobile: student.mobile,
      })
      firstSubtitle.push(`${student.name}: 未签到`);
    }
    firstSubtitle.push('\n')
  }
  doneNode(firstSubtitle.join(''));
  // 第2-n步，对未签到同学签到
  while (getCurrentNode() !== null) {
    // 判断是否已经关闭了对话框
    if (!props.display || !isMounting.value) {
      console.log("已关闭对话框，停止签到");  
      return;
    }
    const currentNode = getCurrentNode();
    if (currentNode.extraData) {
      const resp2 = (await api.post('sign', {
        fixedParams: props.data.fixedParams,
        specialParams: props.data.specialParams,
        signType: props.data.signType,
        uid: currentNode.extraData.uid,
      })).data;
      doneNode(resp2.msg, 'white', resp2.suc ? 'rgba(0, 222, 0, 255)' : 'red');
    } else {
      doneNode("错误: ExtraData undefined", 'white', 'red');
    }
  }
}

function onCloseButton() {
  emit('closeDialog');
}

onUnmounted(()=>{
  isMounting.value = false;
})
onMounted(() => {
 isMounting.value = true;
})

watch(() => props.display, (newVal, oldVal) => {
  if (oldVal == false && newVal == true) {
    startSignProgress();
  }
})


</script>

<style scoped>
.bg {
  position: absolute;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background-color: rgba(0, 0, 0, 0.5);
  z-index: 1000;
  transition: all .3s ease-in-out;
}

.container {
  position: absolute;
  top: 50%;
  left: 50%;
  width: 85%;
  max-height: 80%;
  background-color: white;
  border-radius: 10px;
  transform: translate(-50%, -50%);
  display: flex;
  justify-content: center;
  align-items: center;
  flex-direction: column;
  padding-right: 6px;
  padding-left: 6px;
  padding-bottom: 16px;
  box-sizing: border-box;
}

.description {
  font-size: 12px;
  color: #666;
  white-space: pre-wrap;
  overflow-y: auto;
  max-height: 160px;
}

.circle {
  width: 24px;
  height: 24px;
  margin: 16px;
  border-radius: 50%;
  background-color: var(--color-primary);
  position: relative;
}

.circleContent {
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  color: white;
  font-weight: 600;
  text-shadow: 1 1 4px rgba(0, 0, 0, 0.3);
}

.closeButton {
  position: absolute;
  top: 16px;
  right: 16px;
  z-index: 1001;
}
</style>