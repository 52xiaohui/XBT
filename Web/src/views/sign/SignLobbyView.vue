<template>
  <h2>课程列表</h2>
  <var-paper elevation="2" class="paper">
    <var-cell title="课程名字" description="教师名字" @click="() => { }" ripple>
      <template #icon>
        <var-image width="42px" height="42px" fit="cover" radius="4" src="https://varletjs.org/cat.jpg"
          style="margin-right: 8px;" />
      </template>
      <template #extra>
        <div class="cell-extra">8分钟前</div>
      </template>
    </var-cell>
    <var-divider margin="0"></var-divider>
    <var-cell icon="map-marker" title="签到类型" description="签到状态" ripple>
      <template #extra>
        <div class="cell-extra">8分钟前</div>
      </template>
    </var-cell>
    <var-cell icon="qrcode-scan" title="签到类型" description="签到状态" ripple>
      <template #extra>
        <div class="cell-extra">2025-04-01</div>
      </template>
    </var-cell>
  </var-paper>


</template>

<script setup>
import { reactive, ref } from 'vue';
let selectedClasses = reactive(
  [
    {
      'expanded': false,
      "actives": [
        { "activeId": 7700223477089, "endTime": 1743671311426, "ifRefreshEwm": false, "name": "22277402第25次课签到", "signRecord": { "signTime": 2743877788, "source": "self", "sourceName": "小明" }, "signType": 4, "startTime": 1743671311426 },
        { "activeId": 7700223034249, "endTime": 1743671311426, "ifRefreshEwm": false, "name": "22277332第29次课 签到", "signRecord": { "signTime": 2743388297, "source": "self", "sourceName": "小明" }, "signType": 4, "startTime": 1743671311426 },
        { "activeId": 7700222742083, "endTime": 1743671311426, "ifRefreshEwm": false, "name": "22283027第28次课签到", "signRecord": { "signTime": 2743062423, "source": "self", "sourceName": "小明" }, "signType": 4, "startTime": 1743671311426 },
        { "activeId": 7700222863048, "endTime": 1743671311426, "ifRefreshEwm": false, "name": "22277326第27次课签到", "signRecord": { "signTime": 2742976283, "source": "agent", "sourceName": "小明" }, "signType": 4, "startTime": 1743671311426 },
        { "activeId": 7700222208283, "endTime": 1743671311426, "ifRefreshEwm": false, "name": "22277324第26次课签到", "signRecord": { "signTime": 2742783383, "source": "self", "sourceName": "小明" }, "signType": 4, "startTime": 1743671311426 },
        { "activeId": 7700222773468, "endTime": 1743671311426, "ifRefreshEwm": true, "name": "22277320第28次课签到", "signRecord": { "signTime": 2742487828, "source": "agent", "sourceName": "小明" }, "signType": 4, "startTime": 1743671311426 }
      ], "classId": 224684288, "courseId": 249932822, "icon": "https://varletjs.org/cat.jpg", "isSelected": 2, "name": "高等数学A（2 ）", "teacher": "老师2"
    },
    {
      'expanded': false,
      "actives": [
        { "activeId": 3000228939082, "endTime": 1743671311426, "ifRefreshEwm": false, "name": "签到", "signRecord": { "signTime": 2742228822, "source": "self", "sourceName": "小明" }, "signType": 3, "startTime": 1743671311426 },
        { "activeId": 3000228328262, "endTime": 1743671311426, "ifRefreshEwm": false, "name": "签到", "signRecord": { "signTime": 2740963327, "source": "self", "sourceName": "小明" }, "signType": 3, "startTime": 1743671311426 },
        { "activeId": 3000224300670, "endTime": 1743671311426, "ifRefreshEwm": false, "name": "签到", "signRecord": { "signTime": -2, "source": "none", "sourceName": "未签到" }, "signType": 3, "startTime": 1743671311426 }],
      "classId": 224363239, "courseId": 249826428, "icon": "https://varletjs.org/cat.jpg", "isSelected": 2, "name": "大学物理A（2）/B", "teacher": "老师1"
    }
  ]
);



</script>
<style scoped>
.paper {
  display: flex;
  flex-direction: column;
  user-select: none;
  -webkit-user-select: none;
}
</style>