<template>
  <!-- appbar -->
  <div style="display: flex;flex-direction: row;align-items: center;">
    <h2 style="margin-right: 8px;">课程列表</h2>
    <var-loading size="small" v-show="isLoading" />
    <div style="flex: 1;"></div>
    <var-button type="primary" text icon-container @click="routeToConfig">
      <var-icon name="cog-outline" color="var(--color-primary)" />
    </var-button>
    <var-button type="primary" text icon-container @click="refreshPage">
      <var-icon name="refresh" color="var(--color-primary)" />
    </var-button>
  </div>

  <var-paper v-for="(clazz, index) in selectedClass" elevation="2" class="paper">
    <var-cell :title="clazz.name"
      :description="clazz.teacher.length > 24 ? clazz.teacher.substring(0, 16) + '...' : clazz.teacher"
      @click="() => { classStates[index].expanded = !classStates[index].expanded }" ripple>
      <template #icon>
        <div style="margin-right: 8px;">
          <var-badge type="danger" :value="classStates[index].badgeCount" :hidden="classStates[index].badgeCount == 0">
            <var-image width="42px" height="42px" fit="cover" radius="4" :src="proxyImage(clazz.icon)" />
          </var-badge>
        </div>
      </template>
      <template #extra>
        <div class="cell-extra">{{ clazz.actives.length > 0 ? getChineseStringByDatetime(new
          Date(clazz.actives[0].startTime)) : '' }}</div>
      </template>
    </var-cell>
    <var-collapse-transition :expand="classStates[index].expanded">
      <var-divider margin="0"></var-divider>
      <template v-for="(active, activeIndex) in clazz.actives">
        <var-cell :title="SignType.fromId(active.signType).name"
          :description="activeStates[index][activeIndex].subtitle" ripple
          :style="{ color: active.endTime > Date.now() ? 'var(--color-primary)' : undefined }"
          @click="onActiveClick(clazz, active)">
          <template #icon>
            <div style="margin-right: 12px;">
              <var-badge type="danger" dot :hidden="!activeStates[index][activeIndex].isBadge">
                <var-icon :name="SignType.fromId(active.signType).icon"></var-icon>
              </var-badge>
            </div>
          </template>
          <template #extra>
            <div class="cell-extra">
              {{ getChineseStringByDatetime(new Date(active.startTime)) }}
            </div>
          </template>
        </var-cell>
        <var-divider margin="0" style="border-color: rgba(0,0,0,0.1);" hairline />
      </template>
      <div v-if="classStates[index].triggeredLimit" class="no-more">仅显示最近{{ activesLimit }}条数据</div>
      <div v-if="clazz.actives.length == 0" class="no-more">暂无签到活动</div>
    </var-collapse-transition>
  </var-paper>
  <div v-if="selectedClass.length == 0">暂无已选择课程！<br>请先点击右上角设置图标按钮选择需要开启代签的课程。<br>选课越少，加载越快，请确保仅选择上课可能会签到的课程！</div>
</template>

<script setup>
import router from '@/router';
import api from '@/utils/api';
import { activesLimit, proxyImage, SignType } from '@/utils/constants';
import { getChineseStringByDatetime } from '@/utils/datetime';
import { getSignSubtitle } from '@/utils/sign';
import { Snackbar } from '@varlet/ui';
import { computed, onMounted, reactive, ref, watch } from 'vue';
import { useSelectedClassStore } from '@/stores/SelectedClassStore';
import { storeToRefs } from 'pinia';

const isLoading = ref(false);
const selectedClassStore = useSelectedClassStore();
const { selectedClass } = storeToRefs(selectedClassStore);

// UI state management
const classStates = reactive([]);
const activeStates = reactive([]);

// Watch for changes in selectedClass and update UI states
watch(selectedClass, (newClasses) => {
  if (!newClasses) return;

  // Initialize or update class states
  const oldClassStates = [...classStates];
  classStates.splice(0, classStates.length);
  activeStates.splice(0, activeStates.length);

  newClasses.forEach((clazz, classIndex) => {
    // Initialize class state
    classStates.push({
      expanded: classIndex < oldClassStates.length ? oldClassStates[classIndex].expanded : false,
      triggeredLimit: clazz.actives.length > activesLimit,
    });
    
    // Initialize active states for this class
    const classActiveStates = [];
    let badgeCount = 0;
    clazz.actives = clazz.actives.slice(0, activesLimit);
    clazz.actives.forEach((active) => {
      const isBadge = active.endTime > Date.now() && active.signRecord.source == 'none'
      classActiveStates.push({
        subtitle: getSignSubtitle(active),
        isActive: active.endTime > Date.now(),
        isBadge
      });
      if (isBadge) badgeCount++;
    });
    classStates[classStates.length - 1].badgeCount = badgeCount;
    activeStates.push(classActiveStates);
  });
}, { immediate: true });

async function refreshPage() {
  isLoading.value = true;
  const resp = (await api.post('getSelectedCourseAndActivityList', {})).data;
  if (!resp.suc) {
    Snackbar({
      type: 'warning',
      content: resp.msg,
      duration: 2000,
    })
    isLoading.value = false;
    return;
  }
  // console.log(resp.data);

  const _selectedClasses = JSON.parse(JSON.stringify(resp.data));
  _selectedClasses.forEach((v, i) => {
    for (let j = 0; j < v.actives.length; j++) {
      v.actives[j].classId = v.classId;
      v.actives[j].courseId = v.courseId;
    }
  });

  selectedClassStore.setSelectedClass(_selectedClasses);
  isLoading.value = false;
}

onMounted(() => {
  refreshPage();
})

function routeToConfig() {
  router.push({
    name: 'sign-config',
  })
}

function onActiveClick(clazz, active) {
  router.push({
    name: 'sign-detail',
    query: {
      classId: clazz.classId,
      activeId: active.activeId
    }
  });
}
</script>

<style scoped>
.paper {
  display: flex;
  flex-direction: column;
  user-select: none;
  -webkit-user-select: none;
}

.no-more {
  text-align: center;
  color: rgba(0, 0, 0, 0.5);
  font-size: 12px;
  padding: 3px;
}
</style>