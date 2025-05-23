<template>
  <div style="overflow-y: auto;height: 100%;width: 100%;">
    <div style="height: fit-content;width: 100%;padding: 8px;box-sizing: border-box;">
      <div style="display: flex;flex-direction: row;align-items: center;">
        <h2 style="margin-right: 8px;">配置生效课程</h2>
        <var-loading size="small" v-show="isLoading" />
        <div style="flex: 1;"></div>
        <var-button type="primary" @click="onDone">完成</var-button>
      </div>
    </div>
    <template v-for="(course, index) in allCourses" :key="index">
      <var-cell :title="course.name" :description="course.teacher" ripple @click="onCourseTap(index)">
        <template #icon>
          <var-image width="42px" height="42px" fit="cover" radius="4" :src="proxyImage(course.icon)"
            style="margin-right: 8px;" />
        </template>
        <template #extra>
          <var-switch v-model="course.isSelected" @click.stop @change="() => onCourseTap(index)" />
        </template>
      </var-cell>
      <var-divider margin="0" style="border-color: rgba(0,0,0,0.1);" hairline />
    </template>
  </div>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import api from '@/utils/api';
import { proxyImage } from '@/utils/constants';
import { Snackbar } from '@varlet/ui';

const route = useRoute();
const router = useRouter();
const allCourses = reactive([]);
const isLoading = ref(false);

// 设置课程选择状态
const setCourseSelectState = async () => {
  try {
    await api.post('setCourseSelectState', {
      courses: allCourses
    });
  } catch (error) {
    Snackbar.error('保存失败');
  }
};

// 刷新页面
async function refreshPage() {
  isLoading.value = true;
  try {
    const resp = await api.post('getAllCourse', {});
    if (!resp.data.suc) {
      Snackbar.warning(resp.data.msg);
      return;
    }

    const courses = resp.data.data.map(course => ({
      name: course.name,
      teacher: course.teacher,
      icon: course.icon,
      isSelected: course.isSelected === 1,
      courseId: course.courseId,
      classId: course.classId,
    }));

    // 按选中状态和名称排序
    courses.sort((a, b) => {
      if (a.isSelected === b.isSelected) {
        return a.name.localeCompare(b.name);
      }
      return a.isSelected ? -1 : 1;
    });

    allCourses.splice(0, allCourses.length, ...courses);
  } catch (error) {
    Snackbar.error('加载失败');
  }
  isLoading.value = false;
}

// 处理课程点击
async function onCourseTap(index) {
  allCourses[index].isSelected = !allCourses[index].isSelected;
  await setCourseSelectState();
}

// 处理完成按钮点击
async function onDone() {
  if (isLoading.value) {
    Snackbar.warning('请稍后再试');
    return;
  }

  Snackbar.loading('更改中...');
  try {
    await setCourseSelectState();
    router.back();
    Snackbar.success('更改成功');
  } catch (error) {
    Snackbar.error('更改失败');
  }
}

onMounted(() => {
  refreshPage();
});
</script>

<style scoped>
.paper {
  display: flex;
  flex-direction: column;
  user-select: none;
  -webkit-user-select: none;
}
</style>