import { defineStore } from "pinia";
import { reactive, ref, computed } from "vue";

interface SignRecord {
  signTime: Number,
  source: String,
  sourceName: String,
}

interface Active {
  activeId: Number,
  classId: String,
  courseId: String,
  endTime: Number,
  ifRefreshEwm: Boolean,
  name: String,
  signType: Number,
  startTime: Number,
  signRecord: SignRecord,
}

interface Class {
  classId: Number,
  courseId: Number,
  icon: String,
  name: String,
  teacher: String,
  actives: Active[],
}

export const useSelectedClassStore = defineStore("selectedClass", () => {
  const selectedClass = ref<Class[]>([]);
  
  const setSelectedClass = (classList: Class[]) => {
    selectedClass.value = classList;
  }

  const getClassById = (classId: number) => {
    if (!selectedClass.value) return null;
    return selectedClass.value.find(c => c.classId === classId);
  }

  const getActiveById = (classId: number, activeId: number) => {
    const clazz = getClassById(classId);
    if (!clazz) return null;
    return clazz.actives.find(a => a.activeId === activeId);
  }
  
  return {
    selectedClass,
    setSelectedClass,
    getClassById,
    getActiveById
  }
}, {
  persist: true,
})