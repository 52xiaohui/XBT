export const localJson = {
  // 存储对象到 localStorage
  set(key, value) {
    try {
      const jsonString = JSON.stringify(value);
      localStorage.setItem(key, jsonString);
      return true;
    } catch (error) {
      console.error('存储到 localStorage 失败:', error);
      return false;
    }
  },

  // 从 localStorage 获取对象
  get(key) {
    try {
      const jsonString = localStorage.getItem(key);
      if (jsonString === null) return null;
      return JSON.parse(jsonString);
    } catch (error) {
      console.error('从 localStorage 读取失败:', error);
      return null;
    }
  },

  // 删除指定 key 的数据
  remove(key) {
    try {
      localStorage.removeItem(key);
      return true;
    } catch (error) {
      console.error('删除 localStorage 数据失败:', error);
      return false;
    }
  },

  // 清空所有 localStorage 数据
  clear() {
    try {
      localStorage.clear();
      return true;
    } catch (error) {
      console.error('清空 localStorage 失败:', error);
      return false;
    }
  }
};