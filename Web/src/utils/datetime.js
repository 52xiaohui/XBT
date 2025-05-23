export const getZeroOclockOfDay = (dateTime) => {
  return new Date(dateTime.getFullYear(), dateTime.getMonth(), dateTime.getDate());
};

export const padLeft = (num, length = 2, fill = '0') => {
  return num.toString().padStart(length, fill);
};

export const getChineseStringByDatetime = (dateTime, now = null) => {
  // 确保输入是有效的日期对象
  if (!(dateTime instanceof Date) || isNaN(dateTime.getTime())) {
    return '无效时间';
  }

  now = now ?? new Date();

  const isSameDay = dateTime.getFullYear() === now.getFullYear() &&
    dateTime.getMonth() === now.getMonth() &&
    dateTime.getDate() === now.getDate();

  if (isSameDay) {
    // Same day
    const min = (now.getHours() * 60 + now.getMinutes()) -
      (dateTime.getHours() * 60 + dateTime.getMinutes());

    if (min <= 1) return '刚刚';
    if (min < 60) return `${min}分钟前`;
    return `${now.getHours() - dateTime.getHours()}小时前`;
  }

  // Different day
  const dayDiff = Math.floor(
    (getZeroOclockOfDay(now) - getZeroOclockOfDay(dateTime)) / (1000 * 60 * 60 * 24)
  );

  if (dayDiff <= 0) return '未来(请检查本机系统时间)';
  if (dayDiff === 1) return `昨天${padLeft(dateTime.getHours())}:${padLeft(dateTime.getMinutes())}`;
  if (dayDiff === 2) return '前天';
  if (dayDiff <= 7) return `${dayDiff}天前`;

  // Full date format
  return `${dateTime.getFullYear()}-${padLeft(dateTime.getMonth() + 1)}-${padLeft(dateTime.getDate())}`;
};
