<template>
  <div class="bg">
    <canvas ref="canvas" @touchstart="onTouchStart" @touchend="onTouchEnd" @touchmove="onTouchMove"
      @touchcancel="onTouchEnd">
      本浏览器不支持canvas
    </canvas>
  </div>

</template>
<script setup>
import { Snackbar } from '@varlet/ui';
import { onMounted, reactive, ref } from 'vue';

const props = defineProps({
  signCallBack: {
    type: Function,
    default: (data) => { },
  }
})

const n = 3;
const canvas = ref(null);
const ctx = ref(null);
const path = ref([]);
const pointsPos = reactive({})
const isDrawing = ref(false);

function getPathPointFromXY(x, y) {
  return y * n + (x + 1);
}

function initCanvas() {
  ctx.value = canvas.value.getContext('2d');
  canvas.value.width = canvas.value.clientWidth * window.devicePixelRatio;
  canvas.value.height = canvas.value.clientHeight * window.devicePixelRatio;
  drawBoard();
}

function drawBoard() {
  const a = canvas.value.width; // canvas边长
  // 清空画布
  ctx.value.fillStyle = '#fff';
  ctx.value.fillRect(0, 0, a, a);
  // 绘制“点”
  const dotSize = a / 32;
  const gap = a / (n + 1);
  ctx.value.fillStyle = '#000';
  for (let i = 0; i < n; i++) {
    for (let j = 0; j < n; j++) {
      const x = gap * (j + 1);
      const y = gap * (i + 1);
      const r = dotSize / 2;
      const R = dotSize * 2;
      const pathPoint = getPathPointFromXY(j, i);
      const selected = path.value.includes(pathPoint);
      pointsPos[pathPoint] = { x, y, r: R };
      // 中心点
      ctx.value.beginPath();
      ctx.value.arc(x, y, r, 0, Math.PI * 2);
      ctx.value.fillStyle = selected ? '#397AFF' : 'black';
      ctx.value.fill();
      ctx.value.closePath();
      // 边框
      ctx.value.beginPath();
      ctx.value.arc(x, y, R, 0, Math.PI * 2);
      ctx.value.strokeStyle = selected ? '#397AFF' : 'black';
      ctx.value.lineWidth = 3;
      ctx.value.stroke();
      ctx.value.closePath();
    }
  }
  // 绘制连接线
  for (let i = 0; i < path.value.length - 1; i++) {
    const start = pointsPos[path.value[i]];
    const end = pointsPos[path.value[i + 1]];
    ctx.value.beginPath();
    ctx.value.moveTo(start.x, start.y);
    ctx.value.lineTo(end.x, end.y);
    ctx.value.strokeStyle = '#397AFF';
    ctx.value.lineWidth = 6;
    ctx.value.stroke();
    ctx.value.closePath();
  }
}

function getPathPointFromPosition(x, y) {
  for (const key in pointsPos) {
    const point = pointsPos[key];
    if (x >= point.x - point.r && x <= point.x + point.r && y >= point.y - point.r && y <= point.y + point.r) {
      return Number(key);
    }
  }
  return null;
}

function reDraw() {
  path.value = [];
  isDrawing.value = false;
  drawBoard();
}

function handleTouchPointChanged(x, y) {
  const pathPoint = getPathPointFromPosition(x, y);
  if (pathPoint === null) {
    if (path.value.length === 0) return;
    const lastPoint = path.value[path.value.length - 1];
    const lastPointPos = pointsPos[lastPoint];
    // 画线
    drawBoard();
    ctx.value.beginPath();
    ctx.value.moveTo(lastPointPos.x, lastPointPos.y);
    ctx.value.lineTo(x, y);
    ctx.value.strokeStyle = '#397AFF66';
    ctx.value.lineWidth = 6;
    ctx.value.stroke();
    ctx.value.closePath();
    return;
  };
  if (path.value.includes(pathPoint)) return;
  path.value.push(pathPoint);
  drawBoard();
}

function onTouchStart(e) {
  if (isDrawing.value) return;
  const x = (e.targetTouches[0].pageX - canvas.value.getBoundingClientRect().left) * window.devicePixelRatio;
  const y = (e.touches[0].pageY - canvas.value.getBoundingClientRect().top) * window.devicePixelRatio;
  if (getPathPointFromPosition(x, y) !== null) {
    reDraw();
    isDrawing.value = true;
    handleTouchPointChanged(x, y);
    e.preventDefault();
  }
}

function onTouchEnd(e) {
  e.preventDefault();
  isDrawing.value = false;
  drawBoard();
  if (path.value.length === 1) {
    reDraw();
    return;
  }

  if (path.value.length < 4) {
    Snackbar.warning('请至少连接4个点');
    reDraw();
    return;
  }
  props.signCallBack({ signCode: path.value.join('') });
}

function onTouchMove(e) {
  if (!isDrawing.value) return;
  e.preventDefault();
  const x = (e.targetTouches[0].pageX - canvas.value.getBoundingClientRect().left) * window.devicePixelRatio;
  const y = (e.touches[0].pageY - canvas.value.getBoundingClientRect().top) * window.devicePixelRatio;
  handleTouchPointChanged(x, y);
}

onMounted(() => {
  initCanvas();
})

</script>
<style scoped>
.bg {
  aspect-ratio: 1;
  position: relative;
}

canvas {
  width: 100%;
  height: 100%;
}
</style>