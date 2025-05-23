<template>
  <var-cell :title="title" :description="description" icon="map-marker-radius" ripple @click="onSelectLocation">
  </var-cell>
  <div class="confirm-btn" v-ripple :style="{ backgroundColor: buttonColor }" @click="confirm">
    签到
  </div>
</template>
<script setup>
import { Picker, Snackbar } from '@varlet/ui';
import { locationPreset } from '@/utils/constants';
import { computed, ref } from 'vue';

const locationIndex = ref(-1);

const title = computed(() => {
  if (locationIndex.value === -1) {
    return '请先选择签到地点';
  }
  return locationPreset[locationIndex.value].name;
})

const description = computed(() => {
  if (locationIndex.value === -1) {
    return "点我选择";
  }
  return locationPreset[locationIndex.value].description;
})

const buttonColor = computed(() => {
  return locationIndex.value !== -1 ? 'var(--color-primary)' : 'grey';
});

async function onSelectLocation() {
  const { state, values, indexes, options } = await Picker({
    modelValue: [locationIndex.value === -1 ? Math.round(locationPreset.length / 2) : locationIndex.value],
    columns: [
      locationPreset.map((v, i) => {
        return {
          text: v.name,
          value: i
        }
      })
    ],
    title: '选择签到地点',
  })
  if (state === "confirm") {
    locationIndex.value = values[0];
  }
}

const props = defineProps({
  signCallBack: {
    type: Function,
    default: (data) => { },
  }
})


function confirm() {
  if (locationIndex.value === -1) {
    Snackbar.warning('请先选择签到地点');
    return;
  }
  props.signCallBack({
    'longitude': locationPreset[locationIndex.value]['lng'],
    'latitude': locationPreset[locationIndex.value]['lat'],
    'description': locationPreset[locationIndex.value]['description'],
  });
}

</script>
<style scoped>
.confirm-btn {
  width: 100%;
  height: 40px;
  display: flex;
  justify-content: center;
  align-items: center;
  color: white;
  background-color: var(--color-primary);
}
</style>