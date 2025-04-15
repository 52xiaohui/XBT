import cv2
import sys
import json
import os

def calculate_distance(big_image_path, small_image_path):
    # 检查文件是否存在
    if not os.path.exists(big_image_path):
        raise Exception(f"背景图片不存在: {big_image_path}")
    if not os.path.exists(small_image_path):
        raise Exception(f"滑块图片不存在: {small_image_path}")

    # 检查文件大小
    big_size = os.path.getsize(big_image_path)
    small_size = os.path.getsize(small_image_path)
    if big_size == 0:
        raise Exception(f"背景图片文件大小为0: {big_image_path}")
    if small_size == 0:
        raise Exception(f"滑块图片文件大小为0: {small_image_path}")

    # 读取图片
    big_image = cv2.imread(big_image_path, cv2.IMREAD_COLOR)
    small_image = cv2.imread(small_image_path, cv2.IMREAD_COLOR)

    # 检查图片是否读取成功
    if big_image is None:
        raise Exception(f"无法读取背景图片: {big_image_path}")
    if small_image is None:
        raise Exception(f"无法读取滑块图片: {small_image_path}")

    # 检查图片尺寸
    print(f"背景图片尺寸: {big_image.shape}")
    print(f"滑块图片尺寸: {small_image.shape}")

    # 确保滑块图片不大于背景图片
    if small_image.shape[0] > big_image.shape[0] or small_image.shape[1] > big_image.shape[1]:
        raise Exception(f"滑块图片尺寸大于背景图片: 滑块={small_image.shape}, 背景={big_image.shape}")

    # 模板匹配
    result = cv2.matchTemplate(big_image, small_image, cv2.TM_CCOEFF_NORMED)
    _, _, _, max_loc = cv2.minMaxLoc(result)

    print(f"计算的滑块距离: {max_loc[0]}")
    return max_loc[0]  # 返回滑块需要移动的水平距离

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(json.dumps({"error": "需要两个参数：背景图片路径和滑块图片路径"}))
        sys.exit(1)

    big_image_path = sys.argv[1]
    small_image_path = sys.argv[2]

    try:
        distance = calculate_distance(big_image_path, small_image_path)
        print(json.dumps({"distance": distance}))
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)
