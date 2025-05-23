from enum import Enum
import pymysql
import json
from dbutils.pooled_db import PooledDB

mysqlConf = json.load(open('./keys/mysql.json'))

POOL = PooledDB(
  creator=pymysql,  # 使用链接数据库的模块
  maxconnections=mysqlConf['maxconnections'],  # 连接池允许的最大连接数，0和None表示不限制连接数
  mincached=2,  # 初始化时，链接池中至少创建的空闲的链接，0表示不创建
  blocking=True,  # 连接池中如果没有可用连接后，是否阻塞等待。True，等待；False，不等待然后报错
  ping=0,  # ping MySQL服务端，检查是否服务可用。如：0 = None = never, 1 = default = whenever it is requested, 2 = when a cursor is created, 4 = when a query is executed, 7 = always
  host=mysqlConf['host'],
  port=mysqlConf['port'],
  user=mysqlConf['user'],
  password=mysqlConf['passwd'],
  database=mysqlConf['db'],
  charset=mysqlConf['charset']
)

getActivesLimit = 6

allowedProxyUrl = {
  "https://photo.chaoxing.com/p/",
  "http://photo.chaoxing.com/p/",
  "https://p.ananas.chaoxing.com/star3",
  "http://p.ananas.chaoxing.com/star3",
}

webFormHeaders = {
  'Content-Type': "application/x-www-form-urlencoded; charset=UTF-8",
  'User-Agent': "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
}

mobileFormHeaders = {
  'Content-Type': "application/x-www-form-urlencoded; charset=UTF-8",
  "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 14; Redmi K20 Pro Build/UKQ1.230804.001) (schild:0945de15614364966e17460057ab5aa6) (device:Redmi K20 Pro) Language/zh_CN com.chaoxing.mobile/ChaoXingStudy_3_6.4.8_android_phone_10834_264 (@Kalimdor)_aa664e5fbb1d46df8e5aa65f62a438d8"
}

webHeader = {
  'User-Agent': "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
}

mobileHeader = {
  "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 14; Redmi K20 Pro Build/UKQ1.230804.001) (schild:0945de15614364966e17460057ab5aa6) (device:Redmi K20 Pro) Language/zh_CN com.chaoxing.mobile/ChaoXingStudy_3_6.4.8_android_phone_10834_264 (@Kalimdor)_aa664e5fbb1d46df8e5aa65f62a438d8"
}

imageHeaders = {
  "Referer": "https://mooc1-1.chaoxing.com/",
  "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
}


transferKey = "u2oh6Vu^HWe4_AES"

# QR码刷新相关配置
qrCodeRefreshMinInterval = 2  # 最小刷新间隔(秒)
qrCodeEncCacheTime = 60       # ENC值缓存时间(秒)

# 参考于kuizuo大佬的项目(目前貌似不维护了)
# https://github.com/kuizuo/chaoxing-sign
class ActivityTypeEnum(Enum):
  Sign = 2        # 签到 (Sign-in)
  Answer = 4      # 抢答 (Quick answer)
  Talk = 5        # 主题谈论 (Topic discussion)
  Question = 6    # 投票 (Poll/Question)
  Pick = 11       # 选人 (Pick someone)
  Homework = 19   # 作业 (Homework)
  Evaluation = 23 # 评分 (Evaluation)
  Practice = 42   # 随堂练习 (Practice)
  Vote = 43       # 投票 (Vote)
  Notice = 45     # 通知 (Notice)

# Enum for activity status
class ActivityStatusEnum(Enum):
  Doing = 1       # In progress
  Done = 2        # Completed

# Enum for sign-in types
class SignTypeEnum(Enum):
  Normal = 0      # 普通签到 (Normal sign-in)
  QRCode = 2      # 二维码签到 (QR code sign-in)
  Gesture = 3     # 手势签到 (Gesture sign-in)
  Location = 4    # 位置签到 (Location sign-in)
  Code = 5        # 签到码签到 (Code sign-in)

# Dictionary mapping sign type numbers to their Chinese descriptions
signTypeMap = {
  0: '普通签到',   # Normal sign-in
  2: '二维码签到', # QR code sign-in
  3: '手势签到',   # Gesture sign-in
  4: '位置签到',   # Location sign-in
  5: '签到码签到'  # Code sign-in
}