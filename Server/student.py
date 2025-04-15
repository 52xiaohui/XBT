import requests
import json
from utils.aes import EncryptXXTByAes
from pyquery import PyQuery as pq
from utils.constants import *
from utils.log import *
from urllib import parse
import time
import pymysql
from bs4 import BeautifulSoup
import urllib.parse
import re

class Student:
  # mobile -> Student 保证一个手机号只有一个实例(避免重复登录)
  students = {}

  @staticmethod
  def preLogin(mobile, password) -> requests.cookies.RequestsCookieJar:
    data = {
      "fid": "-1",
      "uname": EncryptXXTByAes(mobile, transferKey),
      "password": EncryptXXTByAes(password, transferKey),
      "refer": "https://i.chaoxing.com",
      "t": "true",
      "forbidotherlogin": "0",
      "validate": "",
      "doubleFactorLogin": "0",
      "independentId": "0",
      "independentNameId": "0"
    }
    resp = requests.post("https://passport2.chaoxing.com/fanyalogin", params=data, headers=webFormHeaders, verify=False)
    suc = resp.json()['status']
    if not suc:
      raise Exception("登录失败")
    resp2 = requests.get("http://i.chaoxing.com/base", cookies=resp.cookies, headers=webFormHeaders, verify=False)
    name = resp2.text.split('<p class="user-name">')[1].split('</p>')[0]
    avatar = resp2.text.split('<img class="icon-head" src="')[1].split('">')[0]
    return {
      'cookie':resp.cookies,
      'uid': int(resp.cookies.get_dict().get('UID')),
      'name': name,
      'avatar': avatar
    }

  def __new__(cls, *args, **kwargs):
    # 单手机号单例
    mobile = args[0]
    if mobile in Student.students:
      return Student.students[mobile]
    return super().__new__(cls)


  def __init__(self, mobile: str, password: str):
    if hasattr(self, "_inited"): # 避免重复初始化
      return
    self._inited = True
    self.uid = 0
    self.name = ''
    self.avatar = ''
    self.mobile = mobile
    self.password = password
    self.log = Log(self.name)
    self.cookieJar = None
    self.cookieJarUpdatedTime = 0
    self.login()

  def login(self):
    data = Student.preLogin(self.mobile, self.password)
    self.name = data['name']
    self.avatar = data['avatar']
    self.uid = data['uid']
    self.cookieJar = data['cookie']
    self.cookieJarUpdatedTime = time.time()

  def getCookieJar(self) -> requests.cookies.RequestsCookieJar:
    # 每日刷新
    if time.time() - self.cookieJarUpdatedTime > 60 * 60 * 24:
      self.login()
      self.log.i("过期cookie刷新成功")
    return self.cookieJar

  def syncAllCoursesToDatabase(self, cursor):
    courses = self.getAllCourses()
    for course in courses:
      cursor.execute(
      "INSERT INTO CourseInfo (name, teacher, courseId, classId, icon) VALUES (%s, %s, %s, %s, %s)"
      "ON DUPLICATE KEY UPDATE name=VALUES(name), teacher=VALUES(teacher), icon=VALUES(icon)",
      (course['name'], course['teacher'], course['courseId'], course['classId'], course['icon'])
      )
      cursor.execute("INSERT IGNORE INTO UserCourse (uid, courseId, classId, isSelected) VALUES (%s, %s, %s, %s)", (self.uid, course['courseId'], course['classId'], False))

  def getAllCoursesFromDatabase(self, cursor) -> list:
    cursor.execute("SELECT CourseInfo.classId, CourseInfo.courseId, CourseInfo.name, CourseInfo.teacher, CourseInfo.icon, UserCourse.isSelected FROM UserCourse JOIN CourseInfo ON UserCourse.courseId = CourseInfo.courseId AND UserCourse.classId = CourseInfo.classId WHERE UserCourse.uid = %s", (self.uid,))
    return cursor.fetchall()

  def getSelectedCoursesFromDatabase(self, cursor) -> list:
    cursor.execute("SELECT CourseInfo.classId, CourseInfo.courseId, CourseInfo.name, CourseInfo.teacher, CourseInfo.icon, UserCourse.isSelected FROM UserCourse JOIN CourseInfo ON UserCourse.courseId = CourseInfo.courseId AND UserCourse.classId = CourseInfo.classId WHERE UserCourse.uid = %s AND UserCourse.isSelected = 1", (self.uid,))
    return cursor.fetchall()

  def getAllCourses(self) -> list:
    courses = []
    params = {
      "view": "json",
      "getTchClazzType": 1,
      "mcode": ""
    }
    # 发起请求获取课程数据
    resp = requests.get("https://mooc1-api.chaoxing.com/mycourse/backclazzdata", params=params, headers=webFormHeaders, cookies=self.getCookieJar().get_dict(), verify=False).json()
    for channel in resp["channelList"]:
      # 检查是否为有效的课程项
      if 'content' not in channel or not isinstance(channel['content'], dict):
        continue
      # 检查是否为文件夹项
      if 'folderName' in channel['content']:
        continue
      # 检查是否有roletype字段
      if 'roletype' not in channel['content']:
        continue
      # 检查roletype是否为1
      if channel['content']['roletype'] == 1:
        continue
      # 检查是否有course字段和data数组
      if 'course' not in channel['content'] or 'data' not in channel['content']['course']:
        continue

      for c in channel['content']['course']['data']:
        url = parse.urlparse(c['courseSquareUrl'])
        par = parse.parse_qs(url.query)
        courses.append({
          "teacher": c['teacherfactor'],
          "name": c['name'],
          "courseId": par['courseId'][0],
          "classId": par['classId'][0],
          "icon": c['imageurl'],
        })
    # 去重（移到循环外，避免重复操作）
    courses = [dict(t) for t in set([tuple(d.items()) for d in courses])]
    return courses

  def getActivesFromCourse(self, cursor, courses: dict) -> list:
    actives = []
    params = {
      "courseId": courses['courseId'],
      "classId": courses['classId'],
    }
    resp = requests.get("https://mobilelearn.chaoxing.com/ppt/activeAPI/taskactivelist", params=params, headers=mobileHeader, cookies=self.getCookieJar().get_dict(), verify=False).json()
    for active in resp['activeList'][:getActivesLimit]:
      if (active['activeType'] != ActivityTypeEnum.Sign.value): # 目前只支持签到
        continue
      actives.append({
        "name": active['nameOne'],
        "activeId": active['id'],
      })
    return actives

  def getActiveDetail(self, cursor, activeId):
    params = {
      "activePrimaryId": activeId,
      "type": 1
    }
    signRecord = {}
    cursor.execute("SELECT source, signTime FROM SignRecord WHERE activeId = %s AND uid = %s", (activeId, self.uid))
    if cursor.rowcount > 0:
      data = cursor.fetchone()
      source = data['source']
      signTime = data['signTime']
      if source == -1:
        signRecord = {
          "source": 'xxt',
          "sourceName": "学习通",
          "signTime": signTime,
        }
      else:
        cursor.execute("SELECT name FROM UserInfo WHERE uid = %s", (source))
        signRecord = {
          "source": 'self' if source == self.uid else 'agent' ,
          "sourceName": cursor.fetchone()['name'],
          "signTime": signTime,
        }
    else:
      signRecord = {
        "source": 'none',
        "sourceName": "未签到",
        "signTime": -1,
      }
    # 这里为高频请求，先从数据库查有没有缓存
    cursor.execute("SELECT activeId, startTime, endTime, signType, ifRefreshEwm FROM SignInfo WHERE activeId = %s", (activeId))
    if cursor.rowcount > 0:
      data = cursor.fetchone()
      # 判断是否手动结束
      if data['endTime'] != 64060559999000 :
        detail = {
          "startTime": data['startTime'],
          "endTime": data['endTime'],
          "signType": data['signType'],
          "ifRefreshEwm": bool(data['ifRefreshEwm']),
          "signRecord": signRecord,
        }
        return detail # 非处于等待手动结束的签到 返回缓存数据
    resp = requests.get("https://mobilelearn.chaoxing.com/newsign/signDetail", params=params, headers=mobileHeader, cookies=self.getCookieJar().get_dict(), verify=False).json()
    # 判断结束时间是否为手动结束
    if resp['endTime'] == None :
      endTime = 64060559999000
    else:
      endTime = int(resp['endTime']['time'])
    detail = {
      "startTime": int(resp['startTime']['time']),
      "endTime": endTime,
      "signType": int(resp['otherId']),
      "ifRefreshEwm": bool(resp['ifRefreshEwm']),
      "signRecord": signRecord,
    }
    cursor.execute("INSERT IGNORE INTO SignInfo (activeId, startTime, endTime, signType, ifRefreshEwm) VALUES (%s, %s, %s, %s, %s)", (activeId, detail['startTime'], detail['endTime'], detail['signType'], detail['ifRefreshEwm']))
    return detail

  def getClassmates(self, cursor, classId, courseId):
    cursor.execute("SELECT uid, name, mobile, avatar FROM UserInfo WHERE uid in (SELECT uid FROM UserCourse WHERE courseId = %s AND classId = %s AND uid != %s AND isSelected = 1)", (courseId, classId, self.uid))
    return cursor.fetchall()


  def setCourseSelectState(self, cursor, courses: list):
    for course in courses:
      cursor.execute("UPDATE UserCourse SET isSelected = %s WHERE uid = %s AND courseId = %s AND classId = %s", (course['isSelected'], self.uid, course['courseId'], course['classId']))


  # 参考于kuizuo大佬的项目(目前貌似不维护了)
  # https://github.com/kuizuo/chaoxing-sign
  # 预签到方法添加更多调试信息
  def preSign(self, fixedParams: dict, code=None, enc=None):
    # 记录预签到参数
    self.log.i(f"开始预签到: activeId={fixedParams.get('activeId')}, uid={fixedParams.get('uid')}, enc={enc[:8] + '...' if enc else 'None'}")

    # First request (equivalent to preSign GET request)
    params = {
      'courseId': fixedParams.get('courseId', ''),
      'classId': fixedParams.get('classId'),
      'activePrimaryId': fixedParams.get('activeId'),
      'general': '1',
      'sys': '1',
      'ls': '1',
      'appType': '15',
      'uid': fixedParams.get('uid'),  # Assuming uid comes from user object in activity
      'isTeacherViewOpen': 0
    }

    # Add rcode if ifRefreshEwm is True
    if fixedParams.get('ifRefreshEwm'):
        rcode = f"SIGNIN:aid={fixedParams.get('activeId')}&source=15&Code={code}&enc={enc}"
        params['rcode'] = urllib.parse.quote(rcode)

    response = requests.get('https://mobilelearn.chaoxing.com/newsign/preSign',
                          params=params, cookies=self.getCookieJar().get_dict(), headers=mobileHeader)
    html = response.text


    # Sleep for 500ms
    # time.sleep(0.5)

    # Second request (analysis)
    analysis_params = {
        'vs': 1,
        'DB_STRATEGY': 'RANDOM',
        'aid': fixedParams.get('activeId')
    }
    analysis_response = requests.get('https://mobilelearn.chaoxing.com/pptSign/analysis', params=analysis_params, cookies=self.getCookieJar().get_dict(), headers=mobileHeader)
    data = analysis_response.text

    # Extract code using regex
    code_match = re.search(r"code='\+'(.*?)'", data)
    code = code_match.group(1) if code_match else None
    # Third request (analysis2)
    analysis2_params = {
        'DB_STRATEGY': 'RANDOM',
        'code': code
    }
    requests.get('https://mobilelearn.chaoxing.com/pptSign/analysis2', params=analysis2_params, cookies=self.getCookieJar().get_dict(), headers=mobileHeader)
    # time.sleep(0.2)
    soup = BeautifulSoup(html, 'html.parser')
    status = soup.select_one('#statuscontent')
    status_text = ''
    if (status):
        status_text = re.sub(r'[\n\s]', '', status.get_text().strip())
    self.log.i("预签到状态: "+ status_text)
    if status_text:
        return status_text

  def sign(self, signType, fixedParams, specialParams):
    params = {}
    if signType == SignTypeEnum.Normal.value:
      params = self.signNormal(fixedParams, specialParams)
    elif signType == SignTypeEnum.QRCode.value:
      params = self.signQRCode(fixedParams, specialParams)
    elif signType == SignTypeEnum.Gesture.value:
      params = self.signGesture(fixedParams, specialParams)
    elif signType == SignTypeEnum.Location.value:
      params = self.signLocation(fixedParams, specialParams)
    elif signType == SignTypeEnum.Code.value:
      params = self.signCode(fixedParams, specialParams)

    # 发送签到请求前记录完整请求信息以便调试
    if signType == SignTypeEnum.QRCode.value:
      self.log.i(f"发送二维码签到请求: activeId={fixedParams.get('activeId')}, enc={params.get('enc')[:8]}...")

    resp = requests.get('https://mobilelearn.chaoxing.com/pptSign/stuSignajax', params=params, cookies=self.getCookieJar().get_dict(), headers=mobileHeader)
    result = resp.text

    # 记录签到结果
    self.log.i(f"签到结果: {result}")

    # 处理需要验证码的情况
    if "validate" in result:
      self.log.i(f"签到需要验证码，尝试获取验证码并重新签到")
      return self.handle_captcha_sign(params, fixedParams, specialParams)

    return result

  def signNormal(self, fixedParams, specialParams):
    params = {
      'activeId': fixedParams['activeId'],
      'uid': fixedParams['uid'],
      'clientip': '',
      'latitude': '-1',
      'longitude': '-1',
      'appType': '15',
      'fid': '',
      'name': self.name,
    }
    return params

  def signQRCode(self, fixedParams, specialParams):
    # 检查必要参数
    if 'enc' not in specialParams or not specialParams['enc']:
      self.log.i("二维码签到缺少必要参数enc")
      raise Exception("缺少必要的签到参数")

    params = {
        'enc': specialParams['enc'],
        'name': self.name,
        'activeId': fixedParams['activeId'],
        'uid': fixedParams['uid'],
        'clientip': '',
        'useragent': '',
        'latitude': '-1',
        'longitude': '-1',
        'fid': '',
        'appType': '15',
    }

    # 如果提供了location参数，添加到请求参数中
    if 'location' in specialParams:
        params['location'] = json.dumps(specialParams['location'], ensure_ascii=False)

    # 如果提供了验证码参数，添加到请求参数中
    if 'validate' in specialParams and specialParams['validate']:
        params['validate'] = specialParams['validate']
        self.log.i(f"二维码签到使用验证码: {specialParams['validate']}")

    # 记录当前使用的enc值用于调试
    self.log.i(f"二维码签到使用ENC值: {specialParams['enc'][:8]}..., uid: {fixedParams['uid']}")

    return params

  def signGesture(self, fixedParams, specialParams):
    resp = requests.get('https://mobilelearn.chaoxing.com/widget/sign/pcStuSignController/checkSignCode',
                                    params={"activeId": fixedParams['activeId'], "signCode": specialParams['signCode']}, cookies=self.getCookieJar().get_dict(), headers=mobileHeader).json()
    if (resp['result'] != 1):
      raise Exception(resp['errorMsg'])
    params = {
      'activeId': fixedParams['activeId'],
      'uid': fixedParams['uid'],
      'clientip': '',
      'latitude': '',
      'longitude': '',
      'appType': '15',
      'fid': '',
      'name': self.name,
      'signCode': specialParams['signCode'],
    }
    return params

  def signLocation(self, fixedParams, specialParams):
    params = {
      'activeId': fixedParams['activeId'],
      'address': specialParams['description'],
      'uid': fixedParams['uid'],
      'clientip': '',
      'latitude': specialParams['latitude'],
      'longitude': specialParams['longitude'],
      'appType': '15',
      'fid': '',
      'name': self.name,
      'ifTiJiao': 1,
      'validate': '',
    }
    return params

  def signCode(self, fixedParams, specialParams):
    params = {
      'activeId': fixedParams['activeId'],
      'uid': fixedParams['uid'],
      'clientip': '',
      'latitude': '',
      'longitude': '',
      'appType': '15',
      'fid': '',
      'name': self.name,
      'signCode': specialParams['signCode'],
    }
    return params

  def signPicture(self, fixedParams, specialParams):
    pass
#这里参考了：https://github.com/maybefw/XXT-sign
  def handle_captcha_sign(self, params, fixedParams, specialParams):
    """
    处理需要验证码的签到
    :param params: 原始签到参数
    :param fixedParams: 固定参数
    :param specialParams: 特殊参数
    :return: 签到结果
    """
    
    try:
      self.log.i("开始处理验证码签到")

      # 导入必要模块
      import uuid
      import hashlib
      import sys
      import os
      import urllib.parse
      from calculate_distance import calculate_distance

      # 最多尝试3次获取验证码
      for attempt in range(3):
        try:
          self.log.i(f"第{attempt+1}次尝试获取验证码")

          # 生成UUID和相关参数
          uuid_val = str(uuid.uuid4())
          current_time = int(time.time() * 1000)

          # 获取验证码配置
          conf_params = {
            'callback': 'cx_captcha_function',
            'captchaId': 'Qt9FIw9o4pwRjOyqM6yizZBh682qN2TU',
            '_': current_time
          }

          # 构建必要的headers
          conf_headers = {
            'Accept': '*/*',
            'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,eo;q=0.7,ar;q=0.6',
            'Connection': 'keep-alive',
            'Cookie': '; '.join([f'{k}={v}' for k, v in self.getCookieJar().get_dict().items()]),
            'DNT': '1',
            'Referer': 'https://mobilelearn.chaoxing.com/page/sign/signIn',
            'Sec-Fetch-Dest': 'script',
            'Sec-Fetch-Mode': 'no-cors',
            'Sec-Fetch-Site': 'same-site',
            'User-Agent': 'Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36'
          }

          conf_response = requests.get(
            "https://captcha.chaoxing.com/captcha/get/conf",
            params=conf_params,
            headers=conf_headers
          )

          # 解析JSONP响应中的服务器时间
          import re
          jsonp_match = re.search(r'cx_captcha_function\((.*)\)', conf_response.text)
          if not jsonp_match:
            self.log.i(f"响应内容: {conf_response.text}")
            raise Exception("无法解析JSONP响应")

          json_data = json.loads(jsonp_match.group(1))
          server_time = str(json_data.get('t'))

          if not server_time:
            self.log.i(f"解析的JSON数据: {json_data}")
            raise Exception("无法从JSON中提取serverTime")

          # 生成验证码所需参数
          import hashlib
          captcha_key = hashlib.md5(f"{uuid_val}{server_time}".encode()).hexdigest()
          token_part1 = hashlib.md5(f"{server_time}Qt9FIw9o4pwRjOyqM6yizZBh682qN2TUslide{captcha_key}".encode()).hexdigest()
          token_part2 = str(int(server_time) + 0x493e0)
          token = f"{token_part1}:{token_part2}"

          iv = hashlib.md5(f"Qt9FIw9o4pwRjOyqM6yizZBh682qN2TUslide{current_time}{uuid_val}".encode()).hexdigest()

          # 获取验证码图片
          captcha_params = {
            'callback': 'cx_captcha_function',
            'captchaId': 'Qt9FIw9o4pwRjOyqM6yizZBh682qN2TU',
            'type': 'slide',
            'version': '1.1.20',
            'captchaKey': captcha_key,
            'token': token,
            'referer': 'https://mobilelearn.chaoxing.com/page/sign/signIn',
            'iv': iv,
            '_': current_time
          }

          # 使用相同的headers获取验证码图片
          captcha_response = requests.get(
            "https://captcha.chaoxing.com/captcha/get/verification/image",
            params=captcha_params,
            headers=conf_headers
          )

          # 解析JSONP响应
          jsonp_match = re.search(r'cx_captcha_function\((.*)\)', captcha_response.text)
          if not jsonp_match:
            self.log.i(f"验证码响应内容: {captcha_response.text}")
            raise Exception("无法解析验证码JSONP响应")

          parsed_response = json.loads(jsonp_match.group(1))
          self.log.i(f"解析的验证码数据: {parsed_response}")

          # 获取图片URL
          big_image_url = parsed_response['imageVerificationVo']['shadeImage']
          small_image_url = parsed_response['imageVerificationVo']['cutoutImage']
          validate_token = parsed_response['token']

          # 下载图片
          big_image_path = "bigImage.jpg"
          small_image_path = "smallImage.jpg"

          # 下载背景图片
          self.log.i(f"开始下载背景图片: {big_image_url}")
          big_image_response = requests.get(big_image_url, headers=conf_headers, stream=True)
          if big_image_response.status_code != 200:
            self.log.i(f"下载背景图片失败: 状态码 {big_image_response.status_code}")
            raise Exception(f"下载背景图片失败: 状态码 {big_image_response.status_code}")

          with open(big_image_path, 'wb') as f:
            for chunk in big_image_response.iter_content(chunk_size=8192):
              if chunk:
                f.write(chunk)

          # 检查背景图片是否下载成功
          if not os.path.exists(big_image_path) or os.path.getsize(big_image_path) == 0:
            self.log.i(f"背景图片下载失败或文件大小为0")
            raise Exception("背景图片下载失败或文件大小为0")

          # 下载滑块图片
          self.log.i(f"开始下载滑块图片: {small_image_url}")
          small_image_response = requests.get(small_image_url, headers=conf_headers, stream=True)
          if small_image_response.status_code != 200:
            self.log.i(f"下载滑块图片失败: 状态码 {small_image_response.status_code}")
            raise Exception(f"下载滑块图片失败: 状态码 {small_image_response.status_code}")

          with open(small_image_path, 'wb') as f:
            for chunk in small_image_response.iter_content(chunk_size=8192):
              if chunk:
                f.write(chunk)

          # 检查滑块图片是否下载成功
          if not os.path.exists(small_image_path) or os.path.getsize(small_image_path) == 0:
            self.log.i(f"滑块图片下载失败或文件大小为0")
            raise Exception("滑块图片下载失败或文件大小为0")

          # 计算滑块距离
          distance = calculate_distance(big_image_path, small_image_path)
          self.log.i(f"计算的滑块距离: {distance}")

          # 验证滑块
          verify_params = {
            'callback': 'cx_captcha_function',
            'captchaId': 'Qt9FIw9o4pwRjOyqM6yizZBh682qN2TU',
            'type': 'slide',
            'token': validate_token,
            'textClickArr': json.dumps([{"x": round(distance)}]),
            'coordinate': '[]',
            'runEnv': '10',
            'version': '1.1.20',
            't': 'a',
            'iv': iv,
            '_': str(int(time.time() * 1000))
          }

          # 使用相同的headers进行验证
          verify_headers = conf_headers.copy()

          verify_url = f"https://captcha.chaoxing.com/captcha/check/verification/result?{urllib.parse.urlencode(verify_params)}"
          verify_response = requests.get(verify_url, headers=verify_headers)

          # 解析验证结果
          verify_match = re.search(r'cx_captcha_function\((.*)\)', verify_response.text)
          if not verify_match:
            self.log.i(f"验证结果响应内容: {verify_response.text}")
            raise Exception("无法解析验证结果")

          verify_result = json.loads(verify_match.group(1))
          self.log.i(f"解析的验证结果: {verify_result}")

          # 检查验证结果
          if verify_result.get('error') == 1:
            self.log.i(f"验证失败: {verify_result.get('msg')}")
            continue

          # 获取validate值
          validate = None
          if verify_result.get('extraData'):
            try:
              extra_data = json.loads(verify_result['extraData'])
              self.log.i(f"解析的extraData: {extra_data}")
              validate = extra_data.get('validate')

              if validate:
                self.log.i(f"成功获取验证码: {validate}")
              else:
                self.log.i(f"extraData中没有validate字段")
            except json.JSONDecodeError as e:
              self.log.i(f"extraData解析失败: {e}, 原始数据: {verify_result['extraData']}")
              # 尝试直接使用extraData作为valiate
              validate = verify_result['extraData']

          if validate:
            # 使用验证码重新签到
            params['validate'] = validate
            resp = requests.get(
                'https://mobilelearn.chaoxing.com/pptSign/stuSignajax',
                params=params,
                cookies=self.getCookieJar().get_dict(),
                headers=mobileHeader
            )

            result = resp.text
            self.log.i(f"使用验证码签到结果: {result}")
            return result

        except Exception as e:
          self.log.i(f"获取验证码失败: {str(e)}")
          if attempt < 2:  # 如果不是最后一次尝试，等待1秒后重试
            time.sleep(1)

      # 所有尝试都失败
      self.log.i("多次尝试后仍未能获取有效验证码")
      return "签到失败：无法获取有效验证码"

    except Exception as e:
      self.log.i(f"处理验证码签到异常: {str(e)}")
      return f"签到失败：{str(e)}"

  def getSignStateFromDataBase(self, cursor, activeId, classmates):
    classmates = [self.uid] + classmates
    result = {}
    for uid in classmates:
      cursor.execute("SELECT source FROM SignRecord WHERE activeId = %s AND uid = %s" % (activeId, uid))
      if cursor.rowcount == 0:
        result[uid] = {
          'suc': False,
          'comment': ""
        }
        continue
      source = cursor.fetchone()['source']
      comment = ""
      if source == -1:
        comment = '学习通'
      elif source == uid:
        comment = '本人签到'
      else:
        cursor.execute("SELECT name FROM UserInfo WHERE uid = %s", (source,))
        comment = cursor.fetchone()['name'] + "代签"
      result[uid] = {
        'suc': True,
        'comment': comment
      }
    return result
