from flask import request
from flask import jsonify, Response
from utils.aes import *
from utils.constants import *
import time
import utils.log
import pymysql
from student import Student

VERSION = '1.1.2'

log = utils.log.Log('Flask')

IGNORE_TOKEN_URL = set({'/login'})
IGNORE_BEFORE_REQUEST = set({'/imageProxy'})
 
def after_request(resp: Response):
  if (resp.json is not None):    
    if (resp.json['suc']):
      log.s(f"{resp.json}")
    else:
      log.w(f"{resp.json}")
  return resp
 
def before_request():
  if any([request.path.startswith(url) for url in IGNORE_BEFORE_REQUEST]):
    return
  conn = POOL.connection()
  cursor = conn.cursor(pymysql.cursors.DictCursor)
  version = request.headers.get('version')
  if not version or version != VERSION:
    return {'suc': False, 'msg': f'客户端版本过低, 请更新v{VERSION}'}
  if not any([request.path.startswith(url) for url in IGNORE_TOKEN_URL]):
    token = request.headers.get('token')
    if not token or token == '':
      return {'suc': False, 'msg': 'Token is required'}, 403
    data = decodeToken(token)
    cursor.execute("select uid, name, token from UserInfo where mobile=%s", (data['mobile']))
    if cursor.rowcount == 0:
      return {'suc': False, 'msg': 'user error'}, 403
    dbToken = cursor.fetchone()['token']
    dbData = decodeToken(dbToken)
    if dbData['password'] != data['password']:
      return {'suc': False, 'msg': 'password error'}, 403
    student = Student(data['mobile'], data['password'])
    request.json['student'] = student
  request.json['cursor'] = cursor
  request.json['conn'] = conn
