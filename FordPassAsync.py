#!/usr/bin/env python3

'''
Asyncio library for communicating with FordPass enabled vehicles
Based on https://github.com/clarkd/fordpass-python by Clark D
1/4/2022 V 1.0.0 N Waterton - Initial Release
5/7/2022 V 2.0.0 N Waterton - New Authentication scheme
'''

import logging
from logging.handlers import RotatingFileHandler
import time, sys, json, argparse, socket, hashlib, re, random, string, datetime
from base64 import urlsafe_b64encode, urlsafe_b64decode
import asyncio
import aiohttp

from mqtt import MQTT

__version__ = __VERSION__ = '2.0.0'

class Vehicle(MQTT):
    '''
    Represents a Ford vehicle, with methods for status and issuing commands
    all methods not starting with '_' can be sent as commands to MQTT topic
    '''
    __version__ = __version__
    regions = { "US": "71A3AD0A-CF46-4CCF-B473-FC7FE5BC4592", # United States
                "CA": "71A3AD0A-CF46-4CCF-B473-FC7FE5BC4592", # Canada
                "EU": "1E8C7794-FF5F-49BC-9596-A1E0C86C5B19", # Europe
                "AU": "5C80A6BB-CF0D-4A30-BDBF-FC804B5C1A98", # Australia
              }

    defaultHeaders = {  'Accept': '*/*',
                        'Accept-Language': 'en-us',
                        'User-Agent': 'FordPass/5 CFNetwork/1327.0.4 Darwin/21.2.0',
                        'Accept-Encoding': 'gzip, deflate, br',
                     }
                     
    client_id = "9fb503e0-715b-47e8-adfd-ad4b7770f73b"

    API_URL = 'https://usapi.cv.ford.com/api'  # US Connected Vehicle api
    VEHICLE_URL = 'https://services.cx.ford.com/api'
    USER_URL = 'https://api.mps.ford.com/api'
    #TOKEN_URL = 'https://sso.ci.ford.com/oidc/endpoint/default/token'
    SSO_URL = 'https://sso.ci.ford.com'

    def __init__(self, username, fordpassword, vin='', region='CA', log=None, **kwargs):
        super().__init__(log=log, **kwargs)
        self.log = log
        if self.log is None:
            self.log = logging.getLogger('Main.'+__class__.__name__)
        self.username = username
        self.fordpassword = fordpassword
        self.vin = vin
        self.region = region
        self.log.info(f'FordPass v{self.__version__}')
        self.token_location = './tokens.json'
        self.apiHeaders = { **self.defaultHeaders,
                            'Application-Id': self.regions[region],  
                            'Content-Type': 'application/json',
                          }
        self.formHeaders = { **self.defaultHeaders,
                             'Content-Type': 'application/x-www-form-urlencoded',
                           }
        self.country = 'USA'    # placeholders, gets updated when tokens are obtained
        self.uom_speed = 'MPH'
        self.uom_distance = 'Mi'
        self.uom_pressure = 'KPa'
        self.session = None
        self.token = None
        self.refresh_token = None
        self.expiresAt = None
        self.refresh_expires_at = None
        self.readToken()
        self.cache = {}
        self.cache_timeout = 5  #5 second timeout on cache, set to 0 to disable cache
        self.loop = asyncio.get_event_loop()
        #self.lock = asyncio.Lock()
        
    def stop(self):
        try:
            self.loop.run_until_complete(self._stop())
        except RuntimeError:
            self.loop.create_task(self._stop())
        
    async def _stop(self):
        '''
        put shutdown routines here
        '''
        await super()._stop()
        
    def _publish(self, topic=None, message=None):
        super()._publish(topic, message)
        
    async def _publish_command(self, command, args=None):
        await super()._publish_command(command, args)
        
    async def _request(self, method, url, api='', **kwargs):
        '''
        V 2.0 with redirect capture for new authentication (V2.0) method
        '''
        try :
            if not kwargs.pop('get_token', False):
                await self.__acquireToken()
                
            get_text = kwargs.pop('get_text', False)
            count = kwargs.pop('count', 0)
                
            if  count > 2:
                self.log.warning('Too many retries')
                return False
                
            if 'headers' not in kwargs:
                if self.token is None:
                    raise asyncio.exceptions.TimeoutError('No Access token')
                    
                kwargs['headers'] = {   **self.apiHeaders,
                                        'auth-token': self.token
                                    }
                                    
            self.log.info(f'{method.upper()} {url}{api}')
            if not self.session:
                self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5.0))
            async with self.session.request(method.upper(), f'{url}{api}', **kwargs) as response:
                self.log.debug('Response status: {}'.format(response.status))
                if response.status == 200:
                    if get_text:
                        return await response.text()
                    else:
                        return await response.json()
                elif response.status == 302:
                    #V2.0 authentication redirects URL's
                    self.log.debug('Redirect url: {}'.format(response.headers["Location"]))
                    return response.headers["Location"]
                elif response.status == 401:
                    self.log.warning('Permission denied, reauthenticating...')
                    await self.__refresh_token()
                    kwargs.pop('headers', None)
                    return await self._request(method, url, api, count=count + 1, **kwargs)
                else:
                    self.log.error(f'Error calling: {url}{api} status: {response.status} {await response.text()}')
        except asyncio.exceptions.TimeoutError as e:
            self.log.warning('Request Timeout: {}'.format(e))
            return {}
        except Exception as e:
            self.log.exception(e)     
        return {}

    def _set_tokens(self, result, save=True):
        self.log.debug('set tokens: {}'.format(result))
        if result.get('access_token'):
            self.token = result['access_token']
            self.refresh_token = result.get('refresh_token', self.refresh_token)
            self.expiresAt = time.time() + result.get('expires_in', 0)                  #timestamp
            self.refresh_expires_at = time.time() + result.get('refresh_expires_in', 0) #timestamp
            self.country = result.get('country', self.country)
            self.uom_speed = result.get('uomSpeed', self.uom_speed)             #MPH, KPH
            self.uom_distance = result.get('uomDistance', self.uom_distance)    #1= mi, 2 = km
            self.uom_pressure = result.get('uomPressure', self.uom_pressure)    #KPa, PSI
            if save:
                self.writeToken(result)
            return True
        return False
        
    def writeToken(self, tokens):
        # Save tokens to file to be reused
        with open(self.token_location, "w") as outfile:
            tokens["user_expiry_timestamp"] = self.expiresAt
            tokens["refresh_expiry_timestamp"] = self.refresh_expires_at
            json.dump(tokens, outfile)

    def readToken(self):
        # Get saved token from file
        try:
            self.log.debug('reading tokens from {}'.format(self.token_location))
            with open(self.token_location) as token_file:
                tokens = json.load(token_file)
                self._set_tokens(tokens, False)
                self.expiresAt = tokens.get("user_expiry_timestamp", self.expiresAt)
                self.refresh_expires_at = tokens.get("refresh_expiry_timestamp", self.refresh_expires_at)
                self.log.info('tokens loaded')
        except Exception as e:
            self.log.warning("cannot load tokens: {}\nWill refresh using credentials".format(e))
        
    def secondsToText(self, secs):
        if secs <=60:
            return '{}s'.format(secs)
        return str(datetime.timedelta(seconds = secs))
        
    def base64UrlEncode(self,data):
        return urlsafe_b64encode(data).rstrip(b'=')

    def generate_hash(self, code):
        m = hashlib.sha256()
        m.update(code.encode('utf-8'))
        return self.base64UrlEncode(m.digest()).decode('utf-8')    
        
    async def _auth(self):
        '''
        New Authentication Method (V2.0)
        Obtain User token and refresh token
        user token good for 30 minutes, refresh token good for 1 year
        '''
        self.log.debug("New Authentication System V2.0")
        
        # Auth Step1 (get login url)
        code1 = ''.join(random.choice(string.ascii_lowercase) for i in range(43))
        code_verifier = self.generate_hash(code1)
        result = await self._request('get', self.SSO_URL, api=f'/v1.0/endpoint/default/authorize?redirect_uri=fordapp://userauthorized&response_type=code&scope=openid&max_age=3600&client_id={self.client_id}&code_challenge={code_verifier}&code_challenge_method=S256', headers=self.apiHeaders, get_token=True, get_text=True)
        if not result:
            raise Exception('No login URL')
        login_url = re.findall('data-ibm-login-url="(.*)"\s', result)[0]

        # Auth Step2 (log in and get redirect url)
        self.log.debug('logging in with URL: {}{}'.format(self.SSO_URL,login_url))
        data = {
            "operation": "verify",
            "login-form-type": "password",
            "username" : self.username,
            "password" : self.fordpassword

        }
        result = await self._request('post', self.SSO_URL, api=login_url, data=data, headers=self.formHeaders, get_token=True, get_text=True, allow_redirects=False)
        self.log.debug('got result (2): {}'.format(result))
        if not result:
            raise Exception('No redirect URL')
        nextUrl = result

        # Auth Step3 (get grant_id and code)
        result = await self._request('get', nextUrl, headers=self.apiHeaders, get_token=True, allow_redirects=False)
        self.log.debug('got result (3): {}'.format(result))
        if not result:
            raise Exception('No redirect Parameters')

        query = result.split('?')
        params = dict(x.split('=') for x in query[1].split('&'))
        self.log.debug('Params: {}'.format(params))

        # Auth Step4 (get ciToken)
        data = {
            "client_id": self.client_id,
            "grant_type": "authorization_code",
            "redirect_uri": query[0],
            "grant_id": params["grant_id"],
            "code": params["code"],
            "code_verifier": code1
            }
            
        result = await self._request('post', self.SSO_URL, api='/oidc/endpoint/default/token', data=data, headers=self.formHeaders, get_token=True)
        if not result.get("access_token"):
            raise Exception("Could Not Obtain new ciToken")

        # Auth Step5 (exchange ciToken for user token and refresh token)
        data = {"ciToken": result["access_token"]}
        result = await self._request('post', self.USER_URL, '/token/v2/cat-with-ci-access-token', headers=self.apiHeaders, json=data, get_token=True)
        return self._set_tokens(result)

    async def _auth_old(self):       
        '''
        Old (V1.0) authentication method
        Authenticate and store the user token
        '''

        data = {    'client_id': self.client_id,
                    'grant_type': 'password',
                    'username': self.username,
                    'password': self.fordpassword
               }

        result = await self._request('post', self.SSO_URL, api='/oidc/endpoint/default/token', data=data, headers=self.formHeaders, get_token=True)
        if self._set_tokens(result):
            return await self._get_user_token()
        return False
            
    async def __refresh_token(self):
        '''
        Exchange a refresh token for a new access dictionary
        '''
        if self.refresh_token is None or time.time() >= self.refresh_expires_at:
            self.log.info('No Refresh Token, or has expired, requesting new Refresh token')
            return await self._auth()
            
        self.log.info('Using Refresh Token, expires in: {}'.format(self.secondsToText(int(self.refresh_expires_at - time.time()))))

        data = {'refresh_token': self.refresh_token}
        
        #New (V2.0) method
        result = await self._request('post', self.USER_URL, '/token/v2/cat-with-refresh-token', headers=self.apiHeaders, json=data, get_token=True)

        #old version (V1.0)
        #result = await self._request('put', self.USER_URL, '/oauth2/v1/refresh', headers=self.apiHeaders, json=data, get_token=True)
        if not result:
            return await self._auth()
        return self._set_tokens(result)
    
    async def __acquireToken(self):
        '''
        Fetch and refresh token as needed
        '''
        if self.token is None or time.time() >= self.expiresAt:
            self.log.info('No User Token, or has expired, requesting new User Token')
            await self.__refresh_token()
        else:
            self.log.info('User Token is valid, expires in: {}, continuing'.format(self.secondsToText(int(self.expiresAt - time.time()))))
            
    async def _get_user_token(self):
        '''
        Old (V1.0) Authentication method
        Exchanges basic token for oauth token
        '''
        if not self.token:
            await self.__acquireToken()

        data = {'code': self.token}
        
        result = await self._request('put', self.USER_URL, '/oauth2/v1/token', headers=self.apiHeaders, json=data)
        return self._set_tokens(result)
        
    def _cache(self, key, value, cache=False):
        '''
        caches value in key for later retrieval, timeout of cach is set by self.cache_timeout
        '''
        if cache and key and self.cache_timeout > 0:
            self.cache[key] = value
            self.loop.call_later(self.cache_timeout, self.cache.pop, key, None)
        return value
        
    def _get_cache(self, key):
        '''
        returns cached value if it exists, else {}
        '''
        return self.cache.get(key, {})
        
    def clear_cache(self):
        self.cache = {}
        
    async def _get_status_values(self, values):
        '''
        returns dictionary of values with key values from vehicle status.
        values should be a list, if not it is converted to a list first
        '''
        values = values if isinstance(values, list) else [values]
        json = await self.get_status()
        return {k:json.get(k) for k in values if k in json.keys()}
        
    async def get_car_info(self):
        '''
        GET Vehicle.info
        [{'nickName': 'Nick’s Car ', 'vin': '1FMCUYYY2NUAXXXX', 'vehicleType': '2022 Escape', 'color': 'ICED/ELITE BLUE', 'modelName': 'Escape', 'modelCode': 'VLTC', 'modelYear': '2022', 'tcuEnabled': 1, 'localMarketValue': 'Escape', 'territoryDescription': 'CANADA', 'vehicleAuthorizationStatus': {'requestStatus': 'CURRENT', 'error': None, 'lastRequested': '2022-04-05T12:50:57.120Z', 'value': {'authorization': 'AUTHORIZED'}}, 'recallInfo': None}]
        '''
        params = {  'language': 'EN',
                    'wakeupVin' : self.vin,
                    'skipRecall' : 'true',
                    'country' : self.country,
                    'region' : self.region}

        cars = await self._request('get', self.USER_URL, '/dashboard/v1/users/vehicles', params=params)
        return cars[0] if cars else {}
        
    async def refresh_status(self):
        '''
        PUT Vehicle.refresh_status
        Send request to refresh data from the cars module - this uses some car battery power, so don't call too often
        response : {'$id': '1', 'commandId': '7c0ab482-6309-42d4-a49e-6a479cc1e5f7', 'status': 200, 'version': '1.0.0'}
        result['status']:
        552: Command is pending
        200: Complete
        '''
        self.log.info('Refreshing Status...')
        result = await self._request('put', self.API_URL, f'/vehicles/v2/{self.vin}/status')
        self.log.info(result)
        if result.get('status', 0) == 200:
            await self._publish_command('get_status')
            return True
        return False
    
    async def get_status(self):
        '''
        Send request for Current vehicle status from server (not car)
        '''
        result = self._get_cache('vehiclestatus')   #return cached value if it exists
        if result:
            return result

        params = {'lrdt': '01-01-1970 00:00:00'}

        result = await self._request('get', self.API_URL, f'/vehicles/v4/{self.vin}/status', params=params)
        
        if result.get('status', 0) == 200:
            # cache results and return
            return self._cache('vehiclestatus', result.get('vehiclestatus', {}), True)
        return {}
        
    async def get_vin(self):
        '''
        GET Vehicle.vin
        {'vin': '1FMCUYYY2NUAXXXX'}
        '''
        return await self._get_status_values('vin')

    async def odometer(self):
        '''
        GET Vehicle.odometer
        {'odometer': {'value': 163.0, 'status': 'CURRENT', 'timestamp': '04-04-2022 18:16:05'}}
        '''
        return await self._get_status_values('odometer')

    async def fuel(self):
        '''
        GET Vehicle.fuel
        {'data': {'fuelLevel': 73.695888, 'distanceToEmpty': 413.3, 'status': 'LAST_KNOWN', 'timestamp': '04-04-2022 12:15:58'}}
        '''
        return await self._get_status_values('fuel')

    async def oil(self):
        '''
        GET Vehicle.oil
        {'oil': {'oilLife': 'STATUS_GOOD', 'oilLifeActual': 100, 'status': 'CURRENT', 'timestamp': '04-04-2022 18:16:05'}}
        '''
        return await self._get_status_values('oil')

    async def tire_pressure(self):
        '''
        GET Vehicle.tire_pressure
        {'TPMS': {'tirePressureByLocation': {'value': 1, 'status': 'CURRENT', 'timestamp': '04-04-2022 18:16:05'}, 'tirePressureSystemStatus': {'value': 'Systm_Activ_Composite_Stat', 'status': 'CURRENT', 'timestamp': '04-04-2022 18:16:05'}, 'dualRearWheel': {'value': 0, 'status': 'CURRENT', 'timestamp': '04-04-2022 18:16:05'}, 'leftFrontTireStatus': {'value': 'Normal', 'status': 'CURRENT', 'timestamp': '04-04-2022 18:16:05'}, 'leftFrontTirePressure': {'value': '241', 'status': 'CURRENT', 'timestamp': '04-04-2022 18:16:05'}, 'rightFrontTireStatus': {'value': 'Normal', 'status': 'CURRENT', 'timestamp': '04-04-2022 18:16:05'}, 'rightFrontTirePressure': {'value': '239', 'status': 'CURRENT', 'timestamp': '04-04-2022 18:16:05'}, 'outerLeftRearTireStatus': {'value': 'Normal', 'status': 'CURRENT', 'timestamp': '04-04-2022 18:16:05'}, 'outerLeftRearTirePressure': {'value': '239', 'status': 'CURRENT', 'timestamp': '04-04-2022 18:16:05'}, 'outerRightRearTireStatus': {'value': 'Normal', 'status': 'CURRENT', 'timestamp': '04-04-2022 18:16:05'}, 'outerRightRearTirePressure': {'value': '224', 'status': 'CURRENT', 'timestamp': '04-04-2022 18:16:05'}, 'innerLeftRearTireStatus': {'value': 'Not_Supported', 'status': 'CURRENT', 'timestamp': '04-04-2022 18:16:05'}, 'innerLeftRearTirePressure': None, 'innerRightRearTireStatus': {'value': 'Not_Supported', 'status': 'CURRENT', 'timestamp': '04-04-2022 18:16:05'}, 'innerRightRearTirePressure': None, 'recommendedFrontTirePressure': {'value': 33, 'status': 'CURRENT', 'timestamp': '04-04-2022 18:16:05'}, 'recommendedRearTirePressure': {'value': 33, 'status': 'CURRENT', 'timestamp': '04-04-2022 18:16:05'}}}
        '''
        return await self._get_status_values(['TPMS','tirePressure'])

    async def battery(self):
        '''
        GET Vehicle.battery
        {'battery': {'batteryHealth': {'value': 'STATUS_GOOD', 'timestamp': '04-04-2022 18:16:03'}, 'batteryStatusActual': {'value': 12, 'status': 'CURRENT', 'timestamp': '04-04-2022 18:16:05'}}}
        '''
        return await self._get_status_values('battery')

    async def location(self):
        '''
        GET Vehicle.location
        {'gps': {'latitude': '43.6025633', 'longitude': '-79.7085133', 'gpsState': 'UNSHIFTED', 'status': 'LAST_KNOWN', 'timestamp': '04-04-2022 12:15:58'}}
        '''
        return await self._get_status_values('gps')

    async def window_positions(self):
        '''
        GET Vehicle.window_position
        {'windowPosition': None}
        '''
        return await self._get_status_values('windowPosition')

    async def door_status(self):
        '''
        GET Vehicle.door_status
        {'doorStatus': {'rightRearDoor': {'value': 'Closed', 'status': 'CURRENT', 'timestamp': '04-04-2022 18:16:05'}, 'leftRearDoor': {'value': 'Closed', 'status': 'CURRENT', 'timestamp': '04-04-2022 18:16:05'}, 'driverDoor': {'value': 'Closed', 'status': 'CURRENT', 'timestamp': '04-04-2022 18:16:05'}, 'passengerDoor': {'value': 'Closed', 'status': 'CURRENT', 'timestamp': '04-04-2022 18:16:05'}, 'hoodDoor': {'value': 'Closed', 'status': 'CURRENT', 'timestamp': '04-04-2022 18:16:05'}, 'tailgateDoor': {'value': 'Closed', 'status': 'CURRENT', 'timestamp': '04-04-2022 18:16:05'}, 'innerTailgateDoor': {'value': 'Closed', 'status': 'CURRENT', 'timestamp': '04-04-2022 18:16:05'}}}
        '''
        return await self._get_status_values('doorStatus')

    async def lock_status(self):
        '''
        GET Vehicle.lock_Status
        {'lockStatus': {'value': 'LOCKED', 'status': 'CURRENT', 'timestamp': '04-04-2022 18:16:05'}}
        '''
        return await self._get_status_values('lockStatus')

    async def alarm_status(self):
        '''
        GET Vehicle.alarm_status
        {'alarm': {'value': 'NOTSET', 'status': 'CURRENT', 'timestamp': '04-04-2022 18:16:05'}}
        '''
        return await self._get_status_values('alarm')

    async def ignition_status(self):
        '''
        GET Vehicle.ignition_status
        {'ignitionStatus': {'value': 'Off', 'status': 'CURRENT', 'timestamp': '04-04-2022 18:16:05'}}
        '''
        return await self._get_status_values('ignitionStatus')
        
    async def remoteStart_status(self):
        '''
        GET Vehicle.remoteStart_status
        {'remoteStart': {"remoteStartDuration": 0, "remoteStartTime": 0,"status": "CURRENT","timestamp": "04-04-2022 18:16:05"}, 'status': {"value": 0, "status": "CURRENT", "timestamp": "04-04-2022 18:16:05"}}
        '''
        return await self._get_status_values(['remoteStart','remoteStartStatus'])
        
    async def deepSleep_status(self):
        '''
        GET Vehicle.deepSleep_status
        {'deepSleepInProgress': {'value': False, 'timestamp': '03-22-2022 17:40:12'}}
        '''
        return await self._get_status_values('deepSleepInProgress')
    
    async def start_engine(self):
        '''
        Issue a start command to the engine
        '''
        return await self.__requestAndPoll('PUT', self.API_URL, f'/vehicles/v2/{self.vin}/engine/start')

    async def stop_engine(self):
        '''
        Issue a stop command to the engine
        '''
        return await self.__requestAndPoll('DELETE', self.API_URL, f'/vehicles/v2/{self.vin}/engine/start')


    async def lock_doors(self):
        '''
        Issue a lock command to the doors
        '''
        return await self.__requestAndPoll('PUT', self.API_URL, f'/vehicles/v2/{self.vin}/doors/lock')
 
    async def unlock_doors(self):
        '''
        Issue an unlock command to the doors
        '''
        return await self.__requestAndPoll('DELETE', self.API_URL, f'/vehicles/v2/{self.vin}/doors/lock')
        
    async def panic_alarm(self):
        '''
        sets panic alarm off
        '''
        #return await self.__requestAndPoll('PUT', self.API_URL, f'/vehicles/{self.vin}/panic/3')
        result = await self._request('PUT', self.API_URL, f'/vehicles/{self.vin}/panic/3')
        status = result.get('status', 0)
        if status == 200:
            self.log.info('Command completed successfully')
            self._publish('command', "Success")
        else:
            self.log.info('Command failed: {}'.format(result))
            self._publish('command', 'Failed: status: {}'.format(status))
        return status == 200

    async def __pollStatus(self, url, api, id, count=0):
        '''
        Poll the given URL with the given command ID until the command is completed
        timeout after 60 seconds
        '''
        if (count := count+1) > 10: # python 3.8 thing
            self.log.error('Command timeout')
            self._publish('command', "Timeout")
            return False
        result = await self._request('get', url, f'{api}/{id}')
        status = result.get('status', 0)
        if status == 552:
            self.log.info('Command is pending')
            self._publish('command', "Pending")
            await asyncio.sleep(5)
            return await self.__pollStatus(url, api, id, count) # retry after 5s
        elif status == 200:
            self.log.info('Command completed successfully')
            self._publish('command', "Success")
            return True
        elif status == 587:
            self.log.info('Command failed: {}'.format('Vehicle is in Deep Sleep, remote commands disabled'))
            self._publish('command', 'Failed: {}'.format('Vehicle is in Deep Sleep mode'))
        else:
            self.log.info('Command failed')
            self._publish('command', "Failed")
        return False

    async def __requestAndPoll(self, method, url, api):
        '''
        send command and wait for result
        '''
        value = False
        result = await self._request(method, url, api)
        self._log.debug(result)
        status = result.get('status', 0)
        if status != 200:
            if status == 590:
                self.log.info('Command failed: {}'.format('Vehicle failed to start. You must start from inside your vehicle after two consecutive remote start events'))
                self._publish('command', 'Failed: {}'.format('Must manually start after two remote starts'))
            elif status == 587:
                self.log.info('Command failed: {}'.format('Vehicle is in Deep Sleep, remote commands disabled'))
                self._publish('command', 'Failed: {}'.format('Vehicle is in Deep Sleep mode'))
            else:
                self.log.info('Command failed: {}'.format(result))
                self._publish('command', 'Failed: status: {}'.format(status))
            return value
        if result.get('commandId'):
            value = await self.__pollStatus(url, api, result['commandId'])
        await self._publish_command('get_status')
        return value
        
def parse_args():
    
    #-------- Command Line -----------------
    parser = argparse.ArgumentParser(
        description='Forward MQTT data to FordPass API')
    parser.add_argument(
        'login',
        action='store',
        type=str,
        default=None,
        help='FordPass login (default: %(default)s)')
    parser.add_argument(
        'password',
        action='store',
        type=str,
        default=None,
        help='FordPass password (default: %(default)s)')
    parser.add_argument(
        'vin',
        action='store',
        type=str,
        default=None,
        help='Vehicle VIN (default: %(default)s)')
    parser.add_argument(
        '-r', '--region',
        action='store',
        type=str,
        choices=['US', 'CA', 'EU', 'AU'],
        default='CA',
        help='Region (default: %(default)s)')
    parser.add_argument(
        '-t', '--topic',
        action='store',
        type=str,
        default="/fordpass/command",
        help='MQTT Topic to send commands to, (can use # '
             'and +) default: %(default)s)')
    parser.add_argument(
        '-T', '--feedback',
        action='store',
        type=str,
        default="/fordpass/feedback",
        help='Topic on broker to publish feedback to (default: '
             '%(default)s)')
    parser.add_argument(
        '-b', '--broker',
        action='store',
        type=str,
        default=None,
        help='ipaddress of MQTT broker (default: %(default)s)')
    parser.add_argument(
        '-p', '--port',
        action='store',
        type=int,
        default=1883,
        help='MQTT broker port number (default: %(default)s)')
    parser.add_argument(
        '-U', '--user',
        action='store',
        type=str,
        default=None,
        help='MQTT broker user name (default: %(default)s)')
    parser.add_argument(
        '-P', '--passwd',
        action='store',
        type=str,
        default=None,
        help='MQTT broker password (default: %(default)s)')
    parser.add_argument(
        '-poll', '--poll_interval',
        action='store',
        type=int,
        default=0,
        help='Polling interval (seconds) (0=off) (default: %(default)s)')
    parser.add_argument(
        '-pm', '--poll_methods',
        nargs='*',
        action='store',
        type=str,
        default='get_status',
        help='Polling method (default: %(default)s)')
    parser.add_argument(
        '-l', '--log',
        action='store',
        type=str,
        default="./fordpass.log",
        help='path/name of log file (default: %(default)s)')
    parser.add_argument(
        '-J', '--json_out',
        action='store_true',
        default = False,
        help='publish topics as json (vs individual topics) (default: %(default)s)')
    parser.add_argument(
        '-D', '--debug',
        action='store_true',
        default = False,
        help='debug mode')
    parser.add_argument(
        '--version',
        action='version',
        version="%(prog)s ({})".format(__version__),
        help='Display version of this program')
    return parser.parse_args()
    
def setuplogger(logger_name, log_file, level=logging.DEBUG, console=False):
    try: 
        l = logging.getLogger(logger_name)
        formatter = logging.Formatter('[%(asctime)s][%(levelname)5.5s](%(name)-20s) %(message)s')
        if log_file is not None:
            fileHandler = logging.handlers.RotatingFileHandler(log_file, mode='a', maxBytes=10000000, backupCount=10)
            fileHandler.setFormatter(formatter)
        if console == True:
            #formatter = logging.Formatter('[%(levelname)1.1s %(name)-20s] %(message)s')
            streamHandler = logging.StreamHandler()
            streamHandler.setFormatter(formatter)

        l.setLevel(level)
        if log_file is not None:
            l.addHandler(fileHandler)
        if console == True:
          l.addHandler(streamHandler)
             
    except Exception as e:
        print("Error in Logging setup: %s - do you have permission to write the log file??" % e)
        sys.exit(1)
            
if __name__ == "__main__":
    arg = parse_args()
    
    if arg.debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    #setup logging
    log_name = 'Main'
    setuplogger(log_name, arg.log, level=log_level,console=True)

    log = logging.getLogger(log_name)

    log.info("*******************")
    log.info("* Program Started *")
    log.info("*******************")
    
    log.debug('Debug Mode')

    log.info("{} Version: {}".format(sys.argv[0], __version__))

    log.info("Python Version: {}".format(sys.version.replace('\n','')))
    
    if arg.poll_interval:
        if not arg.poll_methods:
            arg.poll_interval = 0
        else:
            log.info(f'Polling {arg.poll_methods} every {arg.poll_interval}s')
    
    loop = asyncio.get_event_loop()
    loop.set_debug(arg.debug)
    try:
        if arg.broker:
            r = Vehicle(arg.login,
                        arg.password,
                        arg.vin,
                        arg.region,
                        ip=arg.broker,
                        port=arg.port,
                        user=arg.user,
                        password=arg.passwd,
                        pubtopic=arg.feedback,
                        topic=arg.topic,
                        name=arg.vin,
                        poll=(arg.poll_interval, arg.poll_methods),
                        json_out=arg.json_out,
                        #log=log
                        )
            #asyncio.gather(r, return_exceptions=True)
            loop.run_forever()
        else:
            r = Vehicle(arg.login, arg.password, arg.vin, arg.region, log=log) # Username, Password, VIN, region
            log.info(loop.run_until_complete(r.status()))
            
    except (KeyboardInterrupt, SystemExit):
        log.info("System exit Received - Exiting program")
        if arg.broker:
            r.stop()
        
    finally:
        pass
