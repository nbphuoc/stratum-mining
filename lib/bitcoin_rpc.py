'''
    Implements simple interface to a coin daemon's RPC.
'''

import simplejson as json
import base64
from twisted.internet import defer
from twisted.web import client
import time

import lib.logger
log = lib.logger.get_logger('bitcoin_rpc')

class BitcoinRPC(object):

    def __init__(self, host, port, username, password):
        log.debug("Got to Bitcoin RPC")
        self.bitcoin_url = 'http://%s:%d' % (host, port)
        self.credentials = base64.b64encode("%s:%s" % (username, password))
        self.headers = {
            'Content-Type': 'text/json',
            'Authorization': 'Basic %s' % self.credentials,
        }
        client.HTTPClientFactory.noisy = False

    def _call_raw(self, data):
        client.Headers
        return client.getPage(
            url=self.bitcoin_url,
            method='POST',
            headers=self.headers,
            postdata=data,
        )

    def _call(self, method, params):
        return self._call_raw(json.dumps({
                'jsonrpc': '2.0',
                'method': method,
                'params': params,
                'id': '1',
            }))

    @defer.inlineCallbacks
    def submitblock(self, block_hex, hash_hex, method='submitblock'):
        log.debug("Submitting Block HEX: %s" % [block_hex,])
        # Try submitblock if that fails, go to getblocktemplate
        if method == 'submitblock':
            log.info("Submitting Block with Submit Block ")
            try:
                resp = (yield self._call('submitblock', [block_hex,]))
            except Exception:
                log.error("Submit Block Failed with submitblock")
                method = 'getblocktemplate'

        # Try getblocktemplate
        if method == 'getblocktemplate':
            log.info("Submitting Block with GetBlockTemplate")
            try:
                resp = (yield self._call('getblocktemplate', [{'mode': 'submit', 'data': block_hex}]))
            except Exception as e:
                log.exception("Both SubmitBlock and GetBlockTemplate failed. Problem Submitting block %s. Try Enabling TX Messages in config.py!" % str(e))
                raise

        if json.loads(resp)['result'] == None:
            # make sure the block was created.
            defer.returnValue((yield self.blockexists(hash_hex)))
        else:
            defer.returnValue(False)

    @defer.inlineCallbacks
    def getinfo(self):
         resp = (yield self._call('getinfo', []))
         defer.returnValue(json.loads(resp)['result'])

    @defer.inlineCallbacks
    def getblocktemplate(self):
        try:
            resp = (yield self._call('getblocktemplate', [{}]))
            defer.returnValue(json.loads(resp)['result'])
        # if internal server error try getblocktemplate without empty {} # ppcoin
        except Exception as e:
            if (str(e) == "500 Internal Server Error"):
                resp = (yield self._call('getblocktemplate', []))
                defer.returnValue(json.loads(resp)['result'])
            else:
                raise

    @defer.inlineCallbacks
    def prevhash(self):
        resp = (yield self._call('getwork', []))
        try:
            defer.returnValue(json.loads(resp)['result']['data'][8:72])
        except Exception as e:
            log.exception("Cannot decode prevhash %s" % str(e))
            raise

    @defer.inlineCallbacks
    def validateaddress(self, address):
        resp = (yield self._call('validateaddress', [address,]))
        defer.returnValue(json.loads(resp)['result'])

    @defer.inlineCallbacks
    def getdifficulty(self):
        resp = (yield self._call('getdifficulty', []))
        defer.returnValue(json.loads(resp)['result'])

    @defer.inlineCallbacks
    def blockexists(self, hash_hex):
        log.debug("Checking Block...%s" % hash_hex)

        #Default is not found
        result = False

        try:
            resp = (yield self._call('getblock', [hash_hex,]))
            if "hash" in json.loads(resp)['result'] and json.loads(resp)['result']['hash'] == hash_hex:
                log.debug("Block Confirmed: %s" % hash_hex)
                result = True
            else:
                log.info("Cannot find block for %s" % hash_hex)
        except:
            log.error("Network could not verify block %s. Make sure you have peers connected and have a syncronized block chain" % hash_hex)

        #Resturn Result
        defer.returnValue(result)
