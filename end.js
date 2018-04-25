 /*----------------------------------------------------------------------------*/
 // Copyright (c) 2009 pidder <www.pidder.com>
 // Permission to use, copy, modify, and/or distribute this software for any
 // purpose with or without fee is hereby granted, provided that the above
 // copyright notice and this permission notice appear in all copies.
 //
 // THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 // WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 // MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 // ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 // WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 // ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 // OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
/*----------------------------------------------------------------------------*/
/*
*  AES CBC (Cipher Block Chaining) Mode for use in pidCrypt Library
*  The pidCrypt AES CBC mode is compatible with openssl aes-xxx-cbc mode
*  using the same algorithms for key and iv creation and padding as openssl.
*
*  Depends on pidCrypt (pidcrypt.js, pidcrypt_util.js), AES (aes_core.js)
*  and MD5 (md5.js)
*
/*----------------------------------------------------------------------------*/

if(typeof(pidCrypt) != 'undefined' &&
   typeof(pidCrypt.AES) != 'undefined' &&
   typeof(pidCrypt.MD5) != 'undefined')
{
  pidCrypt.AES.CBC = function () {
    this.pidcrypt = new pidCrypt();
    this.aes = new pidCrypt.AES(this.pidcrypt);
    //shortcuts to pidcrypt methods
    this.getOutput = function(){
      return this.pidcrypt.getOutput();
    }
    this.getAllMessages = function(lnbrk){
      return this.pidcrypt.getAllMessages(lnbrk);
    }
    this.isError = function(){
      return this.pidcrypt.isError();
    }
  }
/**
* Initialize CBC for encryption from password.
* Note: Only for encrypt operation!
* @param  password: String
* @param  options {
*           nBits: aes bit size (128, 192 or 256)
*         }
*/
  pidCrypt.AES.CBC.prototype.init = function(password, options) {
    if(!options) options = {};
    var pidcrypt = this.pidcrypt;
    pidcrypt.setDefaults();
    var pObj = this.pidcrypt.getParams(); //loading defaults
    for(var o in options)
      pObj[o] = options[o];
    var k_iv = this.createKeyAndIv({password:password, salt: pObj.salt, bits: pObj.nBits});
    pObj.key = k_iv.key;
    pObj.iv = k_iv.iv;
    pObj.dataOut = '';
    pidcrypt.setParams(pObj)
    this.aes.init();
  }

/**
* Initialize CBC for encryption from password.
* @param  dataIn: plain text
* @param  password: String
* @param  options {
*           nBits: aes bit size (128, 192 or 256)
*         }
*/
  pidCrypt.AES.CBC.prototype.initEncrypt = function(dataIn, password, options) {
    this.init(password,options);//call standard init
    this.pidcrypt.setParams({dataIn:dataIn, encryptIn: pidCryptUtil.toByteArray(dataIn)})//setting input for encryption
  }
/**
* Initialize CBC for decryption from encrypted text (compatible with openssl).
* see thread http://thedotnet.com/nntp/300307/showpost.aspx
* @param  crypted: base64 encoded aes encrypted text
* @param  passwd: String
* @param  options {
*           nBits: aes bit size (128, 192 or 256),
*           UTF8: boolean, set to false when decrypting certificates,
*           A0_PAD: boolean, set to false when decrypting certificates
*         }
*/
  pidCrypt.AES.CBC.prototype.initDecrypt = function(crypted, password, options){
    if(!options) options = {};
    var pidcrypt = this.pidcrypt;
    pidcrypt.setParams({dataIn:crypted})
    if(!password)
      pidcrypt.appendError('pidCrypt.AES.CBC.initFromEncryption: Sorry, can not crypt or decrypt without password.\n');
    var ciphertext = pidCryptUtil.decodeBase64(crypted);
    if(ciphertext.indexOf('Salted__') != 0)
      pidcrypt.appendError('pidCrypt.AES.CBC.initFromCrypt: Sorry, unknown encryption method.\n');
    var salt = ciphertext.substr(8,8);//extract salt from crypted text
    options.salt = pidCryptUtil.convertToHex(salt);//salt is always hex string
    this.init(password,options);//call standard init
    ciphertext = ciphertext.substr(16);
    pidcrypt.setParams({decryptIn:pidCryptUtil.toByteArray(ciphertext)})
  }
/**
* Init CBC En-/Decryption from given parameters.
* @param  input: plain text or base64 encrypted text
* @param  key: HEX String (16, 24 or 32 byte)
* @param  iv: HEX String (16 byte)
* @param  options {
*           salt: array of bytes (8 byte),
*           nBits: aes bit size (128, 192 or 256)
*         }
*/
  pidCrypt.AES.CBC.prototype.initByValues = function(dataIn, key, iv, options){
    var pObj = {};
    this.init('',options);//empty password, we are setting key, iv manually
    pObj.dataIn = dataIn;
    pObj.key = key
    pObj.iv = iv
    this.pidcrypt.setParams(pObj)
  }

  pidCrypt.AES.CBC.prototype.getAllMessages = function(lnbrk){
    return this.pidcrypt.getAllMessages(lnbrk);
  }
/**
* Creates key of length nBits and an iv form password+salt
* compatible to openssl.
* See thread http://thedotnet.com/nntp/300307/showpost.aspx
*
* @param  pObj {
*    password: password as String
*    [salt]: salt as String, default 8 byte random salt
*    [bits]: no of bits, default pidCrypt.params.nBits = 256
* }
*
* @return         {iv: HEX String, key: HEX String}
*/
  pidCrypt.AES.CBC.prototype.createKeyAndIv = function(pObj){
    var pidcrypt = this.pidcrypt;
    var retObj = {};
    var count = 1;//openssl rounds
    var miter = "3";
    if(!pObj) pObj = {};
    if(!pObj.salt) {
      pObj.salt = pidcrypt.getRandomBytes(8);
      pObj.salt = pidCryptUtil.convertToHex(pidCryptUtil.byteArray2String(pObj.salt));
      pidcrypt.setParams({salt: pObj.salt});
    }
    var data00 = pObj.password + pidCryptUtil.convertFromHex(pObj.salt);
    var hashtarget = '';
    var result = '';
    var keymaterial = [];
    var loop = 0;
    keymaterial[loop++] = data00;
    for(var j=0; j<miter; j++){
      if(j == 0)
        result = data00;   	//initialize
      else {
        hashtarget = pidCryptUtil.convertFromHex(result);
        hashtarget += data00;
        result = hashtarget;
      }
      for(var c=0; c<count; c++){
        result = pidCrypt.MD5(result);
      }
      keymaterial[loop++] = result;
    }
    switch(pObj.bits){
      case 128://128 bit
        retObj.key = keymaterial[1];
        retObj.iv = keymaterial[2];
        break;
      case 192://192 bit
        retObj.key = keymaterial[1] + keymaterial[2].substr(0,16);
        retObj.iv = keymaterial[3];
        break;
      case 256://256 bit
        retObj.key = keymaterial[1] + keymaterial[2];
        retObj.iv = keymaterial[3];
        break;
       default:
         pidcrypt.appendError('pidCrypt.AES.CBC.createKeyAndIv: Sorry, only 128, 192 and 256 bits are supported.\nBits('+typeof(pObj.bits)+') = '+pObj.bits);
    }
    return retObj;
  }
/**
* Encrypt a text using AES encryption in CBC mode of operation
*  - see http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
*
* one of the pidCrypt.AES.CBC init funtions must be called before execution
*
* @param  byteArray: text to encrypt as array of bytes
*
* @return aes-cbc encrypted text
*/
  pidCrypt.AES.CBC.prototype.encryptRaw = function(byteArray) {
    var pidcrypt = this.pidcrypt;
    var aes = this.aes;
    var p = pidcrypt.getParams(); //get parameters for operation set by init
    if(!byteArray)
      byteArray = p.encryptIn;
    pidcrypt.setParams({encryptIn: byteArray});
    if(!p.dataIn) pidcrypt.setParams({dataIn:byteArray});
    var iv = pidCryptUtil.convertFromHex(p.iv);
    //PKCS5 paddding
    var charDiv = p.blockSize - ((byteArray.length+1) % p.blockSize);
    if(p.A0_PAD)
      byteArray[byteArray.length] = 10
    for(var c=0;c<charDiv;c++) byteArray[byteArray.length] = charDiv;
    var nBytes = Math.floor(p.nBits/8);  // nr of bytes in key
    var keyBytes = new Array(nBytes);
    var key = pidCryptUtil.convertFromHex(p.key);
    for (var i=0; i<nBytes; i++) {
      keyBytes[i] = isNaN(key.charCodeAt(i)) ? 0 : key.charCodeAt(i);
    }
    // generate key schedule
    var keySchedule = aes.expandKey(keyBytes);
    var blockCount = Math.ceil(byteArray.length/p.blockSize);
    var ciphertxt = new Array(blockCount);  // ciphertext as array of strings
    var textBlock = [];
    var state = pidCryptUtil.toByteArray(iv);
    for (var b=0; b<blockCount; b++) {
      // XOR last block and next data block, then encrypt that
      textBlock = byteArray.slice(b*p.blockSize, b*p.blockSize+p.blockSize);
      state = aes.xOr_Array(state, textBlock);
      state = aes.encrypt(state.slice(), keySchedule);  // -- encrypt block --
      ciphertxt[b] = pidCryptUtil.byteArray2String(state);
    }
    var ciphertext = ciphertxt.join('');
    pidcrypt.setParams({dataOut:ciphertext, encryptOut:ciphertext});

    //remove all parameters from enviroment for more security is debug off
    if(!pidcrypt.isDebug() && pidcrypt.clear) pidcrypt.clearParams();
   return ciphertext || '';
  }


/**
* Encrypt a text using AES encryption in CBC mode of operation
*  - see http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
*
* Unicode multi-byte character safe
*
* one of the pidCrypt.AES.CBC init funtions must be called before execution
*
* @param  plaintext: text to encrypt
*
* @return aes-cbc encrypted text openssl compatible
*/
 pidCrypt.AES.CBC.prototype.encrypt = function(plaintext) {
    var pidcrypt = this.pidcrypt;
    var salt = '';
    var p = pidcrypt.getParams(); //get parameters for operation set by init
    if(!plaintext)
      plaintext = p.dataIn;
    if(p.UTF8)
      plaintext = pidCryptUtil.encodeUTF8(plaintext);
    pidcrypt.setParams({dataIn:plaintext, encryptIn: pidCryptUtil.toByteArray(plaintext)});
    var ciphertext = this.encryptRaw()
    salt = 'Salted__' + pidCryptUtil.convertFromHex(p.salt);
    ciphertext = salt  + ciphertext;
    ciphertext = pidCryptUtil.encodeBase64(ciphertext);  // encode in base64
    pidcrypt.setParams({dataOut:ciphertext});
    //remove all parameters from enviroment for more security is debug off
    if(!pidcrypt.isDebug() && pidcrypt.clear) pidcrypt.clearParams();

    return ciphertext || '';
  }

/**
* Encrypt a text using AES encryption in CBC mode of operation
*  - see http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
*
* Unicode multi-byte character safe
*
* @param  dataIn: plain text
* @param  password: String
* @param  options {
*           nBits: aes bit size (128, 192 or 256)
*         }
*
* @param  plaintext: text to encrypt
*
* @return aes-cbc encrypted text openssl compatible
*
*/
  pidCrypt.AES.CBC.prototype.encryptText = function(dataIn,password,options) {
   this.initEncrypt(dataIn, password, options);
   return this.encrypt();
  }



/**
* Decrypt a text encrypted by AES in CBC mode of operation
*
* one of the pidCrypt.AES.CBC init funtions must be called before execution
*
* @param  byteArray: aes-cbc encrypted text as array of bytes
* 
* @return           decrypted text as String
*/
pidCrypt.AES.CBC.prototype.decryptRaw = function(byteArray) {
    var aes = this.aes;
    var pidcrypt = this.pidcrypt;
    var p = pidcrypt.getParams(); //get parameters for operation set by init
    if(!byteArray)
      byteArray = p.decryptIn;
    pidcrypt.setParams({decryptIn: byteArray});
    if(!p.dataIn) pidcrypt.setParams({dataIn:byteArray});
    if((p.iv.length/2)<p.blockSize)
      return pidcrypt.appendError('pidCrypt.AES.CBC.decrypt: Sorry, can not decrypt without complete set of parameters.\n Length of key,iv:'+p.key.length+','+p.iv.length);
    var iv = pidCryptUtil.convertFromHex(p.iv);
    if(byteArray.length%p.blockSize != 0)
      return pidcrypt.appendError('pidCrypt.AES.CBC.decrypt: Sorry, the encrypted text has the wrong length for aes-cbc mode\n Length of ciphertext:'+byteArray.length+byteArray.length%p.blockSize);
    var nBytes = Math.floor(p.nBits/8);  // nr of bytes in key
    var keyBytes = new Array(nBytes);
    var key = pidCryptUtil.convertFromHex(p.key);
    for (var i=0; i<nBytes; i++) {
      keyBytes[i] = isNaN(key.charCodeAt(i)) ? 0 : key.charCodeAt(i);
    }
    // generate key schedule
    var keySchedule = aes.expandKey(keyBytes);
    // separate byteArray into blocks
    var nBlocks = Math.ceil((byteArray.length) / p.blockSize);
    // plaintext will get generated block-by-block into array of block-length strings
    var plaintxt = new Array(nBlocks.length);
    var state = pidCryptUtil.toByteArray(iv);
    var ciphertextBlock = [];
    var dec_state = [];
    for (var b=0; b<nBlocks; b++) {
      ciphertextBlock = byteArray.slice(b*p.blockSize, b*p.blockSize+p.blockSize);
      dec_state = aes.decrypt(ciphertextBlock, keySchedule);  // decrypt ciphertext block
      plaintxt[b] = pidCryptUtil.byteArray2String(aes.xOr_Array(state, dec_state));
      state = ciphertextBlock.slice(); //save old ciphertext for next round
    }
    
    // join array of blocks into single plaintext string and return it
    var plaintext = plaintxt.join('');
    if(pidcrypt.isDebug()) pidcrypt.appendDebug('Padding after decryption:'+ pidCryptUtil.convertToHex(plaintext) + ':' + plaintext.length + '\n');
    var endByte = plaintext.charCodeAt(plaintext.length-1);
    //remove oppenssl A0 padding eg. 0A05050505
    if(p.A0_PAD){
        plaintext = plaintext.substr(0,plaintext.length-(endByte+1));
    }
    else {
      var div = plaintext.length - (plaintext.length-endByte);
      var firstPadByte = plaintext.charCodeAt(plaintext.length-endByte);
      if(endByte == firstPadByte && endByte == div)
        plaintext = plaintext.substr(0,plaintext.length-endByte);
    }
    pidcrypt.setParams({dataOut: plaintext,decryptOut: plaintext});

    //remove all parameters from enviroment for more security is debug off
    if(!pidcrypt.isDebug() && pidcrypt.clear) pidcrypt.clearParams();

   return plaintext || '';
  }

/**
* Decrypt a base64 encoded text encrypted by AES in CBC mode of operation
* and removes padding from decrypted text
*
* one of the pidCrypt.AES.CBC init funtions must be called before execution
*
* @param  ciphertext: base64 encoded and aes-cbc encrypted text
*
* @return           decrypted text as String
*/
  pidCrypt.AES.CBC.prototype.decrypt = function(ciphertext) {
    var pidcrypt = this.pidcrypt;
    var p = pidcrypt.getParams(); //get parameters for operation set by init
    if(ciphertext)
      pidcrypt.setParams({dataIn:ciphertext});
    if(!p.decryptIn) {
      var decryptIn = pidCryptUtil.decodeBase64(p.dataIn);
      if(decryptIn.indexOf('Salted__') == 0) decryptIn = decryptIn.substr(16);
      pidcrypt.setParams({decryptIn: pidCryptUtil.toByteArray(decryptIn)});
    }
    var plaintext = this.decryptRaw();
    if(p.UTF8)
      plaintext = pidCryptUtil.decodeUTF8(plaintext);  // decode from UTF8 back to Unicode multi-byte chars
    if(pidcrypt.isDebug()) pidcrypt.appendDebug('Removed Padding after decryption:'+ pidCryptUtil.convertToHex(plaintext) + ':' + plaintext.length + '\n');
    pidcrypt.setParams({dataOut:plaintext});

    //remove all parameters from enviroment for more security is debug off
    if(!pidcrypt.isDebug() && pidcrypt.clear) pidcrypt.clearParams();
    return plaintext || '';
  }

/**
* Decrypt a base64 encoded text encrypted by AES in CBC mode of operation
* and removes padding from decrypted text
*
* one of the pidCrypt.AES.CBC init funtions must be called before execution
*
* @param  dataIn: base64 encoded aes encrypted text
* @param  password: String
* @param  options {
*           nBits: aes bit size (128, 192 or 256),
*           UTF8: boolean, set to false when decrypting certificates,
*           A0_PAD: boolean, set to false when decrypting certificates
*         }
*
* @return           decrypted text as String
*/
   pidCrypt.AES.CBC.prototype.decryptText = function(dataIn, password, options) {
     this.initDecrypt(dataIn, password, options);
     return this.decrypt();
   }

}

/*!Copyright (c) 2009 pidder <www.pidder.com>*/
/*----------------------------------------------------------------------------*/
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License as
// published by the Free Software Foundation; either version 3 of the
// License, or (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
// 02111-1307 USA or check at http://www.gnu.org/licenses/gpl.html

/*----------------------------------------------------------------------------*/
/*
*  pidCrypt AES core implementation for block en-/decryption for use in pidCrypt
*  Library.
*  Derived from jsaes version 0.1 (See original license below)
*  Only minor Changes (e.g. using a precompiled this.SBoxInv) and port to an
*  AES Core Class for use with different AES modes.
*
*  Depends on pidCrypt (pidcrypt.js, pidcrypt_util.js)
/*----------------------------------------------------------------------------*/
/*    jsaes version 0.1  -  Copyright 2006 B. Poettering
 *    http://point-at-infinity.org/jsaes/
 *    Report bugs to: jsaes AT point-at-infinity.org
 *
 *
 * This is a javascript implementation of the AES block cipher. Key lengths
 * of 128, 192 and 256 bits are supported.
 * The well-functioning of the encryption/decryption routines has been
 * verified for different key lengths with the test vectors given in
 * FIPS-197, Appendix C.
 * The following code example enciphers the plaintext block '00 11 22 .. EE FF'
 * with the 256 bit key '00 01 02 .. 1E 1F'.
 *    AES_Init();
 *    var block = new Array(16);
 *    for(var i = 0; i < 16; i++)
 *        block[i] = 0x11 * i;
 *    var key = new Array(32);
 *    for(var i = 0; i < 32; i++)
 *        key[i] = i;
 *    AES_ExpandKey(key);
 *    AES_Encrypt(block, key);
 *    AES_Done();
/*----------------------------------------------------------------------------*/

if(typeof(pidCrypt) != 'undefined'){
  pidCrypt.AES = function(env) {
    this.env = (env) ? env : new pidCrypt();
    this.blockSize = 16;  // block size fixed at 16 bytes / 128 bits (Nb=4) for AES
    this.ShiftRowTabInv; //initialized by init()
    this.xtime; //initialized by init()
    this.SBox = new Array(
      99,124,119,123,242,107,111,197,48,1,103,43,254,215,171,
      118,202,130,201,125,250,89,71,240,173,212,162,175,156,164,114,192,183,253,
      147,38,54,63,247,204,52,165,229,241,113,216,49,21,4,199,35,195,24,150,5,154,
      7,18,128,226,235,39,178,117,9,131,44,26,27,110,90,160,82,59,214,179,41,227,
      47,132,83,209,0,237,32,252,177,91,106,203,190,57,74,76,88,207,208,239,170,
      251,67,77,51,133,69,249,2,127,80,60,159,168,81,163,64,143,146,157,56,245,
      188,182,218,33,16,255,243,210,205,12,19,236,95,151,68,23,196,167,126,61,
      100,93,25,115,96,129,79,220,34,42,144,136,70,238,184,20,222,94,11,219,224,
      50,58,10,73,6,36,92,194,211,172,98,145,149,228,121,231,200,55,109,141,213,
      78,169,108,86,244,234,101,122,174,8,186,120,37,46,28,166,180,198,232,221,
      116,31,75,189,139,138,112,62,181,102,72,3,246,14,97,53,87,185,134,193,29,
      158,225,248,152,17,105,217,142,148,155,30,135,233,206,85,40,223,140,161,
      137,13,191,230,66,104,65,153,45,15,176,84,187,22
    );
    this.SBoxInv = new Array(
      82,9,106,213,48,54,165,56,191,64,163,158,129,243,215,
      251,124,227,57,130,155,47,255,135,52,142,67,68,196,222,233,203,84,123,148,50,
      166,194,35,61,238,76,149,11,66,250,195,78,8,46,161,102,40,217,36,178,118,91,
      162,73,109,139,209,37,114,248,246,100,134,104,152,22,212,164,92,204,93,101,
      182,146,108,112,72,80,253,237,185,218,94,21,70,87,167,141,157,132,144,216,
      171,0,140,188,211,10,247,228,88,5,184,179,69,6,208,44,30,143,202,63,15,2,193,
      175,189,3,1,19,138,107,58,145,17,65,79,103,220,234,151,242,207,206,240,180,
      230,115,150,172,116,34,231,173,53,133,226,249,55,232,28,117,223,110,71,241,
      26,113,29,41,197,137,111,183,98,14,170,24,190,27,252,86,62,75,198,210,121,32,
      154,219,192,254,120,205,90,244,31,221,168,51,136,7,199,49,177,18,16,89,39,
      128,236,95,96,81,127,169,25,181,74,13,45,229,122,159,147,201,156,239,160,224,
      59,77,174,42,245,176,200,235,187,60,131,83,153,97,23,43,4,126,186,119,214,38,
      225,105,20,99,85,33,12,125
    );
    this.ShiftRowTab = new Array(0,5,10,15,4,9,14,3,8,13,2,7,12,1,6,11);
  }
/*
init: initialize the tables needed at runtime. Call this function
before the (first) key expansion.
*/
  pidCrypt.AES.prototype.init = function() {
    this.env.setParams({blockSize:this.blockSize});
    this.ShiftRowTabInv = new Array(16);
    for(var i = 0; i < 16; i++)
      this.ShiftRowTabInv[this.ShiftRowTab[i]] = i;
    this.xtime = new Array(256);
    for(i = 0; i < 128; i++) {
      this.xtime[i] = i << 1;
      this.xtime[128 + i] = (i << 1) ^ 0x1b;
    }
  }
/*
AES_ExpandKey: expand a cipher key. Depending on the desired encryption
strength of 128, 192 or 256 bits 'key' has to be a byte array of length
16, 24 or 32, respectively. The key expansion is done "in place", meaning
that the array 'key' is modified.
*/
  pidCrypt.AES.prototype.expandKey = function(input) {
    var key = input.slice();
    var kl = key.length, ks, Rcon = 1;
    switch (kl) {
      case 16: ks = 16 * (10 + 1); break;
      case 24: ks = 16 * (12 + 1); break;
      case 32: ks = 16 * (14 + 1); break;
      default:
        alert("AESCore.expandKey: Only key lengths of 16, 24 or 32 bytes allowed!");
    }
    for(var i = kl; i < ks; i += 4) {
      var temp = key.slice(i - 4, i);
      if (i % kl == 0) {
        temp = new Array(this.SBox[temp[1]] ^ Rcon, this.SBox[temp[2]],
                         this.SBox[temp[3]], this.SBox[temp[0]]);
        if ((Rcon <<= 1) >= 256)
          Rcon ^= 0x11b;
      }
      else if ((kl > 24) && (i % kl == 16))
        temp = new Array(this.SBox[temp[0]], this.SBox[temp[1]],
      this.SBox[temp[2]], this.SBox[temp[3]]);
      for(var j = 0; j < 4; j++)
        key[i + j] = key[i + j - kl] ^ temp[j];
    }
    return key;
  }
/*
AES_Encrypt: encrypt the 16 byte array 'block' with the previously
expanded key 'key'.
*/
  pidCrypt.AES.prototype.encrypt = function(input, key) {
    var l = key.length;
    var block = input.slice();
    this.addRoundKey(block, key.slice(0, 16));
    for(var i = 16; i < l - 16; i += 16) {
      this.subBytes(block);
      this.shiftRows(block);
      this.mixColumns(block);
      this.addRoundKey(block, key.slice(i, i + 16));
    }
    this.subBytes(block);
    this.shiftRows(block);
    this.addRoundKey(block, key.slice(i, l));

    return block;
  }
/*
AES_Decrypt: decrypt the 16 byte array 'block' with the previously
expanded key 'key'.
*/
  pidCrypt.AES.prototype.decrypt = function(input, key) {
    var l = key.length;
    var block = input.slice();
    this.addRoundKey(block, key.slice(l - 16, l));
    this.shiftRows(block, 1);//1=inverse operation
    this.subBytes(block, 1);//1=inverse operation
    for(var i = l - 32; i >= 16; i -= 16) {
      this.addRoundKey(block, key.slice(i, i + 16));
      this.mixColumns_Inv(block);
      this.shiftRows(block, 1);//1=inverse operation
      this.subBytes(block, 1);//1=inverse operation
    }
    this.addRoundKey(block, key.slice(0, 16));

    return block;
  }
  pidCrypt.AES.prototype.subBytes = function(state, inv) {
    var box = (typeof(inv) == 'undefined') ? this.SBox.slice() : this.SBoxInv.slice();
    for(var i = 0; i < 16; i++)
      state[i] = box[state[i]];
  }
  pidCrypt.AES.prototype.addRoundKey = function(state, rkey) {
    for(var i = 0; i < 16; i++)
      state[i] ^= rkey[i];
  }
  pidCrypt.AES.prototype.shiftRows = function(state, inv) {
    var shifttab = (typeof(inv) == 'undefined') ? this.ShiftRowTab.slice() : this.ShiftRowTabInv.slice();
    var h = new Array().concat(state);
    for(var i = 0; i < 16; i++)
      state[i] = h[shifttab[i]];
  }
  pidCrypt.AES.prototype.mixColumns = function(state) {
    for(var i = 0; i < 16; i += 4) {
      var s0 = state[i + 0], s1 = state[i + 1];
      var s2 = state[i + 2], s3 = state[i + 3];
      var h = s0 ^ s1 ^ s2 ^ s3;
      state[i + 0] ^= h ^ this.xtime[s0 ^ s1];
      state[i + 1] ^= h ^ this.xtime[s1 ^ s2];
      state[i + 2] ^= h ^ this.xtime[s2 ^ s3];
      state[i + 3] ^= h ^ this.xtime[s3 ^ s0];
    }
  }
  pidCrypt.AES.prototype.mixColumns_Inv = function(state) {
    for(var i = 0; i < 16; i += 4) {
      var s0 = state[i + 0], s1 = state[i + 1];
      var s2 = state[i + 2], s3 = state[i + 3];
      var h = s0 ^ s1 ^ s2 ^ s3;
      var xh = this.xtime[h];
      var h1 = this.xtime[this.xtime[xh ^ s0 ^ s2]] ^ h;
      var h2 = this.xtime[this.xtime[xh ^ s1 ^ s3]] ^ h;
      state[i + 0] ^= h1 ^ this.xtime[s0 ^ s1];
      state[i + 1] ^= h2 ^ this.xtime[s1 ^ s2];
      state[i + 2] ^= h1 ^ this.xtime[s2 ^ s3];
      state[i + 3] ^= h2 ^ this.xtime[s3 ^ s0];
    }
  }
// xor the elements of two arrays together
  pidCrypt.AES.prototype.xOr_Array = function( a1, a2 ){
     var i;
     var res = Array();
     for( i=0; i<a1.length; i++ )
        res[i] = a1[i] ^ a2[i];

     return res;
  }
  pidCrypt.AES.prototype.getCounterBlock = function(){
    // initialise counter block (NIST SP800-38A §B.2): millisecond time-stamp for nonce in 1st 8 bytes,
    // block counter in 2nd 8 bytes
    var ctrBlk = new Array(this.blockSize);
    var nonce = (new Date()).getTime();  // timestamp: milliseconds since 1-Jan-1970
    var nonceSec = Math.floor(nonce/1000);
    var nonceMs = nonce%1000;
    // encode nonce with seconds in 1st 4 bytes, and (repeated) ms part filling 2nd 4 bytes
    for (var i=0; i<4; i++) ctrBlk[i] = (nonceSec >>> i*8) & 0xff;
    for (var i=0; i<4; i++) ctrBlk[i+4] = nonceMs & 0xff;
    
   return ctrBlk.slice();
  }
}
 /*----------------------------------------------------------------------------*/
 // Copyright (c) 2009 pidder <www.pidder.com>
 // Permission to use, copy, modify, and/or distribute this software for any
 // purpose with or without fee is hereby granted, provided that the above
 // copyright notice and this permission notice appear in all copies.
 //
 // THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 // WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 // MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 // ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 // WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 // ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 // OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
/*----------------------------------------------------------------------------*/
/*
*  AES CTR (Counter) Mode for use in pidCrypt Library
*  The pidCrypt AES CTR is based on the implementation by Chris Veness 2005-2008.
*  See http://www.movable-type.co.uk/scripts/aes.html for details and for his
*  great job.
*
*  Depends on pidCrypt (pcrypt.js, pidcrypt_util.js), AES (aes_core.js)
/*----------------------------------------------------------------------------*/
/*  AES implementation in JavaScript (c) Chris Veness 2005-2008
* You are welcome to re-use these scripts [without any warranty express or
* implied] provided you retain my copyright notice and when possible a link to
* my website (under a LGPL license). §ection numbers relate the code back to
* sections in the standard.
/*----------------------------------------------------------------------------*/
if(typeof(pidCrypt) != 'undefined' && typeof(pidCrypt.AES) != 'undefined')
{
  pidCrypt.AES.CTR = function () {
    this.pidcrypt = new pidCrypt();
    this.aes = new  pidCrypt.AES(this.pidcrypt);
    //shortcuts to pidcrypt methods
    this.getOutput = function(){
      return this.pidcrypt.getOutput();
    }
    this.getAllMessages = function(lnbrk){
      return this.pidcrypt.getAllMessages(lnbrk);
    }
    this.isError = function(){
      return this.pidcrypt.isError();
    }
  }
/**
 * Initialize CTR for encryption from password.
 * @param  password: String
 * @param  options {
 *           nBits: aes bit size (128, 192 or 256)
 *         }
*/
  pidCrypt.AES.CTR.prototype.init = function(password, options) {
    if(!options) options = {};
    if(!password)
      this.pidcrypt.appendError('pidCrypt.AES.CTR.initFromEncryption: Sorry, can not crypt or decrypt without password.\n');
    this.pidcrypt.setDefaults();
    var pObj = this.pidcrypt.getParams(); //loading defaults
    for(var o in options)
      pObj[o] = options[o];
    pObj.password = password;
    pObj.key = password;
    pObj.dataOut = '';
    this.pidcrypt.setParams(pObj);
    this.aes.init();
  }

/**
* Init CTR Encryption from password.
* @param  dataIn: plain text
* @param  password: String
* @param  options {
*           nBits: aes bit size (128, 192 or 256)
*         }
*/
  pidCrypt.AES.CTR.prototype.initEncrypt = function(dataIn, password, options) {
    this.init(password, options);
    this.pidcrypt.setParams({dataIn:dataIn, encryptIn: pidCryptUtil.toByteArray(dataIn)})//setting input for encryption
 }
/**
* Init CTR for decryption from encrypted text (encrypted with pidCrypt.AES.CTR)
* @param  crypted: base64 encrypted text
* @param  password: String
* @param  options {
*           nBits: aes bit size (128, 192 or 256)
*         }
*/
  pidCrypt.AES.CTR.prototype.initDecrypt = function(crypted, password, options){
    var pObj = {};
    this.init(password, options);
    pObj.dataIn = crypted;
    var cipherText = pidCryptUtil.decodeBase64(crypted);
    // recover nonce from 1st 8 bytes of ciphertext
    var salt = cipherText.substr(0,8);//nonce in ctr
    pObj.salt = pidCryptUtil.convertToHex(salt);
    cipherText = cipherText.substr(8)
    pObj.decryptIn = pidCryptUtil.toByteArray(cipherText);
    this.pidcrypt.setParams(pObj);
  }

  pidCrypt.AES.CTR.prototype.getAllMessages = function(lnbrk){
    return this.pidcrypt.getAllMessages(lnbrk);
  }

  pidCrypt.AES.CTR.prototype.getCounterBlock = function(bs){
// initialise counter block (NIST SP800-38A §B.2): millisecond time-stamp for
// nonce in 1st 8 bytes, block counter in 2nd 8 bytes
    var ctrBlk = new Array(bs);
    var nonce = (new Date()).getTime();  // timestamp: milliseconds since 1-Jan-1970
    var nonceSec = Math.floor(nonce/1000);
    var nonceMs = nonce%1000;
    // encode nonce with seconds in 1st 4 bytes, and (repeated) ms part filling
    // 2nd 4 bytes
    for (var i=0; i<4; i++) ctrBlk[i] = (nonceSec >>> i*8) & 0xff;
    for (i=0; i<4; i++) ctrBlk[i+4] = nonceMs & 0xff;

    return ctrBlk.slice();
  }

/**
* Encrypt a text using AES encryption in CTR mode of operation
*  - see http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
* one of the pidCrypt.AES.CTR init funtions must be called before execution
*
* @param  plaintext: text to encrypt
*
*
* @return          encrypted text
*/
  pidCrypt.AES.CTR.prototype.encryptRaw = function(byteArray) {
    var aes = this.aes;
    var pidcrypt = this.pidcrypt;
    var p = pidcrypt.getParams(); //get parameters for operation set by init
    if(!byteArray)
      byteArray = p.encryptIn;
    pidcrypt.setParams({encryptIn:byteArray});
    var password = p.key;
    // use AES itself to encrypt password to get cipher key (using plain
    // password as source for key expansion) - gives us well encrypted key
    var nBytes = Math.floor(p.nBits/8);  // no bytes in key
    var pwBytes = new Array(nBytes);
    for (var i=0; i<nBytes; i++)
      pwBytes[i] = isNaN(password.charCodeAt(i)) ? 0 : password.charCodeAt(i);
    var key = aes.encrypt(pwBytes.slice(0,16), aes.expandKey(pwBytes));  // gives us 16-byte key
    key = key.concat(key.slice(0, nBytes-16));  // expand key to 16/24/32 bytes long
    var counterBlock = this.getCounterBlock(p.blockSize);
    // and convert it to a string to go on the front of the ciphertext
    var ctrTxt = pidCryptUtil.byteArray2String(counterBlock.slice(0,8));
    pidcrypt.setParams({salt:pidCryptUtil.convertToHex(ctrTxt)});
    // generate key schedule - an expansion of the key into distinct Key Rounds
    // for each round
    var keySchedule = aes.expandKey(key);
    var blockCount = Math.ceil(byteArray.length/p.blockSize);
    var ciphertxt = new Array(blockCount);  // ciphertext as array of strings
    for (var b=0; b<blockCount; b++) {
    // set counter (block #) in last 8 bytes of counter block (leaving nonce in 1st 8 bytes)
    // done in two stages for 32-bit ops: using two words allows us to go past 2^32 blocks (68GB)
      for (var c=0; c<4; c++) counterBlock[15-c] = (b >>> c*8) & 0xff;
      for (var c=0; c<4; c++) counterBlock[15-c-4] = (b/0x100000000 >>> c*8)
      var cipherCntr = aes.encrypt(counterBlock, keySchedule);  // -- encrypt counter block --
      // block size is reduced on final block
      var blockLength = b<blockCount-1 ? p.blockSize : (byteArray.length-1)%p.blockSize+1;
      var cipherChar = new Array(blockLength);
      for (var i=0; i<blockLength; i++) {  // -- xor plaintext with ciphered counter char-by-char --
        cipherChar[i] = cipherCntr[i] ^ byteArray[b*p.blockSize+i];
        cipherChar[i] = String.fromCharCode(cipherChar[i]);
      }
      ciphertxt[b] = cipherChar.join('');
    }
//    alert(pidCryptUtil.encodeBase64(ciphertxt.join('')));
    // Array.join is more efficient than repeated string concatenation
    var ciphertext = ctrTxt + ciphertxt.join('');
    pidcrypt.setParams({dataOut:ciphertext, encryptOut:ciphertext});
    //remove all parameters from enviroment for more security is debug off
    if(!pidcrypt.isDebug() && pidcrypt.clear) pidcrypt.clearParams();
  return ciphertext;  
}

/**
* Encrypt a text using AES encryption in CTR mode of operation
*  - see http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
* one of the pidCrypt.AES.CTR init funtions must be called before execution
*
* Unicode multi-byte character safe
*
*
* @param  plaintext: text to encrypt
*
*
* @return          encrypted text
*/
  pidCrypt.AES.CTR.prototype.encrypt = function(plaintext) {
    var pidcrypt = this.pidcrypt;
    var p = pidcrypt.getParams(); //get parameters for operation set by init
    if(!plaintext)
      plaintext = p.dataIn;
    if(p.UTF8){
      plaintext = pidCryptUtil.encodeUTF8(plaintext);
      pidcrypt.setParams({key:pidCryptUtil.encodeUTF8(pidcrypt.getParam('key'))});
    }
    pidcrypt.setParams({dataIn:plaintext, encryptIn: pidCryptUtil.toByteArray(plaintext)});
    var ciphertext = this.encryptRaw();
    ciphertext = pidCryptUtil.encodeBase64(ciphertext);  // encode in base64
    pidcrypt.setParams({dataOut:ciphertext});
    //remove all parameters from enviroment for more security is debug off
    if(!pidcrypt.isDebug() && pidcrypt.clear) pidcrypt.clearParams();

    return ciphertext;
  }

/**
* Encrypt a text using AES encryption in CTR mode of operation
*  - see http://csrc.nist.gov/publications/nistpubs/800-38a/sp800-38a.pdf
* one of the pidCrypt.AES.CTR init funtions must be called before execution
*
* Unicode multi-byte character safe
*
* @param  dataIn: plain text
* @param  password: String
* @param  options {
*           nBits: aes bit size (128, 192 or 256)
*         }
*
* @return          encrypted text
*/
  pidCrypt.AES.CTR.prototype.encryptText = function(dataIn, password, options) {
   this.initEncrypt(dataIn, password, options);
   return this.encrypt();
 }


/**
* Decrypt a text encrypted by AES in CTR mode of operation
*
* one of the pidCrypt.AES.CTR init funtions must be called before execution
*
* @param  ciphertext: text to decrypt
*
* @return           decrypted text as String
*/
  pidCrypt.AES.CTR.prototype.decryptRaw = function(byteArray) {
    var pidcrypt = this.pidcrypt;
    var aes = this.aes;
    var p = pidcrypt.getParams(); //get parameters for operation set by init
    if(!byteArray)
      byteArray = p.decryptIn;
    pidcrypt.setParams({decryptIn:byteArray});
    if(!p.dataIn) pidcrypt.setParams({dataIn:byteArray});
    // use AES to encrypt password (mirroring encrypt routine)
    var nBytes = Math.floor(p.nBits/8);  // no bytes in key
    var pwBytes = new Array(nBytes);
    for (var i=0; i<nBytes; i++) {
      pwBytes[i] = isNaN(p.key.charCodeAt(i)) ? 0 : p.key.charCodeAt(i);
    }
    var key = aes.encrypt(pwBytes.slice(0,16), aes.expandKey(pwBytes));  // gives us 16-byte key
    key = key.concat(key.slice(0, nBytes-16));  // expand key to 16/24/32 bytes long
    var counterBlock = new Array(8);
    var ctrTxt = pidCryptUtil.convertFromHex(p.salt);
    for (i=0; i<8; i++) counterBlock[i] = ctrTxt.charCodeAt(i);
    // generate key schedule
    var keySchedule =  aes.expandKey(key);
    // separate ciphertext into blocks (skipping past initial 8 bytes)
    var nBlocks = Math.ceil((byteArray.length) / p.blockSize);
    var blockArray = new Array(nBlocks);
    for (var b=0; b<nBlocks; b++) blockArray[b] = byteArray.slice(b*p.blockSize, b*p.blockSize+p.blockSize);
    // plaintext will get generated block-by-block into array of block-length
    // strings
    var plaintxt = new Array(blockArray.length);
    var cipherCntr = [];
    var plaintxtByte = [];
    for (b=0; b<nBlocks; b++) {
    // set counter (block #) in last 8 bytes of counter block (leaving nonce in 1st 8 bytes)
      for (var c=0; c<4; c++) counterBlock[15-c] = ((b) >>> c*8) & 0xff;
      for (c=0; c<4; c++) counterBlock[15-c-4] = (((b+1)/0x100000000-1) >>> c*8) & 0xff;
      cipherCntr = aes.encrypt(counterBlock, keySchedule);  // encrypt counter block
      plaintxtByte = new Array(blockArray[b].length);
      for (i=0; i<blockArray[b].length; i++) {
      // -- xor plaintxt with ciphered counter byte-by-byte --
        plaintxtByte[i] = cipherCntr[i] ^ blockArray[b][i];
        plaintxtByte[i] = String.fromCharCode(plaintxtByte[i]);
      }
      plaintxt[b] = plaintxtByte.join('');
    }
    // join array of blocks into single plaintext string
    var plaintext = plaintxt.join('');
    pidcrypt.setParams({dataOut:plaintext});
    //remove all parameters from enviroment for more security is debug off
    if(!pidcrypt.isDebug() && pidcrypt.clear) pidcrypt.clearParams();

    return plaintext;
  }
  
/**
* Decrypt a text encrypted by AES in CTR mode of operation
*
* one of the pidCrypt.AES.CTR init funtions must be called before execution
*
* @param  ciphertext: text to decrypt
*
* @return  decrypted text as String
*/
  pidCrypt.AES.CTR.prototype.decrypt = function(ciphertext) {
    var pidcrypt = this.pidcrypt;
    var p = pidcrypt.getParams(); //get parameters for operation set by init
    if(ciphertext)
      pidcrypt.setParams({dataIn:ciphertext, decryptIn: pidCryptUtil.toByteArray(ciphertext)});
    if(p.UTF8){
      pidcrypt.setParams({key:pidCryptUtil.encodeUTF8(pidcrypt.getParam('key'))});
    }
    var plaintext = this.decryptRaw();
    plaintext = pidCryptUtil.decodeUTF8(plaintext);  // decode from UTF8 back to Unicode multi-byte chars

    pidcrypt.setParams({dataOut:plaintext});
    //remove all parameters from enviroment for more security is debug off
    if(!pidcrypt.isDebug() && pidcrypt.clear) pidcrypt.clearParams();

    return plaintext;
  }
/**
* Decrypt a text encrypted by AES in CTR mode of operation
*
* one of the pidCrypt.AES.CTR init funtions must be called before execution
*
* @param  crypted: base64 encrypted text
* @param  password: String
* @param  options {
*
* @return  decrypted text as String
*/
  pidCrypt.AES.CTR.prototype.decryptText = function(crypted, password, options) {
    this.initDecrypt(crypted, password, options);
    return this.decrypt();
  }


}
 /*----------------------------------------------------------------------------*/
 // Copyright (c) 2009 pidder <www.pidder.com>
 // Permission to use, copy, modify, and/or distribute this software for any
 // purpose with or without fee is hereby granted, provided that the above
 // copyright notice and this permission notice appear in all copies.
 //
 // THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 // WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 // MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 // ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 // WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 // ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 // OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
/*----------------------------------------------------------------------------*/
/*
*  ASN1 parser for use in pidCrypt Library
*  The pidCrypt ASN1 parser is based on the implementation
*  by Lapo Luchini 2008-2009. See http://lapo.it/asn1js/ for details and
*  for his great job.
*
*  Depends on pidCrypt (pcrypt.js & pidcrypt_util).
*  For supporting Object Identifiers found in ASN.1 structure you must
*  include oids (oids.js).
*  But be aware that oids.js is really big (~> 1500 lines).
*/
/*----------------------------------------------------------------------------*/
// ASN.1 JavaScript decoder
// Copyright (c) 2008-2009 Lapo Luchini <lapo@lapo.it>

// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
// 
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
/*----------------------------------------------------------------------------*/

function Stream(enc, pos) {
  if (enc instanceof Stream) {
    this.enc = enc.enc;
    this.pos = enc.pos;
  } else {
    this.enc = enc;
    this.pos = pos;
  }
}

//pidCrypt extensions start
//hex string
Stream.prototype.parseStringHex = function(start, end) {
  if(typeof(end) == 'undefined') end = this.enc.length;
  var s = "";
  for (var i = start; i < end; ++i) {
    var h = this.get(i);
    s += this.hexDigits.charAt(h >> 4) + this.hexDigits.charAt(h & 0xF);
  }
  return s;
}
//pidCrypt extensions end

Stream.prototype.get = function(pos) {
  if (pos == undefined)
	  pos = this.pos++;
  if (pos >= this.enc.length)
	  throw 'Requesting byte offset ' + pos + ' on a stream of length ' + this.enc.length;

  return this.enc[pos];
}
Stream.prototype.hexDigits = "0123456789ABCDEF";
Stream.prototype.hexDump = function(start, end) {
  var s = "";
  for (var i = start; i < end; ++i) {
    var h = this.get(i);
    s += this.hexDigits.charAt(h >> 4) + this.hexDigits.charAt(h & 0xF);
    if ((i & 0xF) == 0x7)
      s += ' ';
    s += ((i & 0xF) == 0xF) ? '\n' : ' ';
  }

  return s;
}
Stream.prototype.parseStringISO = function(start, end) {
  var s = "";
  for (var i = start; i < end; ++i)
	  s += String.fromCharCode(this.get(i));

  return s;
}
Stream.prototype.parseStringUTF = function(start, end) {
  var s = "", c = 0;
  for (var i = start; i < end; ) {
	  var c = this.get(i++);
	  if (c < 128)
	    s += String.fromCharCode(c);
    else
      if ((c > 191) && (c < 224))
        s += String.fromCharCode(((c & 0x1F) << 6) | (this.get(i++) & 0x3F));
      else
        s += String.fromCharCode(((c & 0x0F) << 12) | ((this.get(i++) & 0x3F) << 6) | (this.get(i++) & 0x3F));
	//TODO: this doesn't check properly 'end', some char could begin before and end after
  }
  return s;
}
Stream.prototype.reTime = /^((?:1[89]|2\d)?\d\d)(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])([01]\d|2[0-3])(?:([0-5]\d)(?:([0-5]\d)(?:[.,](\d{1,3}))?)?)?(Z|[-+](?:[0]\d|1[0-2])([0-5]\d)?)?$/;
Stream.prototype.parseTime = function(start, end) {
  var s = this.parseStringISO(start, end);
  var m = this.reTime.exec(s);
  if (!m)
	  return "Unrecognized time: " + s;
  s = m[1] + "-" + m[2] + "-" + m[3] + " " + m[4];
  if (m[5]) {
	  s += ":" + m[5];
	  if (m[6]) {
	    s += ":" + m[6];
	    if (m[7])
		    s += "." + m[7];
	  }
  }
  if (m[8]) {
	  s += " UTC";
	  if (m[8] != 'Z') {
	    s += m[8];
	    if (m[9])
		    s += ":" + m[9];
	  }
  }
  return s;
}
Stream.prototype.parseInteger = function(start, end) {
  if ((end - start) > 4)
	  return undefined;
  //TODO support negative numbers
  var n = 0;
  for (var i = start; i < end; ++i)
	  n = (n << 8) | this.get(i);

  return n;
}
Stream.prototype.parseOID = function(start, end) {
  var s, n = 0, bits = 0;
  for (var i = start; i < end; ++i) {
	  var v = this.get(i);
	  n = (n << 7) | (v & 0x7F);
	  bits += 7;
	  if (!(v & 0x80)) { // finished
	    if (s == undefined)
		    s = parseInt(n / 40) + "." + (n % 40);
	    else
		    s += "." + ((bits >= 31) ? "big" : n);
	    n = bits = 0;
	  }
	  s += String.fromCharCode();
  }
  return s;
}

if(typeof(pidCrypt) != 'undefined')
{
  pidCrypt.ASN1 = function(stream, header, length, tag, sub) {
    this.stream = stream;
    this.header = header;
    this.length = length;
    this.tag = tag;
    this.sub = sub;
  }
  //pidCrypt extensions start
  //
  //gets the ASN data as tree of hex strings
  //@returns node: as javascript object tree with hex strings as values
  //e.g. RSA Public Key gives
  // {
  //   SEQUENCE:
  //              {
  //                  INTEGER: modulus,
  //                  INTEGER: public exponent
  //              }
  //}
  pidCrypt.ASN1.prototype.toHexTree = function() {
    var node = {};
    node.type = this.typeName();
    if(node.type != 'SEQUENCE')
      node.value = this.stream.parseStringHex(this.posContent(),this.posEnd());
    if (this.sub != null) {
      node.sub = [];
      for (var i = 0, max = this.sub.length; i < max; ++i)
        node.sub[i] = this.sub[i].toHexTree();
    }
    return node;
  }
  //pidCrypt extensions end

  pidCrypt.ASN1.prototype.typeName = function() {
    if (this.tag == undefined)
    return "unknown";
    var tagClass = this.tag >> 6;
    var tagConstructed = (this.tag >> 5) & 1;
    var tagNumber = this.tag & 0x1F;
    switch (tagClass) {
      case 0: // universal
        switch (tagNumber) {
          case 0x00: return "EOC";
          case 0x01: return "BOOLEAN";
          case 0x02: return "INTEGER";
          case 0x03: return "BIT_STRING";
          case 0x04: return "OCTET_STRING";
          case 0x05: return "NULL";
          case 0x06: return "OBJECT_IDENTIFIER";
          case 0x07: return "ObjectDescriptor";
          case 0x08: return "EXTERNAL";
          case 0x09: return "REAL";
          case 0x0A: return "ENUMERATED";
          case 0x0B: return "EMBEDDED_PDV";
          case 0x0C: return "UTF8String";
          case 0x10: return "SEQUENCE";
          case 0x11: return "SET";
          case 0x12: return "NumericString";
          case 0x13: return "PrintableString"; // ASCII subset
          case 0x14: return "TeletexString"; // aka T61String
          case 0x15: return "VideotexString";
          case 0x16: return "IA5String"; // ASCII
          case 0x17: return "UTCTime";
          case 0x18: return "GeneralizedTime";
          case 0x19: return "GraphicString";
          case 0x1A: return "VisibleString"; // ASCII subset
          case 0x1B: return "GeneralString";
          case 0x1C: return "UniversalString";
          case 0x1E: return "BMPString";
          default: return "Universal_" + tagNumber.toString(16);
        }
      case 1: return "Application_" + tagNumber.toString(16);
      case 2: return "[" + tagNumber + "]"; // Context
      case 3: return "Private_" + tagNumber.toString(16);
    }
  }
  pidCrypt.ASN1.prototype.content = function() {
    if (this.tag == undefined)
      return null;
    var tagClass = this.tag >> 6;
    if (tagClass != 0) // universal
      return null;
    var tagNumber = this.tag & 0x1F;
    var content = this.posContent();
    var len = Math.abs(this.length);
    switch (tagNumber) {
    case 0x01: // BOOLEAN
      return (this.stream.get(content) == 0) ? "false" : "true";
    case 0x02: // INTEGER
      return this.stream.parseInteger(content, content + len);
    //case 0x03: // BIT_STRING
    //case 0x04: // OCTET_STRING
    //case 0x05: // NULL
    case 0x06: // OBJECT_IDENTIFIER
      return this.stream.parseOID(content, content + len);
    //case 0x07: // ObjectDescriptor
    //case 0x08: // EXTERNAL
    //case 0x09: // REAL
    //case 0x0A: // ENUMERATED
    //case 0x0B: // EMBEDDED_PDV
    //case 0x10: // SEQUENCE
    //case 0x11: // SET
    case 0x0C: // UTF8String
      return this.stream.parseStringUTF(content, content + len);
    case 0x12: // NumericString
    case 0x13: // PrintableString
    case 0x14: // TeletexString
    case 0x15: // VideotexString
    case 0x16: // IA5String
    //case 0x19: // GraphicString
    case 0x1A: // VisibleString
    //case 0x1B: // GeneralString
    //case 0x1C: // UniversalString
    //case 0x1E: // BMPString
      return this.stream.parseStringISO(content, content + len);
    case 0x17: // UTCTime
    case 0x18: // GeneralizedTime
      return this.stream.parseTime(content, content + len);
    }
    return null;
  }
  pidCrypt.ASN1.prototype.toString = function() {
    return this.typeName() + "@" + this.stream.pos + "[header:" + this.header + ",length:" + this.length + ",sub:" + ((this.sub == null) ? 'null' : this.sub.length) + "]";
  }
  pidCrypt.ASN1.prototype.print = function(indent) {
    if (indent == undefined) indent = '';
      document.writeln(indent + this);
    if (this.sub != null) {
      indent += '  ';
    for (var i = 0, max = this.sub.length; i < max; ++i)
      this.sub[i].print(indent);
    }
  }
  pidCrypt.ASN1.prototype.toPrettyString = function(indent) {
    if (indent == undefined) indent = '';
    var s = indent + this.typeName() + " @" + this.stream.pos;
    if (this.length >= 0)
      s += "+";
    s += this.length;
    if (this.tag & 0x20)
      s += " (constructed)";
    else
      if (((this.tag == 0x03) || (this.tag == 0x04)) && (this.sub != null))
        s += " (encapsulates)";
    s += "\n";
    if (this.sub != null) {
      indent += '  ';
      for (var i = 0, max = this.sub.length; i < max; ++i)
        s += this.sub[i].toPrettyString(indent);
    }
    return s;
  }
  pidCrypt.ASN1.prototype.toDOM = function() {
    var node = document.createElement("div");
    node.className = "node";
    node.asn1 = this;
    var head = document.createElement("div");
    head.className = "head";
    var s = this.typeName();
    head.innerHTML = s;
    node.appendChild(head);
    this.head = head;
    var value = document.createElement("div");
    value.className = "value";
    s = "Offset: " + this.stream.pos + "<br/>";
    s += "Length: " + this.header + "+";
    if (this.length >= 0)
      s += this.length;
    else
      s += (-this.length) + " (undefined)";
    if (this.tag & 0x20)
      s += "<br/>(constructed)";
    else if (((this.tag == 0x03) || (this.tag == 0x04)) && (this.sub != null))
      s += "<br/>(encapsulates)";
    var content = this.content();
    if (content != null) {
      s += "<br/>Value:<br/><b>" + content + "</b>";
      if ((typeof(oids) == 'object') && (this.tag == 0x06)) {
        var oid = oids[content];
        if (oid) {
          if (oid.d) s += "<br/>" + oid.d;
          if (oid.c) s += "<br/>" + oid.c;
          if (oid.w) s += "<br/>(warning!)";
        }
      }
    }
    value.innerHTML = s;
    node.appendChild(value);
    var sub = document.createElement("div");
    sub.className = "sub";
    if (this.sub != null) {
      for (var i = 0, max = this.sub.length; i < max; ++i)
        sub.appendChild(this.sub[i].toDOM());
    }
    node.appendChild(sub);
    head.switchNode = node;
    head.onclick = function() {
      var node = this.switchNode;
      node.className = (node.className == "node collapsed") ? "node" : "node collapsed";
    };
    return node;
  }
  pidCrypt.ASN1.prototype.posStart = function() {
    return this.stream.pos;
  }
  pidCrypt.ASN1.prototype.posContent = function() {
    return this.stream.pos + this.header;
  }
  pidCrypt.ASN1.prototype.posEnd = function() {
    return this.stream.pos + this.header + Math.abs(this.length);
  }
  pidCrypt.ASN1.prototype.toHexDOM_sub = function(node, className, stream, start, end) {
    if (start >= end)
      return;
    var sub = document.createElement("span");
    sub.className = className;
    sub.appendChild(document.createTextNode(
    stream.hexDump(start, end)));
    node.appendChild(sub);
  }
  pidCrypt.ASN1.prototype.toHexDOM = function() {
    var node = document.createElement("span");
    node.className = 'hex';
    this.head.hexNode = node;
    this.head.onmouseover = function() { this.hexNode.className = 'hexCurrent'; }
    this.head.onmouseout  = function() { this.hexNode.className = 'hex'; }
    this.toHexDOM_sub(node, "tag", this.stream, this.posStart(), this.posStart() + 1);
    this.toHexDOM_sub(node, (this.length >= 0) ? "dlen" : "ulen", this.stream, this.posStart() + 1, this.posContent());
    if (this.sub == null)
      node.appendChild(document.createTextNode(
        this.stream.hexDump(this.posContent(), this.posEnd())));
    else if (this.sub.length > 0) {
    var first = this.sub[0];
    var last = this.sub[this.sub.length - 1];
    this.toHexDOM_sub(node, "intro", this.stream, this.posContent(), first.posStart());
    for (var i = 0, max = this.sub.length; i < max; ++i)
        node.appendChild(this.sub[i].toHexDOM());
    this.toHexDOM_sub(node, "outro", this.stream, last.posEnd(), this.posEnd());
    }
    return node;
  }

  /*
  pidCrypt.ASN1.prototype.getValue = function() {
      TODO
  }
  */
  pidCrypt.ASN1.decodeLength = function(stream) {
      var buf = stream.get();
      var len = buf & 0x7F;
      if (len == buf)
          return len;
      if (len > 3)
          throw "Length over 24 bits not supported at position " + (stream.pos - 1);
      if (len == 0)
      return -1; // undefined
      buf = 0;
      for (var i = 0; i < len; ++i)
          buf = (buf << 8) | stream.get();
      return buf;
  }
  pidCrypt.ASN1.hasContent = function(tag, len, stream) {
      if (tag & 0x20) // constructed
      return true;
      if ((tag < 0x03) || (tag > 0x04))
      return false;
      var p = new Stream(stream);
      if (tag == 0x03) p.get(); // BitString unused bits, must be in [0, 7]
      var subTag = p.get();
      if ((subTag >> 6) & 0x01) // not (universal or context)
      return false;
      try {
      var subLength = pidCrypt.ASN1.decodeLength(p);
      return ((p.pos - stream.pos) + subLength == len);
      } catch (exception) {
      return false;
      }
  }
  pidCrypt.ASN1.decode = function(stream) {
    if (!(stream instanceof Stream))
        stream = new Stream(stream, 0);
    var streamStart = new Stream(stream);
    var tag = stream.get();
    var len = pidCrypt.ASN1.decodeLength(stream);
    var header = stream.pos - streamStart.pos;
    var sub = null;
    if (pidCrypt.ASN1.hasContent(tag, len, stream)) {
    // it has content, so we decode it
    var start = stream.pos;
    if (tag == 0x03) stream.get(); // skip BitString unused bits, must be in [0, 7]
        sub = [];
    if (len >= 0) {
        // definite length
        var end = start + len;
        while (stream.pos < end)
        sub[sub.length] = pidCrypt.ASN1.decode(stream);
        if (stream.pos != end)
        throw "Content size is not correct for container starting at offset " + start;
    } else {
        // undefined length
        try {
        for (;;) {
            var s = pidCrypt.ASN1.decode(stream);
            if (s.tag == 0)
            break;
            sub[sub.length] = s;
        }
        len = start - stream.pos;
        } catch (e) {
        throw "Exception while decoding undefined length content: " + e;
        }
    }
    } else
        stream.pos += len; // skip content
    return new pidCrypt.ASN1(streamStart, header, len, tag, sub);
  }
  pidCrypt.ASN1.test = function() {
    var test = [
      { value: [0x27],                   expected: 0x27     },
      { value: [0x81, 0xC9],             expected: 0xC9     },
      { value: [0x83, 0xFE, 0xDC, 0xBA], expected: 0xFEDCBA },
    ];
    for (var i = 0, max = test.length; i < max; ++i) {
      var pos = 0;
      var stream = new Stream(test[i].value, 0);
      var res = pidCrypt.ASN1.decodeLength(stream);
      if (res != test[i].expected)
        document.write("In test[" + i + "] expected " + test[i].expected + " got " + res + "\n");
    }
  }
}/*
 * Copyright (c) 2003-2005  Tom Wu
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS-IS" AND WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS, IMPLIED OR OTHERWISE, INCLUDING WITHOUT LIMITATION, ANY
 * WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
 *
 * IN NO EVENT SHALL TOM WU BE LIABLE FOR ANY SPECIAL, INCIDENTAL,
 * INDIRECT OR CONSEQUENTIAL DAMAGES OF ANY KIND, OR ANY DAMAGES WHATSOEVER
 * RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER OR NOT ADVISED OF
 * THE POSSIBILITY OF DAMAGE, AND ON ANY THEORY OF LIABILITY, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * In addition, the following condition applies:
 *
 * All redistributions must retain an intact copy of this copyright notice
 * and disclaimer.
 */
//Address all questions regarding this license to:
//  Tom Wu
//  tjw@cs.Stanford.EDU
// Basic JavaScript BN library - subset useful for RSA encryption.

// Bits per digit
var dbits;

// JavaScript engine analysis
var canary = 0xdeadbeefcafe;
var j_lm = ((canary&0xffffff)==0xefcafe);

// (public) Constructor
function BigInteger(a,b,c) {

  if(a != null)
    if("number" == typeof a) this.fromNumber(a,b,c);
    else if(b == null && "string" != typeof a) this.fromString(a,256);
    else this.fromString(a,b);
}

// return new, unset BigInteger
function nbi() { return new BigInteger(null); }

// am: Compute w_j += (x*this_i), propagate carries,
// c is initial carry, returns final carry.
// c < 3*dvalue, x < 2*dvalue, this_i < dvalue
// We need to select the fastest one that works in this environment.

// am1: use a single mult and divide to get the high bits,
// max digit bits should be 26 because
// max internal value = 2*dvalue^2-2*dvalue (< 2^53)
function am1(i,x,w,j,c,n) {
  while(--n >= 0) {
    var v = x*this[i++]+w[j]+c;
    c = Math.floor(v/0x4000000);
    w[j++] = v&0x3ffffff;
  }
  return c;
}
// am2 avoids a big mult-and-extract completely.
// Max digit bits should be <= 30 because we do bitwise ops
// on values up to 2*hdvalue^2-hdvalue-1 (< 2^31)
function am2(i,x,w,j,c,n) {
  var xl = x&0x7fff, xh = x>>15;
  while(--n >= 0) {
    var l = this[i]&0x7fff;
    var h = this[i++]>>15;
    var m = xh*l+h*xl;
    l = xl*l+((m&0x7fff)<<15)+w[j]+(c&0x3fffffff);
    c = (l>>>30)+(m>>>15)+xh*h+(c>>>30);
    w[j++] = l&0x3fffffff;
  }
  return c;
}
// Alternately, set max digit bits to 28 since some
// browsers slow down when dealing with 32-bit numbers.
function am3(i,x,w,j,c,n) {
  var xl = x&0x3fff, xh = x>>14;
  while(--n >= 0) {
    var l = this[i]&0x3fff;
    var h = this[i++]>>14;
    var m = xh*l+h*xl;
    l = xl*l+((m&0x3fff)<<14)+w[j]+c;
    c = (l>>28)+(m>>14)+xh*h;
    w[j++] = l&0xfffffff;
  }
  return c;
}
if(j_lm && (navigator.appName == "Microsoft Internet Explorer")) {
  BigInteger.prototype.am = am2;
  dbits = 30;
}
else if(j_lm && (navigator.appName != "Netscape")) {
  BigInteger.prototype.am = am1;
  dbits = 26;
}
else { // Mozilla/Netscape seems to prefer am3
  BigInteger.prototype.am = am3;
  dbits = 28;
}

BigInteger.prototype.DB = dbits;
BigInteger.prototype.DM = ((1<<dbits)-1);
BigInteger.prototype.DV = (1<<dbits);

var BI_FP = 52;
BigInteger.prototype.FV = Math.pow(2,BI_FP);
BigInteger.prototype.F1 = BI_FP-dbits;
BigInteger.prototype.F2 = 2*dbits-BI_FP;

// Digit conversions
var BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz";
var BI_RC = new Array();
var rr,vv;
rr = "0".charCodeAt(0);
for(vv = 0; vv <= 9; ++vv) BI_RC[rr++] = vv;
rr = "a".charCodeAt(0);
for(vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;
rr = "A".charCodeAt(0);
for(vv = 10; vv < 36; ++vv) BI_RC[rr++] = vv;

function int2char(n) { return BI_RM.charAt(n); }
function intAt(s,i) {
  var c = BI_RC[s.charCodeAt(i)];
  return (c==null)?-1:c;
}

// (protected) copy this to r
function bnpCopyTo(r) {
  for(var i = this.t-1; i >= 0; --i) r[i] = this[i];
  r.t = this.t;
  r.s = this.s;
}

// (protected) set from integer value x, -DV <= x < DV
function bnpFromInt(x) {
  this.t = 1;
  this.s = (x<0)?-1:0;
  if(x > 0) this[0] = x;
  else if(x < -1) this[0] = x+DV;
  else this.t = 0;
}

// return bigint initialized to value
function nbv(i) { var r = nbi(); r.fromInt(i); return r; }

// (protected) set from string and radix
function bnpFromString(s,b) {
  var k;
  if(b == 16) k = 4;
  else if(b == 8) k = 3;
  else if(b == 256) k = 8; // byte array
  else if(b == 2) k = 1;
  else if(b == 32) k = 5;
  else if(b == 4) k = 2;
  else { this.fromRadix(s,b); return; }
  this.t = 0;
  this.s = 0;
  var i = s.length, mi = false, sh = 0;
  while(--i >= 0) {
    var x = (k==8)?s[i]&0xff:intAt(s,i);
    if(x < 0) {
      if(s.charAt(i) == "-") mi = true;
      continue;
    }
    mi = false;
    if(sh == 0)
      this[this.t++] = x;
    else if(sh+k > this.DB) {
      this[this.t-1] |= (x&((1<<(this.DB-sh))-1))<<sh;
      this[this.t++] = (x>>(this.DB-sh));
    }
    else
      this[this.t-1] |= x<<sh;
    sh += k;
    if(sh >= this.DB) sh -= this.DB;
  }
  if(k == 8 && (s[0]&0x80) != 0) {
    this.s = -1;
    if(sh > 0) this[this.t-1] |= ((1<<(this.DB-sh))-1)<<sh;
  }
  this.clamp();
  if(mi) BigInteger.ZERO.subTo(this,this);
}

// (protected) clamp off excess high words
function bnpClamp() {
  var c = this.s&this.DM;
  while(this.t > 0 && this[this.t-1] == c) --this.t;
}

// (public) return string representation in given radix
function bnToString(b) {
  if(this.s < 0) return "-"+this.negate().toString(b);
  var k;
  if(b == 16) k = 4;
  else if(b == 8) k = 3;
  else if(b == 2) k = 1;
  else if(b == 32) k = 5;
  else if(b == 4) k = 2;
  else return this.toRadix(b);
  var km = (1<<k)-1, d, m = false, r = "", i = this.t;
  var p = this.DB-(i*this.DB)%k;
  if(i-- > 0) {
    if(p < this.DB && (d = this[i]>>p) > 0) { m = true; r = int2char(d); }
    while(i >= 0) {
      if(p < k) {
        d = (this[i]&((1<<p)-1))<<(k-p);
        d |= this[--i]>>(p+=this.DB-k);
      }
      else {
        d = (this[i]>>(p-=k))&km;
        if(p <= 0) { p += this.DB; --i; }
      }
      if(d > 0) m = true;
      if(m) r += int2char(d);
    }
  }
  return m?r:"0";
}

// (public) -this
function bnNegate() { var r = nbi(); BigInteger.ZERO.subTo(this,r); return r; }

// (public) |this|
function bnAbs() { return (this.s<0)?this.negate():this; }

// (public) return + if this > a, - if this < a, 0 if equal
function bnCompareTo(a) {
  var r = this.s-a.s;
  if(r != 0) return r;
  var i = this.t;
  r = i-a.t;
  if(r != 0) return r;
  while(--i >= 0) if((r=this[i]-a[i]) != 0) return r;
  return 0;
}

// returns bit length of the integer x
function nbits(x) {
  var r = 1, t;
  if((t=x>>>16) != 0) { x = t; r += 16; }
  if((t=x>>8) != 0) { x = t; r += 8; }
  if((t=x>>4) != 0) { x = t; r += 4; }
  if((t=x>>2) != 0) { x = t; r += 2; }
  if((t=x>>1) != 0) { x = t; r += 1; }
  return r;
}

// (public) return the number of bits in "this"
function bnBitLength() {
  if(this.t <= 0) return 0;
  return this.DB*(this.t-1)+nbits(this[this.t-1]^(this.s&this.DM));
}

// (protected) r = this << n*DB
function bnpDLShiftTo(n,r) {
  var i;
  for(i = this.t-1; i >= 0; --i) r[i+n] = this[i];
  for(i = n-1; i >= 0; --i) r[i] = 0;
  r.t = this.t+n;
  r.s = this.s;
}

// (protected) r = this >> n*DB
function bnpDRShiftTo(n,r) {
  for(var i = n; i < this.t; ++i) r[i-n] = this[i];
  r.t = Math.max(this.t-n,0);
  r.s = this.s;
}

// (protected) r = this << n
function bnpLShiftTo(n,r) {
  var bs = n%this.DB;
  var cbs = this.DB-bs;
  var bm = (1<<cbs)-1;
  var ds = Math.floor(n/this.DB), c = (this.s<<bs)&this.DM, i;
  for(i = this.t-1; i >= 0; --i) {
    r[i+ds+1] = (this[i]>>cbs)|c;
    c = (this[i]&bm)<<bs;
  }
  for(i = ds-1; i >= 0; --i) r[i] = 0;
  r[ds] = c;
  r.t = this.t+ds+1;
  r.s = this.s;
  r.clamp();
}

// (protected) r = this >> n
function bnpRShiftTo(n,r) {
  r.s = this.s;
  var ds = Math.floor(n/this.DB);
  if(ds >= this.t) { r.t = 0; return; }
  var bs = n%this.DB;
  var cbs = this.DB-bs;
  var bm = (1<<bs)-1;
  r[0] = this[ds]>>bs;
  for(var i = ds+1; i < this.t; ++i) {
    r[i-ds-1] |= (this[i]&bm)<<cbs;
    r[i-ds] = this[i]>>bs;
  }
  if(bs > 0) r[this.t-ds-1] |= (this.s&bm)<<cbs;
  r.t = this.t-ds;
  r.clamp();
}

// (protected) r = this - a
function bnpSubTo(a,r) {
  var i = 0, c = 0, m = Math.min(a.t,this.t);
  while(i < m) {
    c += this[i]-a[i];
    r[i++] = c&this.DM;
    c >>= this.DB;
  }
  if(a.t < this.t) {
    c -= a.s;
    while(i < this.t) {
      c += this[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c += this.s;
  }
  else {
    c += this.s;
    while(i < a.t) {
      c -= a[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c -= a.s;
  }
  r.s = (c<0)?-1:0;
  if(c < -1) r[i++] = this.DV+c;
  else if(c > 0) r[i++] = c;
  r.t = i;
  r.clamp();
}

// (protected) r = this * a, r != this,a (HAC 14.12)
// "this" should be the larger one if appropriate.
function bnpMultiplyTo(a,r) {
  var x = this.abs(), y = a.abs();
  var i = x.t;
  r.t = i+y.t;
  while(--i >= 0) r[i] = 0;
  for(i = 0; i < y.t; ++i) r[i+x.t] = x.am(0,y[i],r,i,0,x.t);
  r.s = 0;
  r.clamp();
  if(this.s != a.s) BigInteger.ZERO.subTo(r,r);
}

// (protected) r = this^2, r != this (HAC 14.16)
function bnpSquareTo(r) {
  var x = this.abs();
  var i = r.t = 2*x.t;
  while(--i >= 0) r[i] = 0;
  for(i = 0; i < x.t-1; ++i) {
    var c = x.am(i,x[i],r,2*i,0,1);
    if((r[i+x.t]+=x.am(i+1,2*x[i],r,2*i+1,c,x.t-i-1)) >= x.DV) {
      r[i+x.t] -= x.DV;
      r[i+x.t+1] = 1;
    }
  }
  if(r.t > 0) r[r.t-1] += x.am(i,x[i],r,2*i,0,1);
  r.s = 0;
  r.clamp();
}

// (protected) divide this by m, quotient and remainder to q, r (HAC 14.20)
// r != q, this != m.  q or r may be null.
function bnpDivRemTo(m,q,r) {
  var pm = m.abs();
  if(pm.t <= 0) return;
  var pt = this.abs();
  if(pt.t < pm.t) {
    if(q != null) q.fromInt(0);
    if(r != null) this.copyTo(r);
    return;
  }
  if(r == null) r = nbi();
  var y = nbi(), ts = this.s, ms = m.s;
  var nsh = this.DB-nbits(pm[pm.t-1]);	// normalize modulus
  if(nsh > 0) { pm.lShiftTo(nsh,y); pt.lShiftTo(nsh,r); }
  else { pm.copyTo(y); pt.copyTo(r); }
  var ys = y.t;
  var y0 = y[ys-1];
  if(y0 == 0) return;
  var yt = y0*(1<<this.F1)+((ys>1)?y[ys-2]>>this.F2:0);
  var d1 = this.FV/yt, d2 = (1<<this.F1)/yt, e = 1<<this.F2;
  var i = r.t, j = i-ys, t = (q==null)?nbi():q;
  y.dlShiftTo(j,t);
  if(r.compareTo(t) >= 0) {
    r[r.t++] = 1;
    r.subTo(t,r);
  }
  BigInteger.ONE.dlShiftTo(ys,t);
  t.subTo(y,y);	// "negative" y so we can replace sub with am later
  while(y.t < ys) y[y.t++] = 0;
  while(--j >= 0) {
    // Estimate quotient digit
    var qd = (r[--i]==y0)?this.DM:Math.floor(r[i]*d1+(r[i-1]+e)*d2);
    if((r[i]+=y.am(0,qd,r,j,0,ys)) < qd) {	// Try it out
      y.dlShiftTo(j,t);
      r.subTo(t,r);
      while(r[i] < --qd) r.subTo(t,r);
    }
  }
  if(q != null) {
    r.drShiftTo(ys,q);
    if(ts != ms) BigInteger.ZERO.subTo(q,q);
  }
  r.t = ys;
  r.clamp();
  if(nsh > 0) r.rShiftTo(nsh,r);	// Denormalize remainder
  if(ts < 0) BigInteger.ZERO.subTo(r,r);
}

// (public) this mod a
function bnMod(a) {
  var r = nbi();
  this.abs().divRemTo(a,null,r);
  if(this.s < 0 && r.compareTo(BigInteger.ZERO) > 0) a.subTo(r,r);
  return r;
}

// Modular reduction using "classic" algorithm
function Classic(m) { this.m = m; }
function cConvert(x) {
  if(x.s < 0 || x.compareTo(this.m) >= 0) return x.mod(this.m);
  else return x;
}
function cRevert(x) { return x; }
function cReduce(x) { x.divRemTo(this.m,null,x); }
function cMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }
function cSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

Classic.prototype.convert = cConvert;
Classic.prototype.revert = cRevert;
Classic.prototype.reduce = cReduce;
Classic.prototype.mulTo = cMulTo;
Classic.prototype.sqrTo = cSqrTo;

// (protected) return "-1/this % 2^DB"; useful for Mont. reduction
// justification:
//         xy == 1 (mod m)
//         xy =  1+km
//   xy(2-xy) = (1+km)(1-km)
// x[y(2-xy)] = 1-k^2m^2
// x[y(2-xy)] == 1 (mod m^2)
// if y is 1/x mod m, then y(2-xy) is 1/x mod m^2
// should reduce x and y(2-xy) by m^2 at each step to keep size bounded.
// JS multiply "overflows" differently from C/C++, so care is needed here.
function bnpInvDigit() {
  if(this.t < 1) return 0;
  var x = this[0];
  if((x&1) == 0) return 0;
  var y = x&3;		// y == 1/x mod 2^2
  y = (y*(2-(x&0xf)*y))&0xf;	// y == 1/x mod 2^4
  y = (y*(2-(x&0xff)*y))&0xff;	// y == 1/x mod 2^8
  y = (y*(2-(((x&0xffff)*y)&0xffff)))&0xffff;	// y == 1/x mod 2^16
  // last step - calculate inverse mod DV directly;
  // assumes 16 < DB <= 32 and assumes ability to handle 48-bit ints
  y = (y*(2-x*y%this.DV))%this.DV;		// y == 1/x mod 2^dbits
  // we really want the negative inverse, and -DV < y < DV
  return (y>0)?this.DV-y:-y;
}

// Montgomery reduction
function Montgomery(m) {
  this.m = m;
  this.mp = m.invDigit();
  this.mpl = this.mp&0x7fff;
  this.mph = this.mp>>15;
  this.um = (1<<(m.DB-15))-1;
  this.mt2 = 2*m.t;
}

// xR mod m
function montConvert(x) {
  var r = nbi();
  x.abs().dlShiftTo(this.m.t,r);
  r.divRemTo(this.m,null,r);
  if(x.s < 0 && r.compareTo(BigInteger.ZERO) > 0) this.m.subTo(r,r);
  return r;
}

// x/R mod m
function montRevert(x) {
  var r = nbi();
  x.copyTo(r);
  this.reduce(r);
  return r;
}

// x = x/R mod m (HAC 14.32)
function montReduce(x) {
  while(x.t <= this.mt2)	// pad x so am has enough room later
    x[x.t++] = 0;
  for(var i = 0; i < this.m.t; ++i) {
    // faster way of calculating u0 = x[i]*mp mod DV
    var j = x[i]&0x7fff;
    var u0 = (j*this.mpl+(((j*this.mph+(x[i]>>15)*this.mpl)&this.um)<<15))&x.DM;
    // use am to combine the multiply-shift-add into one call
    j = i+this.m.t;
    x[j] += this.m.am(0,u0,x,i,0,this.m.t);
    // propagate carry
    while(x[j] >= x.DV) { x[j] -= x.DV; x[++j]++; }
  }
  x.clamp();
  x.drShiftTo(this.m.t,x);
  if(x.compareTo(this.m) >= 0) x.subTo(this.m,x);
}

// r = "x^2/R mod m"; x != r
function montSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

// r = "xy/R mod m"; x,y != r
function montMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }

Montgomery.prototype.convert = montConvert;
Montgomery.prototype.revert = montRevert;
Montgomery.prototype.reduce = montReduce;
Montgomery.prototype.mulTo = montMulTo;
Montgomery.prototype.sqrTo = montSqrTo;

// (protected) true iff this is even
function bnpIsEven() { return ((this.t>0)?(this[0]&1):this.s) == 0; }

// (protected) this^e, e < 2^32, doing sqr and mul with "r" (HAC 14.79)
function bnpExp(e,z) {
  if(e > 0xffffffff || e < 1) return BigInteger.ONE;
  var r = nbi(), r2 = nbi(), g = z.convert(this), i = nbits(e)-1;
  g.copyTo(r);
  while(--i >= 0) {
    z.sqrTo(r,r2);
    if((e&(1<<i)) > 0) z.mulTo(r2,g,r);
    else { var t = r; r = r2; r2 = t; }
  }
  return z.revert(r);
}

// (public) this^e % m, 0 <= e < 2^32
function bnModPowInt(e,m) {
  var z;
  if(e < 256 || m.isEven()) z = new Classic(m); else z = new Montgomery(m);
  return this.exp(e,z);
}

// protected
BigInteger.prototype.copyTo = bnpCopyTo;
BigInteger.prototype.fromInt = bnpFromInt;
BigInteger.prototype.fromString = bnpFromString;
BigInteger.prototype.clamp = bnpClamp;
BigInteger.prototype.dlShiftTo = bnpDLShiftTo;
BigInteger.prototype.drShiftTo = bnpDRShiftTo;
BigInteger.prototype.lShiftTo = bnpLShiftTo;
BigInteger.prototype.rShiftTo = bnpRShiftTo;
BigInteger.prototype.subTo = bnpSubTo;
BigInteger.prototype.multiplyTo = bnpMultiplyTo;
BigInteger.prototype.squareTo = bnpSquareTo;
BigInteger.prototype.divRemTo = bnpDivRemTo;
BigInteger.prototype.invDigit = bnpInvDigit;
BigInteger.prototype.isEven = bnpIsEven;
BigInteger.prototype.exp = bnpExp;

// public
BigInteger.prototype.toString = bnToString;
BigInteger.prototype.negate = bnNegate;
BigInteger.prototype.abs = bnAbs;
BigInteger.prototype.compareTo = bnCompareTo;
BigInteger.prototype.bitLength = bnBitLength;
BigInteger.prototype.mod = bnMod;
BigInteger.prototype.modPowInt = bnModPowInt;

// "constants"
BigInteger.ZERO = nbv(0);
BigInteger.ONE = nbv(1);


// Extended JavaScript BN functions, required for RSA private ops.

// (public)
function bnClone() { var r = nbi(); this.copyTo(r); return r; }

// (public) return value as integer
function bnIntValue() {
  if(this.s < 0) {
    if(this.t == 1) return this[0]-this.DV;
    else if(this.t == 0) return -1;
  }
  else if(this.t == 1) return this[0];
  else if(this.t == 0) return 0;
  // assumes 16 < DB < 32
  return ((this[1]&((1<<(32-this.DB))-1))<<this.DB)|this[0];
}

// (public) return value as byte
function bnByteValue() { return (this.t==0)?this.s:(this[0]<<24)>>24; }

// (public) return value as short (assumes DB>=16)
function bnShortValue() { return (this.t==0)?this.s:(this[0]<<16)>>16; }

// (protected) return x s.t. r^x < DV
function bnpChunkSize(r) { return Math.floor(Math.LN2*this.DB/Math.log(r)); }

// (public) 0 if this == 0, 1 if this > 0
function bnSigNum() {
  if(this.s < 0) return -1;
  else if(this.t <= 0 || (this.t == 1 && this[0] <= 0)) return 0;
  else return 1;
}

// (protected) convert to radix string
function bnpToRadix(b) {
  if(b == null) b = 10;
  if(this.signum() == 0 || b < 2 || b > 36) return "0";
  var cs = this.chunkSize(b);
  var a = Math.pow(b,cs);
  var d = nbv(a), y = nbi(), z = nbi(), r = "";
  this.divRemTo(d,y,z);
  while(y.signum() > 0) {
    r = (a+z.intValue()).toString(b).substr(1) + r;
    y.divRemTo(d,y,z);
  }
  return z.intValue().toString(b) + r;
}

// (protected) convert from radix string
function bnpFromRadix(s,b) {
  this.fromInt(0);
  if(b == null) b = 10;
  var cs = this.chunkSize(b);
  var d = Math.pow(b,cs), mi = false, j = 0, w = 0;
  for(var i = 0; i < s.length; ++i) {
    var x = intAt(s,i);
    if(x < 0) {
      if(s.charAt(i) == "-" && this.signum() == 0) mi = true;
      continue;
    }
    w = b*w+x;
    if(++j >= cs) {
      this.dMultiply(d);
      this.dAddOffset(w,0);
      j = 0;
      w = 0;
    }
  }
  if(j > 0) {
    this.dMultiply(Math.pow(b,j));
    this.dAddOffset(w,0);
  }
  if(mi) BigInteger.ZERO.subTo(this,this);
}

// (protected) alternate constructor
function bnpFromNumber(a,b,c) {
if("number" == typeof b) {
    // new BigInteger(int,int,RNG)
    if(a < 2) this.fromInt(1);
    else {
      this.fromNumber(a,c);
      if(!this.testBit(a-1))	// force MSB set
        this.bitwiseTo(BigInteger.ONE.shiftLeft(a-1),op_or,this);
      if(this.isEven()) this.dAddOffset(1,0); // force odd
      while(!this.isProbablePrime(b)) {
        this.dAddOffset(2,0);
        if(this.bitLength() > a) this.subTo(BigInteger.ONE.shiftLeft(a-1),this);
      }
    }
  }
  else {
    // new BigInteger(int,RNG)
    var x = new Array(), t = a&7;
    x.length = (a>>3)+1;
    b.nextBytes(x);
    if(t > 0) x[0] &= ((1<<t)-1); else x[0] = 0;
    this.fromString(x,256);
  }
}

// (public) convert to bigendian byte array
function bnToByteArray() {
  var i = this.t, r = new Array();
  r[0] = this.s;
  var p = this.DB-(i*this.DB)%8, d, k = 0;
  if(i-- > 0) {
    if(p < this.DB && (d = this[i]>>p) != (this.s&this.DM)>>p)
      r[k++] = d|(this.s<<(this.DB-p));
    while(i >= 0) {
      if(p < 8) {
        d = (this[i]&((1<<p)-1))<<(8-p);
        d |= this[--i]>>(p+=this.DB-8);
      }
      else {
        d = (this[i]>>(p-=8))&0xff;
        if(p <= 0) { p += this.DB; --i; }
      }
      if((d&0x80) != 0) d |= -256;
      if(k == 0 && (this.s&0x80) != (d&0x80)) ++k;
      if(k > 0 || d != this.s) r[k++] = d;
    }
  }
  return r;
}

function bnEquals(a) { return(this.compareTo(a)==0); }
function bnMin(a) { return(this.compareTo(a)<0)?this:a; }
function bnMax(a) { return(this.compareTo(a)>0)?this:a; }

// (protected) r = this op a (bitwise)
function bnpBitwiseTo(a,op,r) {
  var i, f, m = Math.min(a.t,this.t);
  for(i = 0; i < m; ++i) r[i] = op(this[i],a[i]);
  if(a.t < this.t) {
    f = a.s&this.DM;
    for(i = m; i < this.t; ++i) r[i] = op(this[i],f);
    r.t = this.t;
  }
  else {
    f = this.s&this.DM;
    for(i = m; i < a.t; ++i) r[i] = op(f,a[i]);
    r.t = a.t;
  }
  r.s = op(this.s,a.s);
  r.clamp();
}

// (public) this & a
function op_and(x,y) { return x&y; }
function bnAnd(a) { var r = nbi(); this.bitwiseTo(a,op_and,r); return r; }

// (public) this | a
function op_or(x,y) { return x|y; }
function bnOr(a) { var r = nbi(); this.bitwiseTo(a,op_or,r); return r; }

// (public) this ^ a
function op_xor(x,y) { return x^y; }
function bnXor(a) { var r = nbi(); this.bitwiseTo(a,op_xor,r); return r; }

// (public) this & ~a
function op_andnot(x,y) { return x&~y; }
function bnAndNot(a) { var r = nbi(); this.bitwiseTo(a,op_andnot,r); return r; }

// (public) ~this
function bnNot() {
  var r = nbi();
  for(var i = 0; i < this.t; ++i) r[i] = this.DM&~this[i];
  r.t = this.t;
  r.s = ~this.s;
  return r;
}

// (public) this << n
function bnShiftLeft(n) {
  var r = nbi();
  if(n < 0) this.rShiftTo(-n,r); else this.lShiftTo(n,r);
  return r;
}

// (public) this >> n
function bnShiftRight(n) {
  var r = nbi();
  if(n < 0) this.lShiftTo(-n,r); else this.rShiftTo(n,r);
  return r;
}

// return index of lowest 1-bit in x, x < 2^31
function lbit(x) {
  if(x == 0) return -1;
  var r = 0;
  if((x&0xffff) == 0) { x >>= 16; r += 16; }
  if((x&0xff) == 0) { x >>= 8; r += 8; }
  if((x&0xf) == 0) { x >>= 4; r += 4; }
  if((x&3) == 0) { x >>= 2; r += 2; }
  if((x&1) == 0) ++r;
  return r;
}

// (public) returns index of lowest 1-bit (or -1 if none)
function bnGetLowestSetBit() {
  for(var i = 0; i < this.t; ++i)
    if(this[i] != 0) return i*this.DB+lbit(this[i]);
  if(this.s < 0) return this.t*this.DB;
  return -1;
}

// return number of 1 bits in x
function cbit(x) {
  var r = 0;
  while(x != 0) { x &= x-1; ++r; }
  return r;
}

// (public) return number of set bits
function bnBitCount() {
  var r = 0, x = this.s&this.DM;
  for(var i = 0; i < this.t; ++i) r += cbit(this[i]^x);
  return r;
}

// (public) true iff nth bit is set
function bnTestBit(n) {
  var j = Math.floor(n/this.DB);
  if(j >= this.t) return(this.s!=0);
  return((this[j]&(1<<(n%this.DB)))!=0);
}

// (protected) this op (1<<n)
function bnpChangeBit(n,op) {
  var r = BigInteger.ONE.shiftLeft(n);
  this.bitwiseTo(r,op,r);
  return r;
}

// (public) this | (1<<n)
function bnSetBit(n) { return this.changeBit(n,op_or); }

// (public) this & ~(1<<n)
function bnClearBit(n) { return this.changeBit(n,op_andnot); }

// (public) this ^ (1<<n)
function bnFlipBit(n) { return this.changeBit(n,op_xor); }

// (protected) r = this + a
function bnpAddTo(a,r) {
  var i = 0, c = 0, m = Math.min(a.t,this.t);
  while(i < m) {
    c += this[i]+a[i];
    r[i++] = c&this.DM;
    c >>= this.DB;
  }
  if(a.t < this.t) {
    c += a.s;
    while(i < this.t) {
      c += this[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c += this.s;
  }
  else {
    c += this.s;
    while(i < a.t) {
      c += a[i];
      r[i++] = c&this.DM;
      c >>= this.DB;
    }
    c += a.s;
  }
  r.s = (c<0)?-1:0;
  if(c > 0) r[i++] = c;
  else if(c < -1) r[i++] = this.DV+c;
  r.t = i;
  r.clamp();
}

// (public) this + a
function bnAdd(a) { var r = nbi(); this.addTo(a,r); return r; }

// (public) this - a
function bnSubtract(a) { var r = nbi(); this.subTo(a,r); return r; }

// (public) this * a
function bnMultiply(a) { var r = nbi(); this.multiplyTo(a,r); return r; }

// (public) this / a
function bnDivide(a) { var r = nbi(); this.divRemTo(a,r,null); return r; }

// (public) this % a
function bnRemainder(a) { var r = nbi(); this.divRemTo(a,null,r); return r; }

// (public) [this/a,this%a]
function bnDivideAndRemainder(a) {
  var q = nbi(), r = nbi();
  this.divRemTo(a,q,r);
  return new Array(q,r);
}

// (protected) this *= n, this >= 0, 1 < n < DV
function bnpDMultiply(n) {
  this[this.t] = this.am(0,n-1,this,0,0,this.t);
  ++this.t;
  this.clamp();
}

// (protected) this += n << w words, this >= 0
function bnpDAddOffset(n,w) {
  while(this.t <= w) this[this.t++] = 0;
  this[w] += n;
  while(this[w] >= this.DV) {
    this[w] -= this.DV;
    if(++w >= this.t) this[this.t++] = 0;
    ++this[w];
  }
}

// A "null" reducer
function NullExp() {}
function nNop(x) { return x; }
function nMulTo(x,y,r) { x.multiplyTo(y,r); }
function nSqrTo(x,r) { x.squareTo(r); }

NullExp.prototype.convert = nNop;
NullExp.prototype.revert = nNop;
NullExp.prototype.mulTo = nMulTo;
NullExp.prototype.sqrTo = nSqrTo;

// (public) this^e
function bnPow(e) { return this.exp(e,new NullExp()); }

// (protected) r = lower n words of "this * a", a.t <= n
// "this" should be the larger one if appropriate.
function bnpMultiplyLowerTo(a,n,r) {
  var i = Math.min(this.t+a.t,n);
  r.s = 0; // assumes a,this >= 0
  r.t = i;
  while(i > 0) r[--i] = 0;
  var j;
  for(j = r.t-this.t; i < j; ++i) r[i+this.t] = this.am(0,a[i],r,i,0,this.t);
  for(j = Math.min(a.t,n); i < j; ++i) this.am(0,a[i],r,i,0,n-i);
  r.clamp();
}

// (protected) r = "this * a" without lower n words, n > 0
// "this" should be the larger one if appropriate.
function bnpMultiplyUpperTo(a,n,r) {
  --n;
  var i = r.t = this.t+a.t-n;
  r.s = 0; // assumes a,this >= 0
  while(--i >= 0) r[i] = 0;
  for(i = Math.max(n-this.t,0); i < a.t; ++i)
    r[this.t+i-n] = this.am(n-i,a[i],r,0,0,this.t+i-n);
  r.clamp();
  r.drShiftTo(1,r);
}

// Barrett modular reduction
function Barrett(m) {
  // setup Barrett
  this.r2 = nbi();
  this.q3 = nbi();
  BigInteger.ONE.dlShiftTo(2*m.t,this.r2);
  this.mu = this.r2.divide(m);
  this.m = m;
}

function barrettConvert(x) {
  if(x.s < 0 || x.t > 2*this.m.t) return x.mod(this.m);
  else if(x.compareTo(this.m) < 0) return x;
  else { var r = nbi(); x.copyTo(r); this.reduce(r); return r; }
}

function barrettRevert(x) { return x; }

// x = x mod m (HAC 14.42)
function barrettReduce(x) {
  x.drShiftTo(this.m.t-1,this.r2);
  if(x.t > this.m.t+1) { x.t = this.m.t+1; x.clamp(); }
  this.mu.multiplyUpperTo(this.r2,this.m.t+1,this.q3);
  this.m.multiplyLowerTo(this.q3,this.m.t+1,this.r2);
  while(x.compareTo(this.r2) < 0) x.dAddOffset(1,this.m.t+1);
  x.subTo(this.r2,x);
  while(x.compareTo(this.m) >= 0) x.subTo(this.m,x);
}

// r = x^2 mod m; x != r
function barrettSqrTo(x,r) { x.squareTo(r); this.reduce(r); }

// r = x*y mod m; x,y != r
function barrettMulTo(x,y,r) { x.multiplyTo(y,r); this.reduce(r); }

Barrett.prototype.convert = barrettConvert;
Barrett.prototype.revert = barrettRevert;
Barrett.prototype.reduce = barrettReduce;
Barrett.prototype.mulTo = barrettMulTo;
Barrett.prototype.sqrTo = barrettSqrTo;

// (public) this^e % m (HAC 14.85)
function bnModPow(e,m) {
  var i = e.bitLength(), k, r = nbv(1), z;
  if(i <= 0) return r;
  else if(i < 18) k = 1;
  else if(i < 48) k = 3;
  else if(i < 144) k = 4;
  else if(i < 768) k = 5;
  else k = 6;
  if(i < 8)
    z = new Classic(m);
  else if(m.isEven())
    z = new Barrett(m);
  else
    z = new Montgomery(m);

  // precomputation
  var g = new Array(), n = 3, k1 = k-1, km = (1<<k)-1;
  g[1] = z.convert(this);
  if(k > 1) {
    var g2 = nbi();
    z.sqrTo(g[1],g2);
    while(n <= km) {
      g[n] = nbi();
      z.mulTo(g2,g[n-2],g[n]);
      n += 2;
    }
  }

  var j = e.t-1, w, is1 = true, r2 = nbi(), t;
  i = nbits(e[j])-1;
  while(j >= 0) {
    if(i >= k1) w = (e[j]>>(i-k1))&km;
    else {
      w = (e[j]&((1<<(i+1))-1))<<(k1-i);
      if(j > 0) w |= e[j-1]>>(this.DB+i-k1);
    }

    n = k;
    while((w&1) == 0) { w >>= 1; --n; }
    if((i -= n) < 0) { i += this.DB; --j; }
    if(is1) {	// ret == 1, don't bother squaring or multiplying it
      g[w].copyTo(r);
      is1 = false;
    }
    else {
      while(n > 1) { z.sqrTo(r,r2); z.sqrTo(r2,r); n -= 2; }
      if(n > 0) z.sqrTo(r,r2); else { t = r; r = r2; r2 = t; }
      z.mulTo(r2,g[w],r);
    }

    while(j >= 0 && (e[j]&(1<<i)) == 0) {
      z.sqrTo(r,r2); t = r; r = r2; r2 = t;
      if(--i < 0) { i = this.DB-1; --j; }
    }
  }
  return z.revert(r);
}

// (public) gcd(this,a) (HAC 14.54)
function bnGCD(a) {
  var x = (this.s<0)?this.negate():this.clone();
  var y = (a.s<0)?a.negate():a.clone();
  if(x.compareTo(y) < 0) { var t = x; x = y; y = t; }
  var i = x.getLowestSetBit(), g = y.getLowestSetBit();
  if(g < 0) return x;
  if(i < g) g = i;
  if(g > 0) {
    x.rShiftTo(g,x);
    y.rShiftTo(g,y);
  }
  while(x.signum() > 0) {
    if((i = x.getLowestSetBit()) > 0) x.rShiftTo(i,x);
    if((i = y.getLowestSetBit()) > 0) y.rShiftTo(i,y);
    if(x.compareTo(y) >= 0) {
      x.subTo(y,x);
      x.rShiftTo(1,x);
    }
    else {
      y.subTo(x,y);
      y.rShiftTo(1,y);
    }
  }
  if(g > 0) y.lShiftTo(g,y);
  return y;
}

// (protected) this % n, n < 2^26
function bnpModInt(n) {
  if(n <= 0) return 0;
  var d = this.DV%n, r = (this.s<0)?n-1:0;
  if(this.t > 0)
    if(d == 0) r = this[0]%n;
    else for(var i = this.t-1; i >= 0; --i) r = (d*r+this[i])%n;
  return r;
}

// (public) 1/this % m (HAC 14.61)
function bnModInverse(m) {
  var ac = m.isEven();
  if((this.isEven() && ac) || m.signum() == 0) return BigInteger.ZERO;
  var u = m.clone(), v = this.clone();
  var a = nbv(1), b = nbv(0), c = nbv(0), d = nbv(1);
  while(u.signum() != 0) {
    while(u.isEven()) {
      u.rShiftTo(1,u);
      if(ac) {
        if(!a.isEven() || !b.isEven()) { a.addTo(this,a); b.subTo(m,b); }
        a.rShiftTo(1,a);
      }
      else if(!b.isEven()) b.subTo(m,b);
      b.rShiftTo(1,b);
    }
    while(v.isEven()) {
      v.rShiftTo(1,v);
      if(ac) {
        if(!c.isEven() || !d.isEven()) { c.addTo(this,c); d.subTo(m,d); }
        c.rShiftTo(1,c);
      }
      else if(!d.isEven()) d.subTo(m,d);
      d.rShiftTo(1,d);
    }
    if(u.compareTo(v) >= 0) {
      u.subTo(v,u);
      if(ac) a.subTo(c,a);
      b.subTo(d,b);
    }
    else {
      v.subTo(u,v);
      if(ac) c.subTo(a,c);
      d.subTo(b,d);
    }
  }
  if(v.compareTo(BigInteger.ONE) != 0) return BigInteger.ZERO;
  if(d.compareTo(m) >= 0) return d.subtract(m);
  if(d.signum() < 0) d.addTo(m,d); else return d;
  if(d.signum() < 0) return d.add(m); else return d;
}

var lowprimes = [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199,211,223,227,229,233,239,241,251,257,263,269,271,277,281,283,293,307,311,313,317,331,337,347,349,353,359,367,373,379,383,389,397,401,409,419,421,431,433,439,443,449,457,461,463,467,479,487,491,499,503,509];
var lplim = (1<<26)/lowprimes[lowprimes.length-1];

// (public) test primality with certainty >= 1-.5^t
function bnIsProbablePrime(t) {
  var i, x = this.abs();
  if(x.t == 1 && x[0] <= lowprimes[lowprimes.length-1]) {
    for(i = 0; i < lowprimes.length; ++i)
      if(x[0] == lowprimes[i]) return true;
    return false;
  }
  if(x.isEven()) return false;
  i = 1;
  while(i < lowprimes.length) {
    var m = lowprimes[i], j = i+1;
    while(j < lowprimes.length && m < lplim) m *= lowprimes[j++];
    m = x.modInt(m);
    while(i < j) if(m%lowprimes[i++] == 0) return false;
  }
  return x.millerRabin(t);
}

// (protected) true if probably prime (HAC 4.24, Miller-Rabin)
function bnpMillerRabin(t) {
  var n1 = this.subtract(BigInteger.ONE);
  var k = n1.getLowestSetBit();
  if(k <= 0) return false;
  var r = n1.shiftRight(k);
  t = (t+1)>>1;
  if(t > lowprimes.length) t = lowprimes.length;
  var a = nbi();
  for(var i = 0; i < t; ++i) {
    a.fromInt(lowprimes[i]);
    var y = a.modPow(r,this);
    if(y.compareTo(BigInteger.ONE) != 0 && y.compareTo(n1) != 0) {
      var j = 1;
      while(j++ < k && y.compareTo(n1) != 0) {
        y = y.modPowInt(2,this);
        if(y.compareTo(BigInteger.ONE) == 0) return false;
      }
      if(y.compareTo(n1) != 0) return false;
    }
  }
  return true;
}

// protected
BigInteger.prototype.chunkSize = bnpChunkSize;
BigInteger.prototype.toRadix = bnpToRadix;
BigInteger.prototype.fromRadix = bnpFromRadix;
BigInteger.prototype.fromNumber = bnpFromNumber;
BigInteger.prototype.bitwiseTo = bnpBitwiseTo;
BigInteger.prototype.changeBit = bnpChangeBit;
BigInteger.prototype.addTo = bnpAddTo;
BigInteger.prototype.dMultiply = bnpDMultiply;
BigInteger.prototype.dAddOffset = bnpDAddOffset;
BigInteger.prototype.multiplyLowerTo = bnpMultiplyLowerTo;
BigInteger.prototype.multiplyUpperTo = bnpMultiplyUpperTo;
BigInteger.prototype.modInt = bnpModInt;
BigInteger.prototype.millerRabin = bnpMillerRabin;

// public
BigInteger.prototype.clone = bnClone;
BigInteger.prototype.intValue = bnIntValue;
BigInteger.prototype.byteValue = bnByteValue;
BigInteger.prototype.shortValue = bnShortValue;
BigInteger.prototype.signum = bnSigNum;
BigInteger.prototype.toByteArray = bnToByteArray;
BigInteger.prototype.equals = bnEquals;
BigInteger.prototype.min = bnMin;
BigInteger.prototype.max = bnMax;
BigInteger.prototype.and = bnAnd;
BigInteger.prototype.or = bnOr;
BigInteger.prototype.xor = bnXor;
BigInteger.prototype.andNot = bnAndNot;
BigInteger.prototype.not = bnNot;
BigInteger.prototype.shiftLeft = bnShiftLeft;
BigInteger.prototype.shiftRight = bnShiftRight;
BigInteger.prototype.getLowestSetBit = bnGetLowestSetBit;
BigInteger.prototype.bitCount = bnBitCount;
BigInteger.prototype.testBit = bnTestBit;
BigInteger.prototype.setBit = bnSetBit;
BigInteger.prototype.clearBit = bnClearBit;
BigInteger.prototype.flipBit = bnFlipBit;
BigInteger.prototype.add = bnAdd;
BigInteger.prototype.subtract = bnSubtract;
BigInteger.prototype.multiply = bnMultiply;
BigInteger.prototype.divide = bnDivide;
BigInteger.prototype.remainder = bnRemainder;
BigInteger.prototype.divideAndRemainder = bnDivideAndRemainder;
BigInteger.prototype.modPow = bnModPow;
BigInteger.prototype.modInverse = bnModInverse;
BigInteger.prototype.pow = bnPow;
BigInteger.prototype.gcd = bnGCD;
BigInteger.prototype.isProbablePrime = bnIsProbablePrime;

// BigInteger interfaces not implemented in jsbn:

// BigInteger(int signum, byte[] magnitude)
// double doubleValue()
// float floatValue()
// int hashCode()
// long longValue()
// static BigInteger valueOf(long val)
/**
*
*  MD5 (Message-Digest Algorithm) for use in pidCrypt Library
*  Depends on pidCrypt (pidcrypt.js, pidcrypt_util.js)
*
*  For original source see http://www.webtoolkit.info/
*  Download: 15.02.2009 from http://www.webtoolkit.info/javascript-md5.html
**/

if(typeof(pidCrypt) != 'undefined') {
  pidCrypt.MD5 = function(string) {

    function RotateLeft(lValue, iShiftBits) {
      return (lValue<<iShiftBits) | (lValue>>>(32-iShiftBits));
    }

    function AddUnsigned(lX,lY) {
      var lX4,lY4,lX8,lY8,lResult;
      lX8 = (lX & 0x80000000);
      lY8 = (lY & 0x80000000);
      lX4 = (lX & 0x40000000);
      lY4 = (lY & 0x40000000);
      lResult = (lX & 0x3FFFFFFF)+(lY & 0x3FFFFFFF);
      if (lX4 & lY4) {
        return (lResult ^ 0x80000000 ^ lX8 ^ lY8);
      }
      if (lX4 | lY4) {
        if (lResult & 0x40000000) {
          return (lResult ^ 0xC0000000 ^ lX8 ^ lY8);
        } else {
          return (lResult ^ 0x40000000 ^ lX8 ^ lY8);
        }
      } else {
        return (lResult ^ lX8 ^ lY8);
      }
    }

    function F(x,y,z) { return (x & y) | ((~x) & z); }
    function G(x,y,z) { return (x & z) | (y & (~z)); }
    function H(x,y,z) { return (x ^ y ^ z); }
    function I(x,y,z) { return (y ^ (x | (~z))); }

    function FF(a,b,c,d,x,s,ac) {
      a = AddUnsigned(a, AddUnsigned(AddUnsigned(F(b, c, d), x), ac));
      return AddUnsigned(RotateLeft(a, s), b);
    };

    function GG(a,b,c,d,x,s,ac) {
      a = AddUnsigned(a, AddUnsigned(AddUnsigned(G(b, c, d), x), ac));
      return AddUnsigned(RotateLeft(a, s), b);
    };

    function HH(a,b,c,d,x,s,ac) {
      a = AddUnsigned(a, AddUnsigned(AddUnsigned(H(b, c, d), x), ac));
      return AddUnsigned(RotateLeft(a, s), b);
    };

    function II(a,b,c,d,x,s,ac) {
      a = AddUnsigned(a, AddUnsigned(AddUnsigned(I(b, c, d), x), ac));
      return AddUnsigned(RotateLeft(a, s), b);
    };

    function ConvertToWordArray(string) {
      var lWordCount;
      var lMessageLength = string.length;
      var lNumberOfWords_temp1=lMessageLength + 8;
      var lNumberOfWords_temp2=(lNumberOfWords_temp1-(lNumberOfWords_temp1 % 64))/64;
      var lNumberOfWords = (lNumberOfWords_temp2+1)*16;
      var lWordArray=Array(lNumberOfWords-1);
      var lBytePosition = 0;
      var lByteCount = 0;
      while ( lByteCount < lMessageLength ) {
        lWordCount = (lByteCount-(lByteCount % 4))/4;
        lBytePosition = (lByteCount % 4)*8;
        lWordArray[lWordCount] = (lWordArray[lWordCount] | (string.charCodeAt(lByteCount)<<lBytePosition));
        lByteCount++;
      }
      lWordCount = (lByteCount-(lByteCount % 4))/4;
      lBytePosition = (lByteCount % 4)*8;
      lWordArray[lWordCount] = lWordArray[lWordCount] | (0x80<<lBytePosition);
      lWordArray[lNumberOfWords-2] = lMessageLength<<3;
      lWordArray[lNumberOfWords-1] = lMessageLength>>>29;
      return lWordArray;
    };

    function WordToHex(lValue) {
      var WordToHexValue="",WordToHexValue_temp="",lByte,lCount;
      for (lCount = 0;lCount<=3;lCount++) {
        lByte = (lValue>>>(lCount*8)) & 255;
        WordToHexValue_temp = "0" + lByte.toString(16);
        WordToHexValue = WordToHexValue + WordToHexValue_temp.substr(WordToHexValue_temp.length-2,2);
      }
      return WordToHexValue;
    };

    //**	function Utf8Encode(string) removed. Aready defined in pidcrypt_utils.js

    var x=Array();
    var k,AA,BB,CC,DD,a,b,c,d;
    var S11=7, S12=12, S13=17, S14=22;
    var S21=5, S22=9 , S23=14, S24=20;
    var S31=4, S32=11, S33=16, S34=23;
    var S41=6, S42=10, S43=15, S44=21;

    //	string = Utf8Encode(string); #function call removed

    x = ConvertToWordArray(string);

    a = 0x67452301; b = 0xEFCDAB89; c = 0x98BADCFE; d = 0x10325476;

    for (k=0;k<x.length;k+=16) {
      AA=a; BB=b; CC=c; DD=d;
      a=FF(a,b,c,d,x[k+0], S11,0xD76AA478);
      d=FF(d,a,b,c,x[k+1], S12,0xE8C7B756);
      c=FF(c,d,a,b,x[k+2], S13,0x242070DB);
      b=FF(b,c,d,a,x[k+3], S14,0xC1BDCEEE);
      a=FF(a,b,c,d,x[k+4], S11,0xF57C0FAF);
      d=FF(d,a,b,c,x[k+5], S12,0x4787C62A);
      c=FF(c,d,a,b,x[k+6], S13,0xA8304613);
      b=FF(b,c,d,a,x[k+7], S14,0xFD469501);
      a=FF(a,b,c,d,x[k+8], S11,0x698098D8);
      d=FF(d,a,b,c,x[k+9], S12,0x8B44F7AF);
      c=FF(c,d,a,b,x[k+10],S13,0xFFFF5BB1);
      b=FF(b,c,d,a,x[k+11],S14,0x895CD7BE);
      a=FF(a,b,c,d,x[k+12],S11,0x6B901122);
      d=FF(d,a,b,c,x[k+13],S12,0xFD987193);
      c=FF(c,d,a,b,x[k+14],S13,0xA679438E);
      b=FF(b,c,d,a,x[k+15],S14,0x49B40821);
      a=GG(a,b,c,d,x[k+1], S21,0xF61E2562);
      d=GG(d,a,b,c,x[k+6], S22,0xC040B340);
      c=GG(c,d,a,b,x[k+11],S23,0x265E5A51);
      b=GG(b,c,d,a,x[k+0], S24,0xE9B6C7AA);
      a=GG(a,b,c,d,x[k+5], S21,0xD62F105D);
      d=GG(d,a,b,c,x[k+10],S22,0x2441453);
      c=GG(c,d,a,b,x[k+15],S23,0xD8A1E681);
      b=GG(b,c,d,a,x[k+4], S24,0xE7D3FBC8);
      a=GG(a,b,c,d,x[k+9], S21,0x21E1CDE6);
      d=GG(d,a,b,c,x[k+14],S22,0xC33707D6);
      c=GG(c,d,a,b,x[k+3], S23,0xF4D50D87);
      b=GG(b,c,d,a,x[k+8], S24,0x455A14ED);
      a=GG(a,b,c,d,x[k+13],S21,0xA9E3E905);
      d=GG(d,a,b,c,x[k+2], S22,0xFCEFA3F8);
      c=GG(c,d,a,b,x[k+7], S23,0x676F02D9);
      b=GG(b,c,d,a,x[k+12],S24,0x8D2A4C8A);
      a=HH(a,b,c,d,x[k+5], S31,0xFFFA3942);
      d=HH(d,a,b,c,x[k+8], S32,0x8771F681);
      c=HH(c,d,a,b,x[k+11],S33,0x6D9D6122);
      b=HH(b,c,d,a,x[k+14],S34,0xFDE5380C);
      a=HH(a,b,c,d,x[k+1], S31,0xA4BEEA44);
      d=HH(d,a,b,c,x[k+4], S32,0x4BDECFA9);
      c=HH(c,d,a,b,x[k+7], S33,0xF6BB4B60);
      b=HH(b,c,d,a,x[k+10],S34,0xBEBFBC70);
      a=HH(a,b,c,d,x[k+13],S31,0x289B7EC6);
      d=HH(d,a,b,c,x[k+0], S32,0xEAA127FA);
      c=HH(c,d,a,b,x[k+3], S33,0xD4EF3085);
      b=HH(b,c,d,a,x[k+6], S34,0x4881D05);
      a=HH(a,b,c,d,x[k+9], S31,0xD9D4D039);
      d=HH(d,a,b,c,x[k+12],S32,0xE6DB99E5);
      c=HH(c,d,a,b,x[k+15],S33,0x1FA27CF8);
      b=HH(b,c,d,a,x[k+2], S34,0xC4AC5665);
      a=II(a,b,c,d,x[k+0], S41,0xF4292244);
      d=II(d,a,b,c,x[k+7], S42,0x432AFF97);
      c=II(c,d,a,b,x[k+14],S43,0xAB9423A7);
      b=II(b,c,d,a,x[k+5], S44,0xFC93A039);
      a=II(a,b,c,d,x[k+12],S41,0x655B59C3);
      d=II(d,a,b,c,x[k+3], S42,0x8F0CCC92);
      c=II(c,d,a,b,x[k+10],S43,0xFFEFF47D);
      b=II(b,c,d,a,x[k+1], S44,0x85845DD1);
      a=II(a,b,c,d,x[k+8], S41,0x6FA87E4F);
      d=II(d,a,b,c,x[k+15],S42,0xFE2CE6E0);
      c=II(c,d,a,b,x[k+6], S43,0xA3014314);
      b=II(b,c,d,a,x[k+13],S44,0x4E0811A1);
      a=II(a,b,c,d,x[k+4], S41,0xF7537E82);
      d=II(d,a,b,c,x[k+11],S42,0xBD3AF235);
      c=II(c,d,a,b,x[k+2], S43,0x2AD7D2BB);
      b=II(b,c,d,a,x[k+9], S44,0xEB86D391);
      a=AddUnsigned(a,AA);
      b=AddUnsigned(b,BB);
      c=AddUnsigned(c,CC);
      d=AddUnsigned(d,DD);
    }
    var temp = WordToHex(a)+WordToHex(b)+WordToHex(c)+WordToHex(d);
    return temp.toLowerCase();
  }
}
// Converted from: http://www.cs.auckland.ac.nz/~pgut001/dumpasn1.cfg
// which was written by Peter Gutmann and whose license states:
//   You can use this code in whatever way you want,
//   as long as you don't try to claim you wrote it.
oids = {
"0.2.262.1.10": { "d": "Telesec", "c": "Deutsche Telekom", "w": false },
"0.2.262.1.10.0": { "d": "extension", "c": "Telesec", "w": false },
"0.2.262.1.10.1": { "d": "mechanism", "c": "Telesec", "w": false },
"0.2.262.1.10.1.0": { "d": "authentication", "c": "Telesec mechanism", "w": false },
"0.2.262.1.10.1.0.1": { "d": "passwordAuthentication", "c": "Telesec authentication", "w": false },
"0.2.262.1.10.1.0.2": { "d": "protectedPasswordAuthentication", "c": "Telesec authentication", "w": false },
"0.2.262.1.10.1.0.3": { "d": "oneWayX509Authentication", "c": "Telesec authentication", "w": false },
"0.2.262.1.10.1.0.4": { "d": "twoWayX509Authentication", "c": "Telesec authentication", "w": false },
"0.2.262.1.10.1.0.5": { "d": "threeWayX509Authentication", "c": "Telesec authentication", "w": false },
"0.2.262.1.10.1.0.6": { "d": "oneWayISO9798Authentication", "c": "Telesec authentication", "w": false },
"0.2.262.1.10.1.0.7": { "d": "twoWayISO9798Authentication", "c": "Telesec authentication", "w": false },
"0.2.262.1.10.1.0.8": { "d": "telekomAuthentication", "c": "Telesec authentication", "w": false },
"0.2.262.1.10.1.1": { "d": "signature", "c": "Telesec mechanism", "w": false },
"0.2.262.1.10.1.1.1": { "d": "md4WithRSAAndISO9697", "c": "Telesec mechanism", "w": false },
"0.2.262.1.10.1.1.2": { "d": "md4WithRSAAndTelesecSignatureStandard", "c": "Telesec mechanism", "w": false },
"0.2.262.1.10.1.1.3": { "d": "md5WithRSAAndISO9697", "c": "Telesec mechanism", "w": false },
"0.2.262.1.10.1.1.4": { "d": "md5WithRSAAndTelesecSignatureStandard", "c": "Telesec mechanism", "w": false },
"0.2.262.1.10.1.1.5": { "d": "ripemd160WithRSAAndTelekomSignatureStandard", "c": "Telesec mechanism", "w": false },
"0.2.262.1.10.1.1.9": { "d": "hbciRsaSignature", "c": "Telesec signature", "w": false },
"0.2.262.1.10.1.2": { "d": "encryption", "c": "Telesec mechanism", "w": false },
"0.2.262.1.10.1.2.0": { "d": "none", "c": "Telesec encryption", "w": false },
"0.2.262.1.10.1.2.1": { "d": "rsaTelesec", "c": "Telesec encryption", "w": false },
"0.2.262.1.10.1.2.2": { "d": "des", "c": "Telesec encryption", "w": false },
"0.2.262.1.10.1.2.2.1": { "d": "desECB", "c": "Telesec encryption", "w": false },
"0.2.262.1.10.1.2.2.2": { "d": "desCBC", "c": "Telesec encryption", "w": false },
"0.2.262.1.10.1.2.2.3": { "d": "desOFB", "c": "Telesec encryption", "w": false },
"0.2.262.1.10.1.2.2.4": { "d": "desCFB8", "c": "Telesec encryption", "w": false },
"0.2.262.1.10.1.2.2.5": { "d": "desCFB64", "c": "Telesec encryption", "w": false },
"0.2.262.1.10.1.2.3": { "d": "des3", "c": "Telesec encryption", "w": false },
"0.2.262.1.10.1.2.3.1": { "d": "des3ECB", "c": "Telesec encryption", "w": false },
"0.2.262.1.10.1.2.3.2": { "d": "des3CBC", "c": "Telesec encryption", "w": false },
"0.2.262.1.10.1.2.3.3": { "d": "des3OFB", "c": "Telesec encryption", "w": false },
"0.2.262.1.10.1.2.3.4": { "d": "des3CFB8", "c": "Telesec encryption", "w": false },
"0.2.262.1.10.1.2.3.5": { "d": "des3CFB64", "c": "Telesec encryption", "w": false },
"0.2.262.1.10.1.2.4": { "d": "magenta", "c": "Telesec encryption", "w": false },
"0.2.262.1.10.1.2.5": { "d": "idea", "c": "Telesec encryption", "w": false },
"0.2.262.1.10.1.2.5.1": { "d": "ideaECB", "c": "Telesec encryption", "w": false },
"0.2.262.1.10.1.2.5.2": { "d": "ideaCBC", "c": "Telesec encryption", "w": false },
"0.2.262.1.10.1.2.5.3": { "d": "ideaOFB", "c": "Telesec encryption", "w": false },
"0.2.262.1.10.1.2.5.4": { "d": "ideaCFB8", "c": "Telesec encryption", "w": false },
"0.2.262.1.10.1.2.5.5": { "d": "ideaCFB64", "c": "Telesec encryption", "w": false },
"0.2.262.1.10.1.3": { "d": "oneWayFunction", "c": "Telesec mechanism", "w": false },
"0.2.262.1.10.1.3.1": { "d": "md4", "c": "Telesec one-way function", "w": false },
"0.2.262.1.10.1.3.2": { "d": "md5", "c": "Telesec one-way function", "w": false },
"0.2.262.1.10.1.3.3": { "d": "sqModNX509", "c": "Telesec one-way function", "w": false },
"0.2.262.1.10.1.3.4": { "d": "sqModNISO", "c": "Telesec one-way function", "w": false },
"0.2.262.1.10.1.3.5": { "d": "ripemd128", "c": "Telesec one-way function", "w": false },
"0.2.262.1.10.1.3.6": { "d": "hashUsingBlockCipher", "c": "Telesec one-way function", "w": false },
"0.2.262.1.10.1.3.7": { "d": "mac", "c": "Telesec one-way function", "w": false },
"0.2.262.1.10.1.3.8": { "d": "ripemd160", "c": "Telesec one-way function", "w": false },
"0.2.262.1.10.1.4": { "d": "fecFunction", "c": "Telesec mechanism", "w": false },
"0.2.262.1.10.1.4.1": { "d": "reedSolomon", "c": "Telesec mechanism", "w": false },
"0.2.262.1.10.2": { "d": "module", "c": "Telesec", "w": false },
"0.2.262.1.10.2.0": { "d": "algorithms", "c": "Telesec module", "w": false },
"0.2.262.1.10.2.1": { "d": "attributeTypes", "c": "Telesec module", "w": false },
"0.2.262.1.10.2.2": { "d": "certificateTypes", "c": "Telesec module", "w": false },
"0.2.262.1.10.2.3": { "d": "messageTypes", "c": "Telesec module", "w": false },
"0.2.262.1.10.2.4": { "d": "plProtocol", "c": "Telesec module", "w": false },
"0.2.262.1.10.2.5": { "d": "smeAndComponentsOfSme", "c": "Telesec module", "w": false },
"0.2.262.1.10.2.6": { "d": "fec", "c": "Telesec module", "w": false },
"0.2.262.1.10.2.7": { "d": "usefulDefinitions", "c": "Telesec module", "w": false },
"0.2.262.1.10.2.8": { "d": "stefiles", "c": "Telesec module", "w": false },
"0.2.262.1.10.2.9": { "d": "sadmib", "c": "Telesec module", "w": false },
"0.2.262.1.10.2.10": { "d": "electronicOrder", "c": "Telesec module", "w": false },
"0.2.262.1.10.2.11": { "d": "telesecTtpAsymmetricApplication", "c": "Telesec module", "w": false },
"0.2.262.1.10.2.12": { "d": "telesecTtpBasisApplication", "c": "Telesec module", "w": false },
"0.2.262.1.10.2.13": { "d": "telesecTtpMessages", "c": "Telesec module", "w": false },
"0.2.262.1.10.2.14": { "d": "telesecTtpTimeStampApplication", "c": "Telesec module", "w": false },
"0.2.262.1.10.3": { "d": "objectClass", "c": "Telesec", "w": false },
"0.2.262.1.10.3.0": { "d": "telesecOtherName", "c": "Telesec object class", "w": false },
"0.2.262.1.10.3.1": { "d": "directory", "c": "Telesec object class", "w": false },
"0.2.262.1.10.3.2": { "d": "directoryType", "c": "Telesec object class", "w": false },
"0.2.262.1.10.3.3": { "d": "directoryGroup", "c": "Telesec object class", "w": false },
"0.2.262.1.10.3.4": { "d": "directoryUser", "c": "Telesec object class", "w": false },
"0.2.262.1.10.3.5": { "d": "symmetricKeyEntry", "c": "Telesec object class", "w": false },
"0.2.262.1.10.4": { "d": "package", "c": "Telesec", "w": false },
"0.2.262.1.10.5": { "d": "parameter", "c": "Telesec", "w": false },
"0.2.262.1.10.6": { "d": "nameBinding", "c": "Telesec", "w": false },
"0.2.262.1.10.7": { "d": "attribute", "c": "Telesec", "w": false },
"0.2.262.1.10.7.0": { "d": "applicationGroupIdentifier", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.1": { "d": "certificateType", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.2": { "d": "telesecCertificate", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.3": { "d": "certificateNumber", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.4": { "d": "certificateRevocationList", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.5": { "d": "creationDate", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.6": { "d": "issuer", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.7": { "d": "namingAuthority", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.8": { "d": "publicKeyDirectory", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.9": { "d": "securityDomain", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.10": { "d": "subject", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.11": { "d": "timeOfRevocation", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.12": { "d": "userGroupReference", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.13": { "d": "validity", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.14": { "d": "zert93", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.15": { "d": "securityMessEnv", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.16": { "d": "anonymizedPublicKeyDirectory", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.17": { "d": "telesecGivenName", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.18": { "d": "nameAdditions", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.19": { "d": "telesecPostalCode", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.20": { "d": "nameDistinguisher", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.21": { "d": "telesecCertificateList", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.22": { "d": "teletrustCertificateList", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.23": { "d": "x509CertificateList", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.24": { "d": "timeOfIssue", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.25": { "d": "physicalCardNumber", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.26": { "d": "fileType", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.27": { "d": "ctlFileIsArchive", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.28": { "d": "emailAddress", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.29": { "d": "certificateTemplateList", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.30": { "d": "directoryName", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.31": { "d": "directoryTypeName", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.32": { "d": "directoryGroupName", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.33": { "d": "directoryUserName", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.34": { "d": "revocationFlag", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.35": { "d": "symmetricKeyEntryName", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.36": { "d": "glNumber", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.37": { "d": "goNumber", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.38": { "d": "gKeyData", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.39": { "d": "zKeyData", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.40": { "d": "ktKeyData", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.41": { "d": "ktKeyNumber", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.51": { "d": "timeOfRevocationGen", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.7.52": { "d": "liabilityText", "c": "Telesec attribute", "w": false },
"0.2.262.1.10.8": { "d": "attributeGroup", "c": "Telesec", "w": false },
"0.2.262.1.10.9": { "d": "action", "c": "Telesec", "w": false },
"0.2.262.1.10.10": { "d": "notification", "c": "Telesec", "w": false },
"0.2.262.1.10.11": { "d": "snmp-mibs", "c": "Telesec", "w": false },
"0.2.262.1.10.11.1": { "d": "securityApplication", "c": "Telesec SNMP MIBs", "w": false },
"0.2.262.1.10.12": { "d": "certAndCrlExtensionDefinitions", "c": "Telesec", "w": false },
"0.2.262.1.10.12.0": { "d": "liabilityLimitationFlag", "c": "Telesec cert/CRL extension", "w": false },
"0.2.262.1.10.12.1": { "d": "telesecCertIdExt", "c": "Telesec cert/CRL extension", "w": false },
"0.2.262.1.10.12.2": { "d": "Telesec policyIdentifier", "c": "Telesec cert/CRL extension", "w": false },
"0.2.262.1.10.12.3": { "d": "telesecPolicyQualifierID", "c": "Telesec cert/CRL extension", "w": false },
"0.2.262.1.10.12.4": { "d": "telesecCRLFilteredExt", "c": "Telesec cert/CRL extension", "w": false },
"0.2.262.1.10.12.5": { "d": "telesecCRLFilterExt", "c": "Telesec cert/CRL extension", "w": false },
"0.2.262.1.10.12.6": { "d": "telesecNamingAuthorityExt", "c": "Telesec cert/CRL extension", "w": false },
"0.4.0.127.0.7": { "d": "bsi", "c": "BSI TR-03110/TR-03111", "w": false },
"0.4.0.127.0.7.1": { "d": "bsiEcc", "c": "BSI TR-03111", "w": false },
"0.4.0.127.0.7.1.1": { "d": "bsifieldType", "c": "BSI TR-03111", "w": false },
"0.4.0.127.0.7.1.1.1": { "d": "bsiPrimeField", "c": "BSI TR-03111", "w": false },
"0.4.0.127.0.7.1.1.2": { "d": "bsiCharacteristicTwoField", "c": "BSI TR-03111", "w": false },
"0.4.0.127.0.7.1.1.2.3": { "d": "bsiCharacteristicTwoBasis", "c": "BSI TR-03111", "w": false },
"0.4.0.127.0.7.1.1.2.3.1": { "d": "bsiGnBasis", "c": "BSI TR-03111", "w": false },
"0.4.0.127.0.7.1.1.2.3.2": { "d": "bsiTpBasis", "c": "BSI TR-03111", "w": false },
"0.4.0.127.0.7.1.1.2.3.3": { "d": "bsiPpBasis", "c": "BSI TR-03111", "w": false },
"0.4.0.127.0.7.1.1.4.1": { "d": "bsiEcdsaSignatures", "c": "BSI TR-03111", "w": false },
"0.4.0.127.0.7.1.1.4.1.1": { "d": "bsiEcdsaWithSHA1", "c": "BSI TR-03111", "w": false },
"0.4.0.127.0.7.1.1.4.1.2": { "d": "bsiEcdsaWithSHA224", "c": "BSI TR-03111", "w": false },
"0.4.0.127.0.7.1.1.4.1.3": { "d": "bsiEcdsaWithSHA256", "c": "BSI TR-03111", "w": false },
"0.4.0.127.0.7.1.1.4.1.4": { "d": "bsiEcdsaWithSHA384", "c": "BSI TR-03111", "w": false },
"0.4.0.127.0.7.1.1.4.1.5": { "d": "bsiEcdsaWithSHA512", "c": "BSI TR-03111", "w": false },
"0.4.0.127.0.7.1.1.4.1.6": { "d": "bsiEcdsaWithRIPEMD160", "c": "BSI TR-03111", "w": false },
"0.4.0.127.0.7.1.2": { "d": "bsiEcKeyType", "c": "BSI TR-03111", "w": false },
"0.4.0.127.0.7.1.2.1": { "d": "bsiEcPublicKey", "c": "BSI TR-03111", "w": false },
"0.4.0.127.0.7.1.5.1": { "d": "bsiKaeg", "c": "BSI TR-03111", "w": false },
"0.4.0.127.0.7.1.5.1.1": { "d": "bsiKaegWithX963KDF", "c": "BSI TR-03111", "w": false },
"0.4.0.127.0.7.1.5.1.2": { "d": "bsiKaegWith3DESKDF", "c": "BSI TR-03111", "w": false },
"0.4.0.127.0.7.2.2.1": { "d": "bsiPK", "c": "BSI TR-03110. Formerly known as bsiCA, now moved to ...2.2.3.x", "w": false },
"0.4.0.127.0.7.2.2.1.1": { "d": "bsiPK_DH", "c": "BSI TR-03110. Formerly known as bsiCA_DH, now moved to ...2.2.3.x", "w": false },
"0.4.0.127.0.7.2.2.1.2": { "d": "bsiPK_ECDH", "c": "BSI TR-03110. Formerly known as bsiCA_ECDH, now moved to ...2.2.3.x", "w": false },
"0.4.0.127.0.7.2.2.2": { "d": "bsiTA", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.2.1": { "d": "bsiTA_RSA", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.2.1.1": { "d": "bsiTA_RSAv1_5_SHA1", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.2.1.2": { "d": "bsiTA_RSAv1_5_SHA256", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.2.1.3": { "d": "bsiTA_RSAPSS_SHA1", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.2.1.4": { "d": "bsiTA_RSAPSS_SHA256", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.2.2": { "d": "bsiTA_ECDSA", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.2.2.1": { "d": "bsiTA_ECDSA_SHA1", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.2.2.2": { "d": "bsiTA_ECDSA_SHA224", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.2.2.3": { "d": "bsiTA_ECDSA_SHA256", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.3": { "d": "bsiCA", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.3.1": { "d": "bsiCA_DH", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.2.2.3.2": { "d": "bsiCA_ECDH", "c": "BSI TR-03110", "w": false },
"0.4.0.127.0.7.3.1.2.1": { "d": "bsiRoleEAC", "c": "BSI TR-03110", "w": false },
"0.4.0.1862": { "d": "etsiQcsProfile", "c": "ETSI TS 101 862 qualified certificates", "w": false },
"0.4.0.1862.1": { "d": "etsiQcs", "c": "ETSI TS 101 862 qualified certificates", "w": false },
"0.4.0.1862.1.1": { "d": "etsiQcsCompliance", "c": "ETSI TS 101 862 qualified certificates", "w": false },
"0.4.0.1862.1.2": { "d": "etsiQcsLimitValue", "c": "ETSI TS 101 862 qualified certificates", "w": false },
"0.4.0.1862.1.3": { "d": "etsiQcsRetentionPeriod", "c": "ETSI TS 101 862 qualified certificates", "w": false },
"0.4.0.1862.1.4": { "d": "etsiQcsQcSSCD", "c": "ETSI TS 101 862 qualified certificates", "w": false },
"0.9.2342.19200300.100.1.1": { "d": "userID", "c": "Some oddball X.500 attribute collection", "w": false },
"0.9.2342.19200300.100.1.3": { "d": "rfc822Mailbox", "c": "Some oddball X.500 attribute collection", "w": false },
"0.9.2342.19200300.100.1.25": { "d": "domainComponent", "c": "Men are from Mars, this OID is from Pluto", "w": false },
"1.0.10118.3.0.49": { "d": "ripemd160", "c": "ISO 10118-3 hash function", "w": false },
"1.0.10118.3.0.50": { "d": "ripemd128", "c": "ISO 10118-3 hash function", "w": false },
"1.0.10118.3.0.55": { "d": "whirlpool", "c": "ISO 10118-3 hash function", "w": false },
"1.2.36.1.333.1": { "d": "australianBusinessNumber", "c": "Australian Government corporate taxpayer ID", "w": false },
"1.2.36.75878867.1.100.1.1": { "d": "Certificates Australia policyIdentifier", "c": "Certificates Australia CA", "w": false },
"1.2.36.68980861.1.1.2": { "d": "Signet personal", "c": "Signet CA", "w": false },
"1.2.36.68980861.1.1.3": { "d": "Signet business", "c": "Signet CA", "w": false },
"1.2.36.68980861.1.1.4": { "d": "Signet legal", "c": "Signet CA", "w": false },
"1.2.36.68980861.1.1.10": { "d": "Signet pilot", "c": "Signet CA", "w": false },
"1.2.36.68980861.1.1.11": { "d": "Signet intraNet", "c": "Signet CA", "w": false },
"1.2.36.68980861.1.1.20": { "d": "Signet policyIdentifier", "c": "Signet CA", "w": false },
"1.2.392.200011.61.1.1.1": { "d": "symmetric-encryption-algorithm", "c": "Mitsubishi security algorithm", "w": false },
"1.2.392.200011.61.1.1.1.1": { "d": "misty1-cbc", "c": "Mitsubishi security algorithm", "w": false },
"1.2.752.34.1": { "d": "seis-cp", "c": "SEIS Project", "w": false },
"1.2.752.34.1.1": { "d": "SEIS high-assurance policyIdentifier", "c": "SEIS Project certificate policies", "w": false },
"1.2.752.34.1.2": { "d": "SEIS GAK policyIdentifier", "c": "SEIS Project certificate policies", "w": false },
"1.2.752.34.2": { "d": "SEIS pe", "c": "SEIS Project", "w": false },
"1.2.752.34.3": { "d": "SEIS at", "c": "SEIS Project", "w": false },
"1.2.752.34.3.1": { "d": "SEIS at-personalIdentifier", "c": "SEIS Project attribute", "w": false },
"1.2.840.10040.1": { "d": "module", "c": "ANSI X9.57", "w": false },
"1.2.840.10040.1.1": { "d": "x9f1-cert-mgmt", "c": "ANSI X9.57 module", "w": false },
"1.2.840.10040.2": { "d": "holdinstruction", "c": "ANSI X9.57", "w": false },
"1.2.840.10040.2.1": { "d": "holdinstruction-none", "c": "ANSI X9.57 hold instruction", "w": false },
"1.2.840.10040.2.2": { "d": "callissuer", "c": "ANSI X9.57 hold instruction", "w": false },
"1.2.840.10040.2.3": { "d": "reject", "c": "ANSI X9.57 hold instruction", "w": false },
"1.2.840.10040.2.4": { "d": "pickupToken", "c": "ANSI X9.57 hold instruction", "w": false },
"1.2.840.10040.3": { "d": "attribute", "c": "ANSI X9.57", "w": false },
"1.2.840.10040.3.1": { "d": "countersignature", "c": "ANSI X9.57 attribute", "w": false },
"1.2.840.10040.3.2": { "d": "attribute-cert", "c": "ANSI X9.57 attribute", "w": false },
"1.2.840.10040.4": { "d": "algorithm", "c": "ANSI X9.57", "w": false },
"1.2.840.10040.4.1": { "d": "dsa", "c": "ANSI X9.57 algorithm", "w": false },
"1.2.840.10040.4.2": { "d": "dsa-match", "c": "ANSI X9.57 algorithm", "w": false },
"1.2.840.10040.4.3": { "d": "dsaWithSha1", "c": "ANSI X9.57 algorithm", "w": false },
"1.2.840.10045.1": { "d": "fieldType", "c": "ANSI X9.62. This OID is also assigned as ecdsa-with-SHA1", "w": false },
"1.2.840.10045.1.1": { "d": "prime-field", "c": "ANSI X9.62 field type", "w": false },
"1.2.840.10045.1.2": { "d": "characteristic-two-field", "c": "ANSI X9.62 field type", "w": false },
"1.2.840.10045.1.2.3": { "d": "characteristic-two-basis", "c": "ANSI X9.62 field type", "w": false },
"1.2.840.10045.1.2.3.1": { "d": "onBasis", "c": "ANSI X9.62 field basis", "w": false },
"1.2.840.10045.1.2.3.2": { "d": "tpBasis", "c": "ANSI X9.62 field basis", "w": false },
"1.2.840.10045.1.2.3.3": { "d": "ppBasis", "c": "ANSI X9.62 field basis", "w": false },
"1.2.840.10045.2": { "d": "publicKeyType", "c": "ANSI X9.62", "w": false },
"1.2.840.10045.2": { "d": "ecPublicKey x", "c": "ANSI X9.62 public key type", "w": false },
"1.2.840.10045.3.0.1": { "d": "c2pnb163v1", "c": "ANSI X9.62 named elliptic curve", "w": false },
"1.2.840.10045.3.0.2": { "d": "c2pnb163v2", "c": "ANSI X9.62 named elliptic curve", "w": false },
"1.2.840.10045.3.0.3": { "d": "c2pnb163v3", "c": "ANSI X9.62 named elliptic curve", "w": false },
"1.2.840.10045.3.0.5": { "d": "c2tnb191v1", "c": "ANSI X9.62 named elliptic curve", "w": false },
"1.2.840.10045.3.0.6": { "d": "c2tnb191v2", "c": "ANSI X9.62 named elliptic curve", "w": false },
"1.2.840.10045.3.0.7": { "d": "c2tnb191v3", "c": "ANSI X9.62 named elliptic curve", "w": false },
"1.2.840.10045.3.0.10": { "d": "c2pnb208w1", "c": "ANSI X9.62 named elliptic curve", "w": false },
"1.2.840.10045.3.0.11": { "d": "c2tnb239v1", "c": "ANSI X9.62 named elliptic curve", "w": false },
"1.2.840.10045.3.0.12": { "d": "c2tnb239v2", "c": "ANSI X9.62 named elliptic curve", "w": false },
"1.2.840.10045.3.0.13": { "d": "c2tnb239v3", "c": "ANSI X9.62 named elliptic curve", "w": false },
"1.2.840.10045.3.0.16": { "d": "c2pnb272w1", "c": "ANSI X9.62 named elliptic curve", "w": false },
"1.2.840.10045.3.0.18": { "d": "c2tnb359v1", "c": "ANSI X9.62 named elliptic curve", "w": false },
"1.2.840.10045.3.0.19": { "d": "c2pnb368w1", "c": "ANSI X9.62 named elliptic curve", "w": false },
"1.2.840.10045.3.0.20": { "d": "c2tnb431r1", "c": "ANSI X9.62 named elliptic curve", "w": false },
"1.2.840.10045.3.1.1": { "d": "ansiX9p192r1", "c": "ANSI X9.62 named elliptic curve", "w": false },
"1.2.840.10045.3.1.1.1": { "d": "prime192v1", "c": "ANSI X9.62 named elliptic curve", "w": false },
"1.2.840.10045.3.1.1.2": { "d": "prime192v2", "c": "ANSI X9.62 named elliptic curve", "w": false },
"1.2.840.10045.3.1.1.3": { "d": "prime192v3", "c": "ANSI X9.62 named elliptic curve", "w": false },
"1.2.840.10045.3.1.1.4": { "d": "prime239v1", "c": "ANSI X9.62 named elliptic curve", "w": false },
"1.2.840.10045.3.1.1.5": { "d": "prime239v2", "c": "ANSI X9.62 named elliptic curve", "w": false },
"1.2.840.10045.3.1.1.6": { "d": "prime239v3", "c": "ANSI X9.62 named elliptic curve", "w": false },
"1.2.840.10045.3.1.1.7": { "d": "prime256v1", "c": "ANSI X9.62 named elliptic curve", "w": false },
"1.2.840.10045.3.1.7": { "d": "ansiX9p256r1", "c": "ANSI X9.62 named elliptic curve", "w": false },
"1.2.840.10045.4.1": { "d": "ecdsaWithSHA1", "c": "ANSI X9.62 ECDSA algorithm with SHA1", "w": false },
"1.2.840.10045.4.2": { "d": "ecdsaWithRecommended", "c": "ANSI X9.62 ECDSA algorithm with Recommended", "w": false },
"1.2.840.10045.4.3": { "d": "ecdsaWithSpecified", "c": "ANSI X9.62 ECDSA algorithm with Specified", "w": false },
"1.2.840.10045.4.3.1": { "d": "ecdsaWithSHA224", "c": "ANSI X9.62 ECDSA algorithm with SHA224", "w": false },
"1.2.840.10045.4.3.2": { "d": "ecdsaWithSHA256", "c": "ANSI X9.62 ECDSA algorithm with SHA256", "w": false },
"1.2.840.10045.4.3.3": { "d": "ecdsaWithSHA384", "c": "ANSI X9.62 ECDSA algorithm with SHA384", "w": false },
"1.2.840.10045.4.3.4": { "d": "ecdsaWithSHA512", "c": "ANSI X9.62 ECDSA algorithm with SHA512", "w": false },
"1.2.840.10046.1": { "d": "fieldType", "c": "ANSI X9.42", "w": false },
"1.2.840.10046.1.1": { "d": "gf-prime", "c": "ANSI X9.42 field type", "w": false },
"1.2.840.10046.2": { "d": "numberType", "c": "ANSI X9.42", "w": false },
"1.2.840.10046.2.1": { "d": "dhPublicKey", "c": "ANSI X9.42 number type", "w": false },
"1.2.840.10046.3": { "d": "scheme", "c": "ANSI X9.42", "w": false },
"1.2.840.10046.3.1": { "d": "dhStatic", "c": "ANSI X9.42 scheme", "w": false },
"1.2.840.10046.3.2": { "d": "dhEphem", "c": "ANSI X9.42 scheme", "w": false },
"1.2.840.10046.3.3": { "d": "dhHybrid1", "c": "ANSI X9.42 scheme", "w": false },
"1.2.840.10046.3.4": { "d": "dhHybrid2", "c": "ANSI X9.42 scheme", "w": false },
"1.2.840.10046.3.5": { "d": "mqv2", "c": "ANSI X9.42 scheme", "w": false },
"1.2.840.10046.3.6": { "d": "mqv1", "c": "ANSI X9.42 scheme", "w": false },
"1.2.840.10065.2.2": { "d": "?", "c": "ASTM 31.20", "w": false },
"1.2.840.10065.2.3": { "d": "healthcareLicense", "c": "ASTM 31.20", "w": false },
"1.2.840.10065.2.3.1.1": { "d": "license?", "c": "ASTM 31.20 healthcare license type", "w": false },
"1.2.840.113533.7": { "d": "nsn", "c": "", "w": false },
"1.2.840.113533.7.65": { "d": "nsn-ce", "c": "", "w": false },
"1.2.840.113533.7.65.0": { "d": "entrustVersInfo", "c": "Nortel Secure Networks ce", "w": false },
"1.2.840.113533.7.66": { "d": "nsn-alg", "c": "", "w": false },
"1.2.840.113533.7.66.3": { "d": "cast3CBC", "c": "Nortel Secure Networks alg", "w": false },
"1.2.840.113533.7.66.10": { "d": "cast5CBC", "c": "Nortel Secure Networks alg", "w": false },
"1.2.840.113533.7.66.11": { "d": "cast5MAC", "c": "Nortel Secure Networks alg", "w": false },
"1.2.840.113533.7.66.12": { "d": "pbeWithMD5AndCAST5-CBC", "c": "Nortel Secure Networks alg", "w": false },
"1.2.840.113533.7.66.13": { "d": "passwordBasedMac", "c": "Nortel Secure Networks alg", "w": false },
"1.2.840.113533.7.67": { "d": "nsn-oc", "c": "", "w": false },
"1.2.840.113533.7.67.0": { "d": "entrustUser", "c": "Nortel Secure Networks oc", "w": false },
"1.2.840.113533.7.68": { "d": "nsn-at", "c": "", "w": false },
"1.2.840.113533.7.68.0": { "d": "entrustCAInfo", "c": "Nortel Secure Networks at", "w": false },
"1.2.840.113533.7.68.10": { "d": "attributeCertificate", "c": "Nortel Secure Networks at", "w": false },
"1.2.840.113549.1.1": { "d": "pkcs-1", "c": "", "w": false },
"1.2.840.113549.1.1.1": { "d": "rsaEncryption", "c": "PKCS #1", "w": false },
"1.2.840.113549.1.1.2": { "d": "md2withRSAEncryption", "c": "PKCS #1", "w": false },
"1.2.840.113549.1.1.3": { "d": "md4withRSAEncryption", "c": "PKCS #1", "w": false },
"1.2.840.113549.1.1.4": { "d": "md5withRSAEncryption", "c": "PKCS #1", "w": false },
"1.2.840.113549.1.1.5": { "d": "sha1withRSAEncryption", "c": "PKCS #1", "w": false },
"1.2.840.113549.1.1.7": { "d": "rsaOAEP", "c": "PKCS #1", "w": false },
"1.2.840.113549.1.1.8": { "d": "pkcs1-MGF", "c": "PKCS #1", "w": false },
"1.2.840.113549.1.1.9": { "d": "rsaOAEP-pSpecified", "c": "PKCS #1", "w": false },
"1.2.840.113549.1.1.10": { "d": "rsaPSS", "c": "PKCS #1", "w": false },
"1.2.840.113549.1.1.11": { "d": "sha256WithRSAEncryption", "c": "PKCS #1", "w": false },
"1.2.840.113549.1.1.12": { "d": "sha384WithRSAEncryption", "c": "PKCS #1", "w": false },
"1.2.840.113549.1.1.13": { "d": "sha512WithRSAEncryption", "c": "PKCS #1", "w": false },
"1.2.840.113549.1.1.14": { "d": "sha224WithRSAEncryption", "c": "PKCS #1", "w": false },
"1.2.840.113549.1.1.6": { "d": "rsaOAEPEncryptionSET", "c": "PKCS #1. This OID may also be assigned as ripemd160WithRSAEncryption", "w": false },
"1.2.840.113549.1.2": { "d": "bsafeRsaEncr", "c": "Obsolete BSAFE OID", "w": true },
"1.2.840.113549.1.3": { "d": "pkcs-3", "c": "", "w": false },
"1.2.840.113549.1.3.1": { "d": "dhKeyAgreement", "c": "PKCS #3", "w": false },
"1.2.840.113549.1.5": { "d": "pkcs-5", "c": "", "w": false },
"1.2.840.113549.1.5.1": { "d": "pbeWithMD2AndDES-CBC", "c": "PKCS #5", "w": false },
"1.2.840.113549.1.5.3": { "d": "pbeWithMD5AndDES-CBC", "c": "PKCS #5", "w": false },
"1.2.840.113549.1.5.4": { "d": "pbeWithMD2AndRC2-CBC", "c": "PKCS #5", "w": false },
"1.2.840.113549.1.5.6": { "d": "pbeWithMD5AndRC2-CBC", "c": "PKCS #5", "w": false },
"1.2.840.113549.1.5.9": { "d": "pbeWithMD5AndXOR", "c": "PKCS #5, used in BSAFE only", "w": true },
"1.2.840.113549.1.5.10": { "d": "pbeWithSHAAndDES-CBC", "c": "PKCS #5", "w": false },
"1.2.840.113549.1.5.12": { "d": "pkcs5PBKDF2", "c": "PKCS #5 v2.0", "w": false },
"1.2.840.113549.1.5.13": { "d": "pkcs5PBES2", "c": "PKCS #5 v2.0", "w": false },
"1.2.840.113549.1.5.14": { "d": "pkcs5PBMAC1", "c": "PKCS #5 v2.0", "w": false },
"1.2.840.113549.1.7": { "d": "pkcs-7", "c": "", "w": false },
"1.2.840.113549.1.7.1": { "d": "data", "c": "PKCS #7", "w": false },
"1.2.840.113549.1.7.2": { "d": "signedData", "c": "PKCS #7", "w": false },
"1.2.840.113549.1.7.3": { "d": "envelopedData", "c": "PKCS #7", "w": false },
"1.2.840.113549.1.7.4": { "d": "signedAndEnvelopedData", "c": "PKCS #7", "w": false },
"1.2.840.113549.1.7.5": { "d": "digestedData", "c": "PKCS #7", "w": false },
"1.2.840.113549.1.7.6": { "d": "encryptedData", "c": "PKCS #7", "w": false },
"1.2.840.113549.1.7.7": { "d": "dataWithAttributes", "c": "PKCS #7 experimental", "w": true },
"1.2.840.113549.1.7.8": { "d": "encryptedPrivateKeyInfo", "c": "PKCS #7 experimental", "w": true },
"1.2.840.113549.1.9": { "d": "pkcs-9", "c": "", "w": false },
"1.2.840.113549.1.9.1": { "d": "emailAddress", "c": "PKCS #9. Deprecated, use an altName extension instead", "w": false },
"1.2.840.113549.1.9.2": { "d": "unstructuredName", "c": "PKCS #9", "w": false },
"1.2.840.113549.1.9.3": { "d": "contentType", "c": "PKCS #9", "w": false },
"1.2.840.113549.1.9.4": { "d": "messageDigest", "c": "PKCS #9", "w": false },
"1.2.840.113549.1.9.5": { "d": "signingTime", "c": "PKCS #9", "w": false },
"1.2.840.113549.1.9.6": { "d": "countersignature", "c": "PKCS #9", "w": false },
"1.2.840.113549.1.9.7": { "d": "challengePassword", "c": "PKCS #9", "w": false },
"1.2.840.113549.1.9.8": { "d": "unstructuredAddress", "c": "PKCS #9", "w": false },
"1.2.840.113549.1.9.9": { "d": "extendedCertificateAttributes", "c": "PKCS #9", "w": false },
"1.2.840.113549.1.9.10": { "d": "issuerAndSerialNumber", "c": "PKCS #9 experimental", "w": true },
"1.2.840.113549.1.9.11": { "d": "passwordCheck", "c": "PKCS #9 experimental", "w": true },
"1.2.840.113549.1.9.12": { "d": "publicKey", "c": "PKCS #9 experimental", "w": true },
"1.2.840.113549.1.9.13": { "d": "signingDescription", "c": "PKCS #9", "w": false },
"1.2.840.113549.1.9.14": { "d": "extensionRequest", "c": "PKCS #9 via CRMF", "w": false },
"1.2.840.113549.1.9.15": { "d": "sMIMECapabilities", "c": "PKCS #9. This OID was formerly assigned as symmetricCapabilities, then reassigned as SMIMECapabilities, then renamed to the current name", "w": false },
"1.2.840.113549.1.9.15.1": { "d": "preferSignedData", "c": "sMIMECapabilities", "w": false },
"1.2.840.113549.1.9.15.2": { "d": "canNotDecryptAny", "c": "sMIMECapabilities", "w": false },
"1.2.840.113549.1.9.15.3": { "d": "receiptRequest", "c": "sMIMECapabilities. Deprecated, use (1 2 840 113549 1 9 16 2 1) instead", "w": true },
"1.2.840.113549.1.9.15.4": { "d": "receipt", "c": "sMIMECapabilities. Deprecated, use (1 2 840 113549 1 9 16 1 1) instead", "w": true },
"1.2.840.113549.1.9.15.5": { "d": "contentHints", "c": "sMIMECapabilities. Deprecated, use (1 2 840 113549 1 9 16 2 4) instead", "w": true },
"1.2.840.113549.1.9.15.6": { "d": "mlExpansionHistory", "c": "sMIMECapabilities. Deprecated, use (1 2 840 113549 1 9 16 2 3) instead", "w": true },
"1.2.840.113549.1.9.16": { "d": "id-sMIME", "c": "PKCS #9", "w": false },
"1.2.840.113549.1.9.16.0": { "d": "id-mod", "c": "id-sMIME", "w": false },
"1.2.840.113549.1.9.16.0.1": { "d": "id-mod-cms", "c": "S/MIME Modules", "w": false },
"1.2.840.113549.1.9.16.0.2": { "d": "id-mod-ess", "c": "S/MIME Modules", "w": false },
"1.2.840.113549.1.9.16.0.3": { "d": "id-mod-oid", "c": "S/MIME Modules", "w": false },
"1.2.840.113549.1.9.16.0.4": { "d": "id-mod-msg-v3", "c": "S/MIME Modules", "w": false },
"1.2.840.113549.1.9.16.0.5": { "d": "id-mod-ets-eSignature-88", "c": "S/MIME Modules", "w": false },
"1.2.840.113549.1.9.16.0.6": { "d": "id-mod-ets-eSignature-97", "c": "S/MIME Modules", "w": false },
"1.2.840.113549.1.9.16.0.7": { "d": "id-mod-ets-eSigPolicy-88", "c": "S/MIME Modules", "w": false },
"1.2.840.113549.1.9.16.0.8": { "d": "id-mod-ets-eSigPolicy-88", "c": "S/MIME Modules", "w": false },
"1.2.840.113549.1.9.16.1": { "d": "contentType", "c": "S/MIME", "w": false },
"1.2.840.113549.1.9.16.1.1": { "d": "receipt", "c": "S/MIME Content Types", "w": false },
"1.2.840.113549.1.9.16.1.2": { "d": "authData", "c": "S/MIME Content Types", "w": false },
"1.2.840.113549.1.9.16.1.3": { "d": "publishCert", "c": "S/MIME Content Types", "w": false },
"1.2.840.113549.1.9.16.1.4": { "d": "tSTInfo", "c": "S/MIME Content Types", "w": false },
"1.2.840.113549.1.9.16.1.5": { "d": "tDTInfo", "c": "S/MIME Content Types", "w": false },
"1.2.840.113549.1.9.16.1.6": { "d": "contentInfo", "c": "S/MIME Content Types", "w": false },
"1.2.840.113549.1.9.16.1.7": { "d": "dVCSRequestData", "c": "S/MIME Content Types", "w": false },
"1.2.840.113549.1.9.16.1.8": { "d": "dVCSResponseData", "c": "S/MIME Content Types", "w": false },
"1.2.840.113549.1.9.16.1.9": { "d": "compressedData", "c": "S/MIME Content Types", "w": false },
"1.2.840.113549.1.9.16.1.16": { "d": "firmwarePackage", "c": "S/MIME Content Types", "w": false },
"1.2.840.113549.1.9.16.1.17": { "d": "firmwareLoadReceipt", "c": "S/MIME Content Types", "w": false },
"1.2.840.113549.1.9.16.1.18": { "d": "firmwareLoadError", "c": "S/MIME Content Types", "w": false },
"1.2.840.113549.1.9.16.2": { "d": "authenticatedAttributes", "c": "S/MIME", "w": false },
"1.2.840.113549.1.9.16.2.1": { "d": "receiptRequest", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.2": { "d": "securityLabel", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.3": { "d": "mlExpandHistory", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.4": { "d": "contentHint", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.5": { "d": "msgSigDigest", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.6": { "d": "encapContentType", "c": "S/MIME Authenticated Attributes.  Obsolete", "w": true },
"1.2.840.113549.1.9.16.2.7": { "d": "contentIdentifier", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.8": { "d": "macValue", "c": "S/MIME Authenticated Attributes.  Obsolete", "w": true },
"1.2.840.113549.1.9.16.2.9": { "d": "equivalentLabels", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.10": { "d": "contentReference", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.11": { "d": "encrypKeyPref", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.12": { "d": "signingCertificate", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.13": { "d": "smimeEncryptCerts", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.14": { "d": "timeStampToken", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.15": { "d": "sigPolicyId", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.16": { "d": "commitmentType", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.17": { "d": "signerLocation", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.18": { "d": "signerAttr", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.19": { "d": "otherSigCert", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.20": { "d": "contentTimestamp", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.21": { "d": "certificateRefs", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.22": { "d": "revocationRefs", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.23": { "d": "certValues", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.24": { "d": "revocationValues", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.25": { "d": "escTimeStamp", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.26": { "d": "certCRLTimestamp", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.27": { "d": "archiveTimeStamp", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.28": { "d": "signatureType", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.29": { "d": "dvcs-dvc", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.35": { "d": "fwPackageID", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.36": { "d": "fwTargetHardwareIDs", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.37": { "d": "fwDecryptKeyID", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.38": { "d": "fwImplCryptAlgs", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.39": { "d": "fwWrappedFirmwareKey", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.40": { "d": "fwCommunityIdentifiers", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.42": { "d": "fwPackageInfo", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.43": { "d": "fwImplCompressAlgs", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.2.47": { "d": "signingCertificateV2", "c": "S/MIME Authenticated Attributes", "w": false },
"1.2.840.113549.1.9.16.3.1": { "d": "algESDHwith3DES", "c": "S/MIME Algorithms. Obsolete", "w": true },
"1.2.840.113549.1.9.16.3.2": { "d": "algESDHwithRC2", "c": "S/MIME Algorithms. Obsolete", "w": true },
"1.2.840.113549.1.9.16.3.3": { "d": "alg3DESwrap", "c": "S/MIME Algorithms. Obsolete", "w": true },
"1.2.840.113549.1.9.16.3.4": { "d": "algRC2wrap", "c": "S/MIME Algorithms. Obsolete", "w": true },
"1.2.840.113549.1.9.16.3.5": { "d": "esDH", "c": "S/MIME Algorithms", "w": false },
"1.2.840.113549.1.9.16.3.6": { "d": "cms3DESwrap", "c": "S/MIME Algorithms", "w": false },
"1.2.840.113549.1.9.16.3.7": { "d": "cmsRC2wrap", "c": "S/MIME Algorithms", "w": false },
"1.2.840.113549.1.9.16.3.8": { "d": "zlib", "c": "S/MIME Algorithms", "w": false },
"1.2.840.113549.1.9.16.3.9": { "d": "pwri-KEK", "c": "S/MIME Algorithms", "w": false },
"1.2.840.113549.1.9.16.4.1": { "d": "certDist-ldap", "c": "S/MIME Certificate Distribution", "w": false },
"1.2.840.113549.1.9.16.4.1": { "d": "sigPolicyQualifier-spuri x", "c": "S/MIME Signature Policy Qualifier", "w": false },
"1.2.840.113549.1.9.16.5.2": { "d": "sigPolicyQualifier-spUserNotice", "c": "S/MIME Signature Policy Qualifier", "w": false },
"1.2.840.113549.1.9.16.6.1": { "d": "proofOfOrigin", "c": "S/MIME", "w": false },
"1.2.840.113549.1.9.16.6.2": { "d": "proofOfReceipt", "c": "S/MIME", "w": false },
"1.2.840.113549.1.9.16.6.3": { "d": "proofOfDelivery", "c": "S/MIME", "w": false },
"1.2.840.113549.1.9.16.6.4": { "d": "proofOfSender", "c": "S/MIME", "w": false },
"1.2.840.113549.1.9.16.6.5": { "d": "proofOfApproval", "c": "S/MIME", "w": false },
"1.2.840.113549.1.9.16.6.6": { "d": "proofOfCreation", "c": "S/MIME", "w": false },
"1.2.840.113549.1.9.15": { "d": "sMIMECapabilities", "c": "PKCS #9. This OID was formerly assigned as symmetricCapabilities, then reassigned as SMIMECapabilities, then renamed to the current name", "w": false },
"1.2.840.113549.1.9.16.9": { "d": "signatureTypeIdentifier", "c": "S/MIME", "w": false },
"1.2.840.113549.1.9.16.9.1": { "d": "originatorSig", "c": "S/MIME Signature Type Identifier", "w": false },
"1.2.840.113549.1.9.16.9.2": { "d": "domainSig", "c": "S/MIME Signature Type Identifier", "w": false },
"1.2.840.113549.1.9.16.9.3": { "d": "additionalAttributesSig", "c": "S/MIME Signature Type Identifier", "w": false },
"1.2.840.113549.1.9.16.9.4": { "d": "reviewSig", "c": "S/MIME Signature Type Identifier", "w": false },
"1.2.840.113549.1.9.16.11": { "d": "capabilities", "c": "S/MIME", "w": false },
"1.2.840.113549.1.9.16.11.1": { "d": "preferBinaryInside", "c": "S/MIME Capability", "w": false },
"1.2.840.113549.1.9.20": { "d": "friendlyName (for PKCS #12)", "c": "PKCS #9 via PKCS #12", "w": false },
"1.2.840.113549.1.9.21": { "d": "localKeyID (for PKCS #12)", "c": "PKCS #9 via PKCS #12", "w": false },
"1.2.840.113549.1.9.22": { "d": "certTypes (for PKCS #12)", "c": "PKCS #9 via PKCS #12", "w": false },
"1.2.840.113549.1.9.22.1": { "d": "x509Certificate (for PKCS #12)", "c": "PKCS #9 via PKCS #12", "w": false },
"1.2.840.113549.1.9.22.2": { "d": "sdsiCertificate (for PKCS #12)", "c": "PKCS #9 via PKCS #12", "w": false },
"1.2.840.113549.1.9.23": { "d": "crlTypes (for PKCS #12)", "c": "PKCS #9 via PKCS #12", "w": false },
"1.2.840.113549.1.9.23.1": { "d": "x509Crl (for PKCS #12)", "c": "PKCS #9 via PKCS #12", "w": false },
"1.2.840.113549.1.9.24": { "d": "pkcs9objectClass", "c": "PKCS #9/RFC 2985", "w": false },
"1.2.840.113549.1.9.25": { "d": "pkcs9attributes", "c": "PKCS #9/RFC 2985", "w": false },
"1.2.840.113549.1.9.25.1": { "d": "pkcs15Token", "c": "PKCS #9/RFC 2985 attribute", "w": false },
"1.2.840.113549.1.9.25.2": { "d": "encryptedPrivateKeyInfo", "c": "PKCS #9/RFC 2985 attribute", "w": false },
"1.2.840.113549.1.9.25.3": { "d": "randomNonce", "c": "PKCS #9/RFC 2985 attribute", "w": false },
"1.2.840.113549.1.9.25.4": { "d": "sequenceNumber", "c": "PKCS #9/RFC 2985 attribute", "w": false },
"1.2.840.113549.1.9.25.5": { "d": "pkcs7PDU", "c": "PKCS #9/RFC 2985 attribute", "w": false },
"1.2.840.113549.1.9.26": { "d": "pkcs9syntax", "c": "PKCS #9/RFC 2985", "w": false },
"1.2.840.113549.1.9.27": { "d": "pkcs9matchingRules", "c": "PKCS #9/RFC 2985", "w": false },
"1.2.840.113549.1.12": { "d": "pkcs-12", "c": "", "w": false },
"1.2.840.113549.1.12.1": { "d": "pkcs-12-PbeIds", "c": "This OID was formerly assigned as PKCS #12 modeID", "w": false },
"1.2.840.113549.1.12.1.1": { "d": "pbeWithSHAAnd128BitRC4", "c": "PKCS #12 PbeIds. This OID was formerly assigned as pkcs-12-OfflineTransportMode", "w": false },
"1.2.840.113549.1.12.1.2": { "d": "pbeWithSHAAnd40BitRC4", "c": "PKCS #12 PbeIds. This OID was formerly assigned as pkcs-12-OnlineTransportMode", "w": false },
"1.2.840.113549.1.12.1.3": { "d": "pbeWithSHAAnd3-KeyTripleDES-CBC", "c": "PKCS #12 PbeIds", "w": false },
"1.2.840.113549.1.12.1.4": { "d": "pbeWithSHAAnd2-KeyTripleDES-CBC", "c": "PKCS #12 PbeIds", "w": false },
"1.2.840.113549.1.12.1.5": { "d": "pbeWithSHAAnd128BitRC2-CBC", "c": "PKCS #12 PbeIds", "w": false },
"1.2.840.113549.1.12.1.6": { "d": "pbeWithSHAAnd40BitRC2-CBC", "c": "PKCS #12 PbeIds", "w": false },
"1.2.840.113549.1.12.2": { "d": "pkcs-12-ESPVKID", "c": "Deprecated", "w": true },
"1.2.840.113549.1.12.2.1": { "d": "pkcs-12-PKCS8KeyShrouding", "c": "PKCS #12 ESPVKID. Deprecated, use (1 2 840 113549 1 12 3 5) instead", "w": true },
"1.2.840.113549.1.12.3": { "d": "pkcs-12-BagIds", "c": "", "w": false },
"1.2.840.113549.1.12.3.1": { "d": "pkcs-12-keyBagId", "c": "PKCS #12 BagIds", "w": false },
"1.2.840.113549.1.12.3.2": { "d": "pkcs-12-certAndCRLBagId", "c": "PKCS #12 BagIds", "w": false },
"1.2.840.113549.1.12.3.3": { "d": "pkcs-12-secretBagId", "c": "PKCS #12 BagIds", "w": false },
"1.2.840.113549.1.12.3.4": { "d": "pkcs-12-safeContentsId", "c": "PKCS #12 BagIds", "w": false },
"1.2.840.113549.1.12.3.5": { "d": "pkcs-12-pkcs-8ShroudedKeyBagId", "c": "PKCS #12 BagIds", "w": false },
"1.2.840.113549.1.12.4": { "d": "pkcs-12-CertBagID", "c": "Deprecated", "w": true },
"1.2.840.113549.1.12.4.1": { "d": "pkcs-12-X509CertCRLBagID", "c": "PKCS #12 CertBagID. This OID was formerly assigned as pkcs-12-X509CertCRLBag", "w": false },
"1.2.840.113549.1.12.4.2": { "d": "pkcs-12-SDSICertBagID", "c": "PKCS #12 CertBagID. This OID was formerly assigned as pkcs-12-SDSICertBag", "w": false },
"1.2.840.113549.1.12.5": { "d": "pkcs-12-OID", "c": "", "w": true },
"1.2.840.113549.1.12.5.1": { "d": "pkcs-12-PBEID", "c": "PKCS #12 OID. Deprecated, use the partially compatible (1 2 840 113549 1 12 1) OIDs instead", "w": true },
"1.2.840.113549.1.12.5.1.1": { "d": "pkcs-12-PBEWithSha1And128BitRC4", "c": "PKCS #12 OID PBEID. Deprecated, use (1 2 840 113549 1 12 1 1) instead", "w": true },
"1.2.840.113549.1.12.5.1.2": { "d": "pkcs-12-PBEWithSha1And40BitRC4", "c": "PKCS #12 OID PBEID. Deprecated, use (1 2 840 113549 1 12 1 2) instead", "w": true },
"1.2.840.113549.1.12.5.1.3": { "d": "pkcs-12-PBEWithSha1AndTripleDESCBC", "c": "PKCS #12 OID PBEID. Deprecated, use the incompatible but similar (1 2 840 113549 1 12 1 3) or (1 2 840 113549 1 12 1 4) instead", "w": true },
"1.2.840.113549.1.12.5.1.4": { "d": "pkcs-12-PBEWithSha1And128BitRC2CBC", "c": "PKCS #12 OID PBEID. Deprecated, use (1 2 840 113549 1 12 1 5) instead", "w": true },
"1.2.840.113549.1.12.5.1.5": { "d": "pkcs-12-PBEWithSha1And40BitRC2CBC", "c": "PKCS #12 OID PBEID. Deprecated, use (1 2 840 113549 1 12 1 6) instead", "w": true },
"1.2.840.113549.1.12.5.1.6": { "d": "pkcs-12-PBEWithSha1AndRC4", "c": "PKCS #12 OID PBEID. Deprecated, use the incompatible but similar (1 2 840 113549 1 12 1 1) or (1 2 840 113549 1 12 1 2) instead", "w": true },
"1.2.840.113549.1.12.5.1.7": { "d": "pkcs-12-PBEWithSha1AndRC2CBC", "c": "PKCS #12 OID PBEID. Deprecated, use the incompatible but similar (1 2 840 113549 1 12 1 5) or (1 2 840 113549 1 12 1 6) instead", "w": true },
"1.2.840.113549.1.12.5.2": { "d": "pkcs-12-EnvelopingID", "c": "PKCS #12 OID. Deprecated, use the conventional PKCS #1 OIDs instead", "w": false },
"1.2.840.113549.1.12.5.2.1": { "d": "pkcs-12-RSAEncryptionWith128BitRC4", "c": "PKCS #12 OID EnvelopingID. Deprecated, use the conventional PKCS #1 OIDs instead", "w": true },
"1.2.840.113549.1.12.5.2.2": { "d": "pkcs-12-RSAEncryptionWith40BitRC4", "c": "PKCS #12 OID EnvelopingID. Deprecated, use the conventional PKCS #1 OIDs instead", "w": true },
"1.2.840.113549.1.12.5.2.3": { "d": "pkcs-12-RSAEncryptionWithTripleDES", "c": "PKCS #12 OID EnvelopingID. Deprecated, use the conventional PKCS #1 OIDs instead", "w": true },
"1.2.840.113549.1.12.5.3": { "d": "pkcs-12-SignatureID", "c": "PKCS #12 OID EnvelopingID. Deprecated, use the conventional PKCS #1 OIDs instead", "w": true },
"1.2.840.113549.1.12.5.3.1": { "d": "pkcs-12-RSASignatureWithSHA1Digest", "c": "PKCS #12 OID SignatureID. Deprecated, use the conventional PKCS #1 OIDs instead", "w": true },
"1.2.840.113549.1.12.10": { "d": "pkcs-12Version1", "c": "", "w": false },
"1.2.840.113549.1.12.10.1": { "d": "pkcs-12BadIds", "c": "", "w": false },
"1.2.840.113549.1.12.10.1.1": { "d": "pkcs-12-keyBag", "c": "PKCS #12 BagIds", "w": false },
"1.2.840.113549.1.12.10.1.2": { "d": "pkcs-12-pkcs-8ShroudedKeyBag", "c": "PKCS #12 BagIds", "w": false },
"1.2.840.113549.1.12.10.1.3": { "d": "pkcs-12-certBag", "c": "PKCS #12 BagIds", "w": false },
"1.2.840.113549.1.12.10.1.4": { "d": "pkcs-12-crlBag", "c": "PKCS #12 BagIds", "w": false },
"1.2.840.113549.1.12.10.1.5": { "d": "pkcs-12-secretBag", "c": "PKCS #12 BagIds", "w": false },
"1.2.840.113549.1.12.10.1.6": { "d": "pkcs-12-safeContentsBag", "c": "PKCS #12 BagIds", "w": false },
"1.2.840.113549.1.15.1": { "d": "pkcs15modules", "c": "PKCS #15", "w": false },
"1.2.840.113549.1.15.2": { "d": "pkcs15attributes", "c": "PKCS #15", "w": false },
"1.2.840.113549.1.15.3": { "d": "pkcs15contentType", "c": "PKCS #15", "w": false },
"1.2.840.113549.1.15.3.1": { "d": "pkcs15content", "c": "PKCS #15 content type", "w": false },
"1.2.840.113549.2": { "d": "digestAlgorithm", "c": "", "w": false },
"1.2.840.113549.2.2": { "d": "md2", "c": "RSADSI digestAlgorithm", "w": false },
"1.2.840.113549.2.4": { "d": "md4", "c": "RSADSI digestAlgorithm", "w": false },
"1.2.840.113549.2.5": { "d": "md5", "c": "RSADSI digestAlgorithm", "w": false },
"1.2.840.113549.2.7": { "d": "hmacWithSHA1", "c": "RSADSI digestAlgorithm", "w": false },
"1.2.840.113549.2.8": { "d": "hmacWithSHA224", "c": "RSADSI digestAlgorithm", "w": false },
"1.2.840.113549.2.9": { "d": "hmacWithSHA256", "c": "RSADSI digestAlgorithm", "w": false },
"1.2.840.113549.2.10": { "d": "hmacWithSHA384", "c": "RSADSI digestAlgorithm", "w": false },
"1.2.840.113549.2.11": { "d": "hmacWithSHA512", "c": "RSADSI digestAlgorithm", "w": false },
"1.2.840.113549.3": { "d": "encryptionAlgorithm", "c": "", "w": false },
"1.2.840.113549.3.2": { "d": "rc2CBC", "c": "RSADSI encryptionAlgorithm", "w": false },
"1.2.840.113549.3.3": { "d": "rc2ECB", "c": "RSADSI encryptionAlgorithm", "w": false },
"1.2.840.113549.3.4": { "d": "rc4", "c": "RSADSI encryptionAlgorithm", "w": false },
"1.2.840.113549.3.5": { "d": "rc4WithMAC", "c": "RSADSI encryptionAlgorithm", "w": false },
"1.2.840.113549.3.6": { "d": "desx-CBC", "c": "RSADSI encryptionAlgorithm", "w": false },
"1.2.840.113549.3.7": { "d": "des-EDE3-CBC", "c": "RSADSI encryptionAlgorithm", "w": false },
"1.2.840.113549.3.8": { "d": "rc5CBC", "c": "RSADSI encryptionAlgorithm", "w": false },
"1.2.840.113549.3.9": { "d": "rc5-CBCPad", "c": "RSADSI encryptionAlgorithm", "w": false },
"1.2.840.113549.3.10": { "d": "desCDMF", "c": "RSADSI encryptionAlgorithm. Formerly called CDMFCBCPad", "w": false },
"1.2.840.114021.1.6.1": { "d": "Identrus unknown policyIdentifier", "c": "Identrus", "w": false },
"1.2.840.114021.4.1": { "d": "identrusOCSP", "c": "Identrus", "w": false },
"1.2.840.113556.1.2.241": { "d": "deliveryMechanism", "c": "Microsoft Exchange Server - attribute", "w": false },
"1.2.840.113556.1.3.0": { "d": "site-Addressing", "c": "Microsoft Exchange Server - object class", "w": false },
"1.2.840.113556.1.3.13": { "d": "classSchema", "c": "Microsoft Exchange Server - object class", "w": false },
"1.2.840.113556.1.3.14": { "d": "attributeSchema", "c": "Microsoft Exchange Server - object class", "w": false },
"1.2.840.113556.1.3.17": { "d": "mailbox-Agent", "c": "Microsoft Exchange Server - object class", "w": false },
"1.2.840.113556.1.3.22": { "d": "mailbox", "c": "Microsoft Exchange Server - object class", "w": false },
"1.2.840.113556.1.3.23": { "d": "container", "c": "Microsoft Exchange Server - object class", "w": false },
"1.2.840.113556.1.3.46": { "d": "mailRecipient", "c": "Microsoft Exchange Server - object class", "w": false },
"1.2.840.113556.1.2.281": { "d": "ntSecurityDescriptor", "c": "Microsoft Cert Template - attribute", "w": false },
"1.2.840.113556.1.4.145": { "d": "revision", "c": "Microsoft Cert Template - attribute", "w": false },
"1.2.840.113556.1.4.1327": { "d": "pKIDefaultKeySpec", "c": "Microsoft Cert Template - attribute", "w": false },
"1.2.840.113556.1.4.1328": { "d": "pKIKeyUsage", "c": "Microsoft Cert Template - attribute", "w": false },
"1.2.840.113556.1.4.1329": { "d": "pKIMaxIssuingDepth", "c": "Microsoft Cert Template - attribute", "w": false },
"1.2.840.113556.1.4.1330": { "d": "pKICriticalExtensions", "c": "Microsoft Cert Template - attribute", "w": false },
"1.2.840.113556.1.4.1331": { "d": "pKIExpirationPeriod", "c": "Microsoft Cert Template - attribute", "w": false },
"1.2.840.113556.1.4.1332": { "d": "pKIOverlapPeriod", "c": "Microsoft Cert Template - attribute", "w": false },
"1.2.840.113556.1.4.1333": { "d": "pKIExtendedKeyUsage", "c": "Microsoft Cert Template - attribute", "w": false },
"1.2.840.113556.1.4.1334": { "d": "pKIDefaultCSPs", "c": "Microsoft Cert Template - attribute", "w": false },
"1.2.840.113556.1.4.1335": { "d": "pKIEnrollmentAccess", "c": "Microsoft Cert Template - attribute", "w": false },
"1.2.840.113556.1.4.1429": { "d": "msPKI-RA-Signature", "c": "Microsoft Cert Template - attribute", "w": false },
"1.2.840.113556.1.4.1430": { "d": "msPKI-Enrollment-Flag", "c": "Microsoft Cert Template - attribute", "w": false },
"1.2.840.113556.1.4.1431": { "d": "msPKI-Private-Key-Flag", "c": "Microsoft Cert Template - attribute", "w": false },
"1.2.840.113556.1.4.1432": { "d": "msPKI-Certificate-Name-Flag", "c": "Microsoft Cert Template - attribute", "w": false },
"1.2.840.113556.1.4.1433": { "d": "msPKI-Minimal-Key-Size", "c": "Microsoft Cert Template - attribute", "w": false },
"1.2.840.113556.1.4.1434": { "d": "msPKI-Template-Schema-Version", "c": "Microsoft Cert Template - attribute", "w": false },
"1.2.840.113556.1.4.1435": { "d": "msPKI-Template-Minor-Revision", "c": "Microsoft Cert Template - attribute", "w": false },
"1.2.840.113556.1.4.1436": { "d": "msPKI-Cert-Template-OID", "c": "Microsoft Cert Template - attribute", "w": false },
"1.2.840.113556.1.4.1437": { "d": "msPKI-Supersede-Templates", "c": "Microsoft Cert Template - attribute", "w": false },
"1.2.840.113556.1.4.1438": { "d": "msPKI-RA-Policies", "c": "Microsoft Cert Template - attribute", "w": false },
"1.2.840.113556.1.4.1439": { "d": "msPKI-Certificate-Policy", "c": "Microsoft Cert Template - attribute", "w": false },
"1.2.840.113556.1.4.1674": { "d": "msPKI-Certificate-Application-Policy", "c": "Microsoft Cert Template - attribute", "w": false },
"1.2.840.113556.1.4.1675": { "d": "msPKI-RA-Application-Policies", "c": "Microsoft Cert Template - attribute", "w": false },
"1.2.840.113556.4.3": { "d": "microsoftExcel", "c": "Microsoft", "w": false },
"1.2.840.113556.4.4": { "d": "titledWithOID", "c": "Microsoft", "w": false },
"1.2.840.113556.4.5": { "d": "microsoftPowerPoint", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.2.1.4": { "d": "spcIndirectDataContext", "c": "Microsoft code signing", "w": false },
"1.3.6.1.4.1.311.2.1.10": { "d": "spcAgencyInfo", "c": "Microsoft code signing. Also known as policyLink", "w": false },
"1.3.6.1.4.1.311.2.1.11": { "d": "spcStatementType", "c": "Microsoft code signing", "w": false },
"1.3.6.1.4.1.311.2.1.12": { "d": "spcSpOpusInfo", "c": "Microsoft code signing", "w": false },
"1.3.6.1.4.1.311.2.1.14": { "d": "certReqExtensions", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.2.1.15": { "d": "spcPEImageData", "c": "Microsoft code signing", "w": false },
"1.3.6.1.4.1.311.2.1.18": { "d": "spcRawFileData", "c": "Microsoft code signing", "w": false },
"1.3.6.1.4.1.311.2.1.19": { "d": "spcStructuredStorageData", "c": "Microsoft code signing", "w": false },
"1.3.6.1.4.1.311.2.1.20": { "d": "spcJavaClassData (type 1)", "c": "Microsoft code signing. Formerly \"link extension\" aka \"glue extension\"", "w": false },
"1.3.6.1.4.1.311.2.1.21": { "d": "individualCodeSigning", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.2.1.22": { "d": "commercialCodeSigning", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.2.1.25": { "d": "spcLink (type 2)", "c": "Microsoft code signing. Also known as \"glue extension\"", "w": false },
"1.3.6.1.4.1.311.2.1.26": { "d": "spcMinimalCriteriaInfo", "c": "Microsoft code signing", "w": false },
"1.3.6.1.4.1.311.2.1.27": { "d": "spcFinancialCriteriaInfo", "c": "Microsoft code signing", "w": false },
"1.3.6.1.4.1.311.2.1.28": { "d": "spcLink (type 3)", "c": "Microsoft code signing.  Also known as \"glue extension\"", "w": false },
"1.3.6.1.4.1.311.3.2.1": { "d": "timestampRequest", "c": "Microsoft code signing", "w": false },
"1.3.6.1.4.1.311.10.1": { "d": "certTrustList", "c": "Microsoft contentType", "w": false },
"1.3.6.1.4.1.311.10.1.1": { "d": "sortedCtl", "c": "Microsoft contentType", "w": false },
"1.3.6.1.4.1.311.10.2": { "d": "nextUpdateLocation", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.10.3.1": { "d": "certTrustListSigning", "c": "Microsoft enhanced key usage", "w": false },
"1.3.6.1.4.1.311.10.3.2": { "d": "timeStampSigning", "c": "Microsoft enhanced key usage", "w": false },
"1.3.6.1.4.1.311.10.3.3": { "d": "serverGatedCrypto", "c": "Microsoft enhanced key usage", "w": false },
"1.3.6.1.4.1.311.10.3.3.1": { "d": "serialized", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.10.3.4": { "d": "encryptedFileSystem", "c": "Microsoft enhanced key usage", "w": false },
"1.3.6.1.4.1.311.10.3.5": { "d": "whqlCrypto", "c": "Microsoft enhanced key usage", "w": false },
"1.3.6.1.4.1.311.10.3.6": { "d": "nt5Crypto", "c": "Microsoft enhanced key usage", "w": false },
"1.3.6.1.4.1.311.10.3.7": { "d": "oemWHQLCrypto", "c": "Microsoft enhanced key usage", "w": false },
"1.3.6.1.4.1.311.10.3.8": { "d": "embeddedNTCrypto", "c": "Microsoft enhanced key usage", "w": false },
"1.3.6.1.4.1.311.10.3.9": { "d": "rootListSigner", "c": "Microsoft enhanced key usage", "w": false },
"1.3.6.1.4.1.311.10.3.10": { "d": "qualifiedSubordination", "c": "Microsoft enhanced key usage", "w": false },
"1.3.6.1.4.1.311.10.3.11": { "d": "keyRecovery", "c": "Microsoft enhanced key usage", "w": false },
"1.3.6.1.4.1.311.10.3.12": { "d": "documentSigning", "c": "Microsoft enhanced key usage", "w": false },
"1.3.6.1.4.1.311.10.3.13": { "d": "lifetimeSigning", "c": "Microsoft enhanced key usage", "w": false },
"1.3.6.1.4.1.311.10.3.14": { "d": "mobileDeviceSoftware", "c": "Microsoft enhanced key usage", "w": false },
"1.3.6.1.4.1.311.10.3.15": { "d": "smartDisplay", "c": "Microsoft enhanced key usage", "w": false },
"1.3.6.1.4.1.311.10.3.16": { "d": "cspSignature", "c": "Microsoft enhanced key usage", "w": false },
"1.3.6.1.4.1.311.10.3.4.1": { "d": "efsRecovery", "c": "Microsoft enhanced key usage", "w": false },
"1.3.6.1.4.1.311.10.4.1": { "d": "yesnoTrustAttr", "c": "Microsoft attribute", "w": false },
"1.3.6.1.4.1.311.10.5.1": { "d": "drm", "c": "Microsoft enhanced key usage", "w": false },
"1.3.6.1.4.1.311.10.5.2": { "d": "drmIndividualization", "c": "Microsoft enhanced key usage", "w": false },
"1.3.6.1.4.1.311.10.6.1": { "d": "licenses", "c": "Microsoft enhanced key usage", "w": false },
"1.3.6.1.4.1.311.10.6.2": { "d": "licenseServer", "c": "Microsoft enhanced key usage", "w": false },
"1.3.6.1.4.1.311.10.7.1": { "d": "keyidRdn", "c": "Microsoft attribute", "w": false },
"1.3.6.1.4.1.311.10.8.1": { "d": "removeCertificate", "c": "Microsoft attribute", "w": false },
"1.3.6.1.4.1.311.10.9.1": { "d": "crossCertDistPoints", "c": "Microsoft attribute", "w": false },
"1.3.6.1.4.1.311.10.10.1": { "d": "cmcAddAttributes", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.10.11": { "d": "certPropIdPrefix", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.10.11.4": { "d": "certMd5HashPropId", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.10.11.20": { "d": "certKeyIdentifierPropId", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.10.11.28": { "d": "certIssuerSerialNumberMd5HashPropId", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.10.11.29": { "d": "certSubjectNameMd5HashPropId", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.10.12.1": { "d": "anyApplicationPolicy", "c": "Microsoft attribute", "w": false },
"1.3.6.1.4.1.311.13.1": { "d": "renewalCertificate", "c": "Microsoft attribute", "w": false },
"1.3.6.1.4.1.311.13.2.1": { "d": "enrolmentNameValuePair", "c": "Microsoft attribute", "w": false },
"1.3.6.1.4.1.311.13.2.2": { "d": "enrolmentCSP", "c": "Microsoft attribute", "w": false },
"1.3.6.1.4.1.311.13.2.3": { "d": "osVersion", "c": "Microsoft attribute", "w": false },
"1.3.6.1.4.1.311.16.4": { "d": "microsoftRecipientInfo", "c": "Microsoft attribute", "w": false },
"1.3.6.1.4.1.311.17.1": { "d": "pkcs12KeyProviderNameAttr", "c": "Microsoft attribute", "w": false },
"1.3.6.1.4.1.311.17.2": { "d": "localMachineKeyset", "c": "Microsoft attribute", "w": false },
"1.3.6.1.4.1.311.17.3": { "d": "pkcs12ExtendedAttributes", "c": "Microsoft attribute", "w": false },
"1.3.6.1.4.1.311.20.1": { "d": "autoEnrollCtlUsage", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.20.2": { "d": "enrollCerttypeExtension", "c": "Microsoft CAPICOM certificate template, V1", "w": false },
"1.3.6.1.4.1.311.20.2.1": { "d": "enrollmentAgent", "c": "Microsoft enhanced key usage", "w": false },
"1.3.6.1.4.1.311.20.2.2": { "d": "smartcardLogon", "c": "Microsoft enhanced key usage", "w": false },
"1.3.6.1.4.1.311.20.2.3": { "d": "universalPrincipalName", "c": "Microsoft UPN", "w": false },
"1.3.6.1.4.1.311.20.3": { "d": "certManifold", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.21.1": { "d": "cAKeyCertIndexPair", "c": "Microsoft attribute.  Also known as certsrvCaVersion", "w": false },
"1.3.6.1.4.1.311.21.5": { "d": "caExchange", "c": "Microsoft extended key usage", "w": true },
"1.3.6.1.4.1.311.21.2": { "d": "certSrvPreviousCertHash", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.21.3": { "d": "crlVirtualBase", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.21.4": { "d": "crlNextPublish", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.21.6": { "d": "keyRecovery", "c": "Microsoft extended key usage", "w": true },
"1.3.6.1.4.1.311.21.7": { "d": "certificateTemplate", "c": "Microsoft CAPICOM certificate template, V2", "w": false },
"1.3.6.1.4.1.311.21.9": { "d": "rdnDummySigner", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.21.10": { "d": "applicationCertPolicies", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.21.11": { "d": "applicationPolicyMappings", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.21.12": { "d": "applicationPolicyConstraints", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.21.13": { "d": "archivedKey", "c": "Microsoft attribute", "w": false },
"1.3.6.1.4.1.311.21.14": { "d": "crlSelfCDP", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.21.15": { "d": "requireCertChainPolicy", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.21.16": { "d": "archivedKeyCertHash", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.21.17": { "d": "issuedCertHash", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.21.19": { "d": "dsEmailReplication", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.21.20": { "d": "requestClientInfo", "c": "Microsoft attribute", "w": false },
"1.3.6.1.4.1.311.21.21": { "d": "encryptedKeyHash", "c": "Microsoft attribute", "w": false },
"1.3.6.1.4.1.311.21.22": { "d": "certsrvCrossCaVersion", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.25.1": { "d": "ntdsReplication", "c": "Microsoft", "w": false },
"1.3.6.1.4.1.311.31.1": { "d": "productUpdate", "c": "Microsoft attribute", "w": false },
"1.3.6.1.4.1.311.47.1.1": { "d": "systemHealth", "c": "Microsoft extended key usage", "w": false },
"1.3.6.1.4.1.311.47.1.3": { "d": "systemHealthLoophole", "c": "Microsoft extended key usage", "w": false },
"1.3.6.1.4.1.311.60.1.1": { "d": "rootProgramFlags", "c": "Microsoft policy attribute", "w": false },
"1.3.6.1.4.1.311.61.1.1": { "d": "kernelModeCodeSigning", "c": "Microsoft enhanced key usage", "w": false },
"1.3.6.1.4.1.311.88.2.1": { "d": "originalFilename", "c": "Microsoft attribute", "w": false },
"1.3.6.1.4.1.188.7.1.1": { "d": "ascom", "c": "Ascom Systech", "w": false },
"1.3.6.1.4.1.188.7.1.1.1": { "d": "ideaECB", "c": "Ascom Systech", "w": false },
"1.3.6.1.4.1.188.7.1.1.2": { "d": "ideaCBC", "c": "Ascom Systech", "w": false },
"1.3.6.1.4.1.188.7.1.1.3": { "d": "ideaCFB", "c": "Ascom Systech", "w": false },
"1.3.6.1.4.1.188.7.1.1.4": { "d": "ideaOFB", "c": "Ascom Systech", "w": false },
"1.3.6.1.4.1.2428.10.1.1": { "d": "UNINETT policyIdentifier", "c": "UNINETT PCA", "w": false },
"1.3.6.1.4.1.2712.10": { "d": "ICE-TEL policyIdentifier", "c": "ICE-TEL CA", "w": false },
"1.3.6.1.4.1.2786.1.1.1": { "d": "ICE-TEL Italian policyIdentifier", "c": "ICE-TEL CA policy", "w": false },
"1.3.6.1.4.1.3029.1.1.1": { "d": "blowfishECB", "c": "cryptlib encryption algorithm", "w": false },
"1.3.6.1.4.1.3029.1.1.2": { "d": "blowfishCBC", "c": "cryptlib encryption algorithm", "w": false },
"1.3.6.1.4.1.3029.1.1.3": { "d": "blowfishCFB", "c": "cryptlib encryption algorithm", "w": false },
"1.3.6.1.4.1.3029.1.1.4": { "d": "blowfishOFB", "c": "cryptlib encryption algorithm", "w": false },
"1.3.6.1.4.1.3029.1.2.1": { "d": "elgamal", "c": "cryptlib public-key algorithm", "w": false },
"1.3.6.1.4.1.3029.1.2.1.1": { "d": "elgamalWithSHA-1", "c": "cryptlib public-key algorithm", "w": false },
"1.3.6.1.4.1.3029.1.2.1.2": { "d": "elgamalWithRIPEMD-160", "c": "cryptlib public-key algorithm", "w": false },
"1.3.6.1.4.1.3029.3.1.1": { "d": "cryptlibPresenceCheck", "c": "cryptlib attribute type", "w": false },
"1.3.6.1.4.1.3029.3.1.2": { "d": "pkiBoot", "c": "cryptlib attribute type", "w": false },
"1.3.6.1.4.1.3029.3.1.4": { "d": "crlExtReason", "c": "cryptlib attribute type", "w": false },
"1.3.6.1.4.1.3029.3.1.5": { "d": "keyFeatures", "c": "cryptlib attribute type", "w": false },
"1.3.6.1.4.1.3029.4.1": { "d": "cryptlibContent", "c": "cryptlib", "w": false },
"1.3.6.1.4.1.3029.4.1.1": { "d": "cryptlibConfigData", "c": "cryptlib content type", "w": false },
"1.3.6.1.4.1.3029.4.1.2": { "d": "cryptlibUserIndex", "c": "cryptlib content type", "w": false },
"1.3.6.1.4.1.3029.4.1.3": { "d": "cryptlibUserInfo", "c": "cryptlib content type", "w": false },
"1.3.6.1.4.1.3029.4.1.4": { "d": "rtcsRequest", "c": "cryptlib content type", "w": false },
"1.3.6.1.4.1.3029.4.1.5": { "d": "rtcsResponse", "c": "cryptlib content type", "w": false },
"1.3.6.1.4.1.3029.4.1.6": { "d": "rtcsResponseExt", "c": "cryptlib content type", "w": false },
"1.3.6.1.4.1.3029.42.11172.1": { "d": "mpeg-1", "c": "cryptlib special MPEG-of-cat OID", "w": false },
"1.3.6.1.4.1.3029.88.89.90.90.89": { "d": "xYZZY policyIdentifier", "c": "cryptlib certificate policy", "w": false },
"1.3.6.1.4.1.3401.8.1.1": { "d": "pgpExtension", "c": "PGP key information", "w": false },
"1.3.6.1.4.1.3576.7": { "d": "eciaAscX12Edi", "c": "TMN EDI for Interactive Agents", "w": false },
"1.3.6.1.4.1.3576.7.1": { "d": "plainEDImessage", "c": "TMN EDI for Interactive Agents", "w": false },
"1.3.6.1.4.1.3576.7.2": { "d": "signedEDImessage", "c": "TMN EDI for Interactive Agents", "w": false },
"1.3.6.1.4.1.3576.7.5": { "d": "integrityEDImessage", "c": "TMN EDI for Interactive Agents", "w": false },
"1.3.6.1.4.1.3576.7.65": { "d": "iaReceiptMessage", "c": "TMN EDI for Interactive Agents", "w": false },
"1.3.6.1.4.1.3576.7.97": { "d": "iaStatusMessage", "c": "TMN EDI for Interactive Agents", "w": false },
"1.3.6.1.4.1.3576.8": { "d": "eciaEdifact", "c": "TMN EDI for Interactive Agents", "w": false },
"1.3.6.1.4.1.3576.9": { "d": "eciaNonEdi", "c": "TMN EDI for Interactive Agents", "w": false },
"1.3.6.1.4.1.5472": { "d": "timeproof", "c": "enterprise", "w": false },
"1.3.6.1.4.1.5472.1": { "d": "tss", "c": "timeproof", "w": false },
"1.3.6.1.4.1.5472.1.1": { "d": "tss80", "c": "timeproof TSS", "w": false },
"1.3.6.1.4.1.5472.1.2": { "d": "tss380", "c": "timeproof TSS", "w": false },
"1.3.6.1.4.1.5472.1.3": { "d": "tss400", "c": "timeproof TSS", "w": false },
"1.3.6.1.4.1.5770.0.3": { "d": "secondaryPractices", "c": "MEDePass", "w": false },
"1.3.6.1.4.1.5770.0.4": { "d": "physicianIdentifiers", "c": "MEDePass", "w": false },
"1.3.6.1.4.1.6449.1.2.1.3.1": { "d": "comodoPolicy", "c": "Comodo CA", "w": false },
"1.3.6.1.4.1.6449.1.3.5.2": { "d": "comodoCertifiedDeliveryService", "c": "Comodo CA", "w": false },
"1.3.6.1.4.1.6449.1.3.5.2": { "d": "validityModel x", "c": "TU Darmstadt ValidityModel", "w": false },
"1.3.6.1.4.1.8301.3.5.1": { "d": "validityModelChain", "c": "TU Darmstadt ValidityModel", "w": false },
"1.3.6.1.4.1.8301.3.5.2": { "d": "validityModelShell", "c": "ValidityModel", "w": false },
"1.3.6.1.4.1.8231.1": { "d": "rolUnicoNacional", "c": "Chilean Government national unique roll number", "w": false },
"1.3.6.1.4.1.11591": { "d": "gnu", "c": "GNU Project (see http://www.gnupg.org/oids.html)", "w": false },
"1.3.6.1.4.1.11591.1": { "d": "gnuRadius", "c": "GNU Radius", "w": false },
"1.3.6.1.4.1.11591.3": { "d": "gnuRadar", "c": "GNU Radar", "w": false },
"1.3.6.1.4.1.11591.12": { "d": "gnuDigestAlgorithm", "c": "GNU digest algorithm", "w": false },
"1.3.6.1.4.1.11591.12.2": { "d": "tiger", "c": "GNU digest algorithm", "w": false },
"1.3.6.1.4.1.11591.13": { "d": "gnuEncryptionAlgorithm", "c": "GNU encryption algorithm", "w": false },
"1.3.6.1.4.1.11591.13.2": { "d": "serpent", "c": "GNU encryption algorithm", "w": false },
"1.3.6.1.4.1.11591.13.2.1": { "d": "serpent128_ECB", "c": "GNU encryption algorithm", "w": false },
"1.3.6.1.4.1.11591.13.2.2": { "d": "serpent128_CBC", "c": "GNU encryption algorithm", "w": false },
"1.3.6.1.4.1.11591.13.2.3": { "d": "serpent128_OFB", "c": "GNU encryption algorithm", "w": false },
"1.3.6.1.4.1.11591.13.2.4": { "d": "serpent128_CFB", "c": "GNU encryption algorithm", "w": false },
"1.3.6.1.4.1.11591.13.2.21": { "d": "serpent192_ECB", "c": "GNU encryption algorithm", "w": false },
"1.3.6.1.4.1.11591.13.2.22": { "d": "serpent192_CBC", "c": "GNU encryption algorithm", "w": false },
"1.3.6.1.4.1.11591.13.2.23": { "d": "serpent192_OFB", "c": "GNU encryption algorithm", "w": false },
"1.3.6.1.4.1.11591.13.2.24": { "d": "serpent192_CFB", "c": "GNU encryption algorithm", "w": false },
"1.3.6.1.4.1.11591.13.2.41": { "d": "serpent256_ECB", "c": "GNU encryption algorithm", "w": false },
"1.3.6.1.4.1.11591.13.2.42": { "d": "serpent256_CBC", "c": "GNU encryption algorithm", "w": false },
"1.3.6.1.4.1.11591.13.2.43": { "d": "serpent256_OFB", "c": "GNU encryption algorithm", "w": false },
"1.3.6.1.4.1.11591.13.2.44": { "d": "serpent256_CFB", "c": "GNU encryption algorithm", "w": false },
"1.3.6.1.4.1.16334.509.1.1": { "d": "Northrop Grumman extKeyUsage?", "c": "Northrop Grumman extended key usage", "w": false },
"1.3.6.1.4.1.16334.509.2.1": { "d": "ngcClass1", "c": "Northrop Grumman policy", "w": false },
"1.3.6.1.4.1.16334.509.2.2": { "d": "ngcClass2", "c": "Northrop Grumman policy", "w": false },
"1.3.6.1.4.1.16334.509.2.3": { "d": "ngcClass3", "c": "Northrop Grumman policy", "w": false },
"1.3.6.1.5.5.7": { "d": "pkix", "c": "", "w": false },
"1.3.6.1.5.5.7.0.12": { "d": "attributeCert", "c": "PKIX", "w": false },
"1.3.6.1.5.5.7.1": { "d": "privateExtension", "c": "PKIX", "w": false },
"1.3.6.1.5.5.7.1.1": { "d": "authorityInfoAccess", "c": "PKIX private extension", "w": false },
"1.3.6.1.5.5.7.1.2": { "d": "biometricInfo", "c": "PKIX private extension", "w": false },
"1.3.6.1.5.5.7.1.3": { "d": "qcStatements", "c": "PKIX private extension", "w": false },
"1.3.6.1.5.5.7.1.4": { "d": "acAuditIdentity", "c": "PKIX private extension", "w": false },
"1.3.6.1.5.5.7.1.5": { "d": "acTargeting", "c": "PKIX private extension", "w": false },
"1.3.6.1.5.5.7.1.6": { "d": "acAaControls", "c": "PKIX private extension", "w": false },
"1.3.6.1.5.5.7.1.7": { "d": "sbgp-ipAddrBlock", "c": "PKIX private extension", "w": false },
"1.3.6.1.5.5.7.1.8": { "d": "sbgp-autonomousSysNum", "c": "PKIX private extension", "w": false },
"1.3.6.1.5.5.7.1.9": { "d": "sbgp-routerIdentifier", "c": "PKIX private extension", "w": false },
"1.3.6.1.5.5.7.1.10": { "d": "acProxying", "c": "PKIX private extension", "w": false },
"1.3.6.1.5.5.7.1.11": { "d": "subjectInfoAccess", "c": "PKIX private extension", "w": false },
"1.3.6.1.5.5.7.1.12": { "d": "logoType", "c": "PKIX private extension", "w": false },
"1.3.6.1.5.5.7.2": { "d": "policyQualifierIds", "c": "PKIX", "w": false },
"1.3.6.1.5.5.7.2.1": { "d": "cps", "c": "PKIX policy qualifier", "w": false },
"1.3.6.1.5.5.7.2.2": { "d": "unotice", "c": "PKIX policy qualifier", "w": false },
"1.3.6.1.5.5.7.2.3": { "d": "textNotice", "c": "PKIX policy qualifier", "w": false },
"1.3.6.1.5.5.7.3": { "d": "keyPurpose", "c": "PKIX", "w": false },
"1.3.6.1.5.5.7.3.1": { "d": "serverAuth", "c": "PKIX key purpose", "w": false },
"1.3.6.1.5.5.7.3.2": { "d": "clientAuth", "c": "PKIX key purpose", "w": false },
"1.3.6.1.5.5.7.3.3": { "d": "codeSigning", "c": "PKIX key purpose", "w": false },
"1.3.6.1.5.5.7.3.4": { "d": "emailProtection", "c": "PKIX key purpose", "w": false },
"1.3.6.1.5.5.7.3.5": { "d": "ipsecEndSystem", "c": "PKIX key purpose", "w": false },
"1.3.6.1.5.5.7.3.6": { "d": "ipsecTunnel", "c": "PKIX key purpose", "w": false },
"1.3.6.1.5.5.7.3.7": { "d": "ipsecUser", "c": "PKIX key purpose", "w": false },
"1.3.6.1.5.5.7.3.8": { "d": "timeStamping", "c": "PKIX key purpose", "w": false },
"1.3.6.1.5.5.7.3.9": { "d": "ocspSigning", "c": "PKIX key purpose", "w": false },
"1.3.6.1.5.5.7.3.10": { "d": "dvcs", "c": "PKIX key purpose", "w": false },
"1.3.6.1.5.5.7.3.11": { "d": "sbgpCertAAServerAuth", "c": "PKIX key purpose", "w": false },
"1.3.6.1.5.5.7.3.13": { "d": "eapOverPPP", "c": "PKIX key purpose", "w": false },
"1.3.6.1.5.5.7.3.14": { "d": "wlanSSID", "c": "PKIX key purpose", "w": false },
"1.3.6.1.5.5.7.4": { "d": "cmpInformationTypes", "c": "PKIX", "w": false },
"1.3.6.1.5.5.7.4.1": { "d": "caProtEncCert", "c": "PKIX CMP information", "w": false },
"1.3.6.1.5.5.7.4.2": { "d": "signKeyPairTypes", "c": "PKIX CMP information", "w": false },
"1.3.6.1.5.5.7.4.3": { "d": "encKeyPairTypes", "c": "PKIX CMP information", "w": false },
"1.3.6.1.5.5.7.4.4": { "d": "preferredSymmAlg", "c": "PKIX CMP information", "w": false },
"1.3.6.1.5.5.7.4.5": { "d": "caKeyUpdateInfo", "c": "PKIX CMP information", "w": false },
"1.3.6.1.5.5.7.4.6": { "d": "currentCRL", "c": "PKIX CMP information", "w": false },
"1.3.6.1.5.5.7.4.7": { "d": "unsupportedOIDs", "c": "PKIX CMP information", "w": false },
"1.3.6.1.5.5.7.4.10": { "d": "keyPairParamReq", "c": "PKIX CMP information", "w": false },
"1.3.6.1.5.5.7.4.11": { "d": "keyPairParamRep", "c": "PKIX CMP information", "w": false },
"1.3.6.1.5.5.7.4.12": { "d": "revPassphrase", "c": "PKIX CMP information", "w": false },
"1.3.6.1.5.5.7.4.13": { "d": "implicitConfirm", "c": "PKIX CMP information", "w": false },
"1.3.6.1.5.5.7.4.14": { "d": "confirmWaitTime", "c": "PKIX CMP information", "w": false },
"1.3.6.1.5.5.7.4.15": { "d": "origPKIMessage", "c": "PKIX CMP information", "w": false },
"1.3.6.1.5.5.7.4.16": { "d": "suppLangTags", "c": "PKIX CMP information", "w": false },
"1.3.6.1.5.5.7.5": { "d": "crmfRegistration", "c": "PKIX", "w": false },
"1.3.6.1.5.5.7.5.1": { "d": "regCtrl", "c": "PKIX CRMF registration", "w": false },
"1.3.6.1.5.5.7.5.1.1": { "d": "regToken", "c": "PKIX CRMF registration control", "w": false },
"1.3.6.1.5.5.7.5.1.2": { "d": "authenticator", "c": "PKIX CRMF registration control", "w": false },
"1.3.6.1.5.5.7.5.1.3": { "d": "pkiPublicationInfo", "c": "PKIX CRMF registration control", "w": false },
"1.3.6.1.5.5.7.5.1.4": { "d": "pkiArchiveOptions", "c": "PKIX CRMF registration control", "w": false },
"1.3.6.1.5.5.7.5.1.5": { "d": "oldCertID", "c": "PKIX CRMF registration control", "w": false },
"1.3.6.1.5.5.7.5.1.6": { "d": "protocolEncrKey", "c": "PKIX CRMF registration control", "w": false },
"1.3.6.1.5.5.7.5.1.7": { "d": "altCertTemplate", "c": "PKIX CRMF registration control", "w": false },
"1.3.6.1.5.5.7.5.1.8": { "d": "wtlsTemplate", "c": "PKIX CRMF registration control", "w": false },
"1.3.6.1.5.5.7.5.2": { "d": "utf8Pairs", "c": "PKIX CRMF registration", "w": false },
"1.3.6.1.5.5.7.5.2.1": { "d": "utf8Pairs", "c": "PKIX CRMF registration control", "w": false },
"1.3.6.1.5.5.7.5.2.2": { "d": "certReq", "c": "PKIX CRMF registration control", "w": false },
"1.3.6.1.5.5.7.6": { "d": "algorithms", "c": "PKIX", "w": false },
"1.3.6.1.5.5.7.6.1": { "d": "des40", "c": "PKIX algorithm", "w": false },
"1.3.6.1.5.5.7.6.2": { "d": "noSignature", "c": "PKIX algorithm", "w": false },
"1.3.6.1.5.5.7.6.3": { "d": "dh-sig-hmac-sha1", "c": "PKIX algorithm", "w": false },
"1.3.6.1.5.5.7.6.4": { "d": "dh-pop", "c": "PKIX algorithm", "w": false },
"1.3.6.1.5.5.7.7": { "d": "cmcControls", "c": "PKIX", "w": false },
"1.3.6.1.5.5.7.8": { "d": "otherNames", "c": "PKIX", "w": false },
"1.3.6.1.5.5.7.8.1": { "d": "personalData", "c": "PKIX other name", "w": false },
"1.3.6.1.5.5.7.8.2": { "d": "userGroup", "c": "PKIX other name", "w": false },
"1.3.6.1.5.5.7.9": { "d": "personalData", "c": "PKIX qualified certificates", "w": false },
"1.3.6.1.5.5.7.9.1": { "d": "dateOfBirth", "c": "PKIX personal data", "w": false },
"1.3.6.1.5.5.7.9.2": { "d": "placeOfBirth", "c": "PKIX personal data", "w": false },
"1.3.6.1.5.5.7.9.3": { "d": "gender", "c": "PKIX personal data", "w": false },
"1.3.6.1.5.5.7.9.4": { "d": "countryOfCitizenship", "c": "PKIX personal data", "w": false },
"1.3.6.1.5.5.7.9.5": { "d": "countryOfResidence", "c": "PKIX personal data", "w": false },
"1.3.6.1.5.5.7.10": { "d": "attributeCertificate", "c": "PKIX", "w": false },
"1.3.6.1.5.5.7.10.1": { "d": "authenticationInfo", "c": "PKIX attribute certificate extension", "w": false },
"1.3.6.1.5.5.7.10.2": { "d": "accessIdentity", "c": "PKIX attribute certificate extension", "w": false },
"1.3.6.1.5.5.7.10.3": { "d": "chargingIdentity", "c": "PKIX attribute certificate extension", "w": false },
"1.3.6.1.5.5.7.10.4": { "d": "group", "c": "PKIX attribute certificate extension", "w": false },
"1.3.6.1.5.5.7.10.5": { "d": "role", "c": "PKIX attribute certificate extension", "w": false },
"1.3.6.1.5.5.7.10.6": { "d": "encAttrs", "c": "PKIX attribute certificate extension", "w": false },
"1.3.6.1.5.5.7.11": { "d": "personalData", "c": "PKIX qualified certificates", "w": false },
"1.3.6.1.5.5.7.11.1": { "d": "pkixQCSyntax-v1", "c": "PKIX qualified certificates", "w": false },
"1.3.6.1.5.5.7.20": { "d": "logo", "c": "PKIX qualified certificates", "w": false },
"1.3.6.1.5.5.7.20.1": { "d": "logoLoyalty", "c": "PKIX", "w": false },
"1.3.6.1.5.5.7.20.2": { "d": "logoBackground", "c": "PKIX", "w": false },
"1.3.6.1.5.5.7.48.1": { "d": "ocsp", "c": "PKIX", "w": false },
"1.3.6.1.5.5.7.48.1.1": { "d": "ocspBasic", "c": "OCSP", "w": false },
"1.3.6.1.5.5.7.48.1.2": { "d": "ocspNonce", "c": "OCSP", "w": false },
"1.3.6.1.5.5.7.48.1.3": { "d": "ocspCRL", "c": "OCSP", "w": false },
"1.3.6.1.5.5.7.48.1.4": { "d": "ocspResponse", "c": "OCSP", "w": false },
"1.3.6.1.5.5.7.48.1.5": { "d": "ocspNoCheck", "c": "OCSP", "w": false },
"1.3.6.1.5.5.7.48.1.6": { "d": "ocspArchiveCutoff", "c": "OCSP", "w": false },
"1.3.6.1.5.5.7.48.1.7": { "d": "ocspServiceLocator", "c": "OCSP", "w": false },
"1.3.6.1.5.5.7.48.2": { "d": "caIssuers", "c": "PKIX subject/authority info access descriptor", "w": false },
"1.3.6.1.5.5.7.48.3": { "d": "timeStamping", "c": "PKIX subject/authority info access descriptor", "w": false },
"1.3.6.1.5.5.7.48.3": { "d": "caRepository x", "c": "PKIX subject/authority info access descriptor", "w": false },
"1.3.6.1.5.5.8.1.1": { "d": "hmacMD5", "c": "ISAKMP HMAC algorithm", "w": false },
"1.3.6.1.5.5.8.1.2": { "d": "hmacSHA", "c": "ISAKMP HMAC algorithm", "w": false },
"1.3.6.1.5.5.8.1.3": { "d": "hmacTiger", "c": "ISAKMP HMAC algorithm", "w": false },
"1.3.6.1.5.5.8.2.2": { "d": "iKEIntermediate", "c": "IKE ???", "w": false },
"1.3.12.2.1011.7.1": { "d": "decEncryptionAlgorithm", "c": "DASS algorithm", "w": false },
"1.3.12.2.1011.7.1.2": { "d": "decDEA", "c": "DASS encryption algorithm", "w": false },
"1.3.12.2.1011.7.2": { "d": "decHashAlgorithm", "c": "DASS algorithm", "w": false },
"1.3.12.2.1011.7.2.1": { "d": "decMD2", "c": "DASS hash algorithm", "w": false },
"1.3.12.2.1011.7.2.2": { "d": "decMD4", "c": "DASS hash algorithm", "w": false },
"1.3.12.2.1011.7.3": { "d": "decSignatureAlgorithm", "c": "DASS algorithm", "w": false },
"1.3.12.2.1011.7.3.1": { "d": "decMD2withRSA", "c": "DASS signature algorithm", "w": false },
"1.3.12.2.1011.7.3.2": { "d": "decMD4withRSA", "c": "DASS signature algorithm", "w": false },
"1.3.12.2.1011.7.3.3": { "d": "decDEAMAC", "c": "DASS signature algorithm", "w": false },
"1.3.14.2.26.5": { "d": "sha", "c": "Unsure about this OID", "w": false },
"1.3.14.3.2.1.1": { "d": "rsa", "c": "X.509. Unsure about this OID", "w": false },
"1.3.14.3.2.2": { "d": "md4WitRSA", "c": "Oddball OIW OID", "w": false },
"1.3.14.3.2.3": { "d": "md5WithRSA", "c": "Oddball OIW OID", "w": false },
"1.3.14.3.2.4": { "d": "md4WithRSAEncryption", "c": "Oddball OIW OID", "w": false },
"1.3.14.3.2.2.1": { "d": "sqmod-N", "c": "X.509. Deprecated", "w": true },
"1.3.14.3.2.3.1": { "d": "sqmod-NwithRSA", "c": "X.509. Deprecated", "w": true },
"1.3.14.3.2.6": { "d": "desECB", "c": "", "w": false },
"1.3.14.3.2.7": { "d": "desCBC", "c": "", "w": false },
"1.3.14.3.2.8": { "d": "desOFB", "c": "", "w": false },
"1.3.14.3.2.9": { "d": "desCFB", "c": "", "w": false },
"1.3.14.3.2.10": { "d": "desMAC", "c": "", "w": false },
"1.3.14.3.2.11": { "d": "rsaSignature", "c": "ISO 9796-2, also X9.31 Part 1", "w": false },
"1.3.14.3.2.12": { "d": "dsa", "c": "OIW?, supposedly from an incomplete version of SDN.701 (doesn't match final SDN.701)", "w": true },
"1.3.14.3.2.13": { "d": "dsaWithSHA", "c": "Oddball OIW OID.  Incorrectly used by JDK 1.1 in place of (1 3 14 3 2 27)", "w": true },
"1.3.14.3.2.14": { "d": "mdc2WithRSASignature", "c": "Oddball OIW OID using 9796-2 padding rules", "w": false },
"1.3.14.3.2.15": { "d": "shaWithRSASignature", "c": "Oddball OIW OID using 9796-2 padding rules", "w": false },
"1.3.14.3.2.16": { "d": "dhWithCommonModulus", "c": "Oddball OIW OID. Deprecated, use a plain DH OID instead", "w": true },
"1.3.14.3.2.17": { "d": "desEDE", "c": "Oddball OIW OID. Mode is ECB", "w": false },
"1.3.14.3.2.18": { "d": "sha", "c": "Oddball OIW OID", "w": false },
"1.3.14.3.2.19": { "d": "mdc-2", "c": "Oddball OIW OID, DES-based hash, planned for X9.31 Part 2", "w": false },
"1.3.14.3.2.20": { "d": "dsaCommon", "c": "Oddball OIW OID.  Deprecated, use a plain DSA OID instead", "w": true },
"1.3.14.3.2.21": { "d": "dsaCommonWithSHA", "c": "Oddball OIW OID.  Deprecated, use a plain dsaWithSHA OID instead", "w": true },
"1.3.14.3.2.22": { "d": "rsaKeyTransport", "c": "Oddball OIW OID", "w": false },
"1.3.14.3.2.23": { "d": "keyed-hash-seal", "c": "Oddball OIW OID", "w": false },
"1.3.14.3.2.24": { "d": "md2WithRSASignature", "c": "Oddball OIW OID using 9796-2 padding rules", "w": false },
"1.3.14.3.2.25": { "d": "md5WithRSASignature", "c": "Oddball OIW OID using 9796-2 padding rules", "w": false },
"1.3.14.3.2.26": { "d": "sha1", "c": "OIW", "w": false },
"1.3.14.3.2.27": { "d": "dsaWithSHA1", "c": "OIW. This OID may also be assigned as ripemd-160", "w": false },
"1.3.14.3.2.28": { "d": "dsaWithCommonSHA1", "c": "OIW", "w": false },
"1.3.14.3.2.29": { "d": "sha-1WithRSAEncryption", "c": "Oddball OIW OID", "w": false },
"1.3.14.3.3.1": { "d": "simple-strong-auth-mechanism", "c": "Oddball OIW OID", "w": false },
"1.3.14.7.2.1.1": { "d": "ElGamal", "c": "Unsure about this OID", "w": false },
"1.3.14.7.2.3.1": { "d": "md2WithRSA", "c": "Unsure about this OID", "w": false },
"1.3.14.7.2.3.2": { "d": "md2WithElGamal", "c": "Unsure about this OID", "w": false },
"1.3.36.1": { "d": "document", "c": "Teletrust document", "w": false },
"1.3.36.1.1": { "d": "finalVersion", "c": "Teletrust document", "w": false },
"1.3.36.1.2": { "d": "draft", "c": "Teletrust document", "w": false },
"1.3.36.2": { "d": "sio", "c": "Teletrust sio", "w": false },
"1.3.36.2.1": { "d": "sedu", "c": "Teletrust sio", "w": false },
"1.3.36.3": { "d": "algorithm", "c": "Teletrust algorithm", "w": false },
"1.3.36.3.1": { "d": "encryptionAlgorithm", "c": "Teletrust algorithm", "w": false },
"1.3.36.3.1.1": { "d": "des", "c": "Teletrust encryption algorithm", "w": false },
"1.3.36.3.1.1.1": { "d": "desECB_pad", "c": "Teletrust encryption algorithm", "w": false },
"1.3.36.3.1.1.1.1": { "d": "desECB_ISOpad", "c": "Teletrust encryption algorithm", "w": false },
"1.3.36.3.1.1.2.1": { "d": "desCBC_pad", "c": "Teletrust encryption algorithm", "w": false },
"1.3.36.3.1.1.2.1.1": { "d": "desCBC_ISOpad", "c": "Teletrust encryption algorithm", "w": false },
"1.3.36.3.1.3": { "d": "des_3", "c": "Teletrust encryption algorithm", "w": false },
"1.3.36.3.1.3.1.1": { "d": "des_3ECB_pad", "c": "Teletrust encryption algorithm. EDE triple DES", "w": false },
"1.3.36.3.1.3.1.1.1": { "d": "des_3ECB_ISOpad", "c": "Teletrust encryption algorithm. EDE triple DES", "w": false },
"1.3.36.3.1.3.2.1": { "d": "des_3CBC_pad", "c": "Teletrust encryption algorithm. EDE triple DES", "w": false },
"1.3.36.3.1.3.2.1.1": { "d": "des_3CBC_ISOpad", "c": "Teletrust encryption algorithm. EDE triple DES", "w": false },
"1.3.36.3.1.2": { "d": "idea", "c": "Teletrust encryption algorithm", "w": false },
"1.3.36.3.1.2.1": { "d": "ideaECB", "c": "Teletrust encryption algorithm", "w": false },
"1.3.36.3.1.2.1.1": { "d": "ideaECB_pad", "c": "Teletrust encryption algorithm", "w": false },
"1.3.36.3.1.2.1.1.1": { "d": "ideaECB_ISOpad", "c": "Teletrust encryption algorithm", "w": false },
"1.3.36.3.1.2.2": { "d": "ideaCBC", "c": "Teletrust encryption algorithm", "w": false },
"1.3.36.3.1.2.2.1": { "d": "ideaCBC_pad", "c": "Teletrust encryption algorithm", "w": false },
"1.3.36.3.1.2.2.1.1": { "d": "ideaCBC_ISOpad", "c": "Teletrust encryption algorithm", "w": false },
"1.3.36.3.1.2.3": { "d": "ideaOFB", "c": "Teletrust encryption algorithm", "w": false },
"1.3.36.3.1.2.4": { "d": "ideaCFB", "c": "Teletrust encryption algorithm", "w": false },
"1.3.36.3.1.4": { "d": "rsaEncryption", "c": "Teletrust encryption algorithm", "w": false },
"1.3.36.3.1.4.512.17": { "d": "rsaEncryptionWithlmod512expe17", "c": "Teletrust encryption algorithm", "w": false },
"1.3.36.3.1.5": { "d": "bsi-1", "c": "Teletrust encryption algorithm", "w": false },
"1.3.36.3.1.5.1": { "d": "bsi_1ECB_pad", "c": "Teletrust encryption algorithm", "w": false },
"1.3.36.3.1.5.2": { "d": "bsi_1CBC_pad", "c": "Teletrust encryption algorithm", "w": false },
"1.3.36.3.1.5.2.1": { "d": "bsi_1CBC_PEMpad", "c": "Teletrust encryption algorithm", "w": false },
"1.3.36.3.2": { "d": "hashAlgorithm", "c": "Teletrust algorithm", "w": false },
"1.3.36.3.2.1": { "d": "ripemd160", "c": "Teletrust hash algorithm", "w": false },
"1.3.36.3.2.2": { "d": "ripemd128", "c": "Teletrust hash algorithm", "w": false },
"1.3.36.3.2.3": { "d": "ripemd256", "c": "Teletrust hash algorithm", "w": false },
"1.3.36.3.2.4": { "d": "mdc2singleLength", "c": "Teletrust hash algorithm", "w": false },
"1.3.36.3.2.5": { "d": "mdc2doubleLength", "c": "Teletrust hash algorithm", "w": false },
"1.3.36.3.3": { "d": "signatureAlgorithm", "c": "Teletrust algorithm", "w": false },
"1.3.36.3.3.1": { "d": "rsaSignature", "c": "Teletrust signature algorithm", "w": false },
"1.3.36.3.3.1.1": { "d": "rsaSignatureWithsha1", "c": "Teletrust signature algorithm", "w": false },
"1.3.36.3.3.1.1.1024.11": { "d": "rsaSignatureWithsha1_l1024_l11", "c": "Teletrust signature algorithm", "w": false },
"1.3.36.3.3.1.2": { "d": "rsaSignatureWithripemd160", "c": "Teletrust signature algorithm", "w": false },
"1.3.36.3.3.1.2.1024.11": { "d": "rsaSignatureWithripemd160_l1024_l11", "c": "Teletrust signature algorithm", "w": false },
"1.3.36.3.3.1.3": { "d": "rsaSignatureWithrimpemd128", "c": "Teletrust signature algorithm", "w": false },
"1.3.36.3.3.1.4": { "d": "rsaSignatureWithrimpemd256", "c": "Teletrust signature algorithm", "w": false },
"1.3.36.3.3.2": { "d": "ecsieSign", "c": "Teletrust signature algorithm", "w": false },
"1.3.36.3.3.2.1": { "d": "ecsieSignWithsha1", "c": "Teletrust signature algorithm", "w": false },
"1.3.36.3.3.2.2": { "d": "ecsieSignWithripemd160", "c": "Teletrust signature algorithm", "w": false },
"1.3.36.3.3.2.3": { "d": "ecsieSignWithmd2", "c": "Teletrust signature algorithm", "w": false },
"1.3.36.3.3.2.4": { "d": "ecsieSignWithmd5", "c": "Teletrust signature algorithm", "w": false },
"1.3.36.3.3.2.8.1.1.1": { "d": "brainpoolP160r1", "c": "ECC Brainpool Standard Curves and Curve Generation", "w": false },
"1.3.36.3.3.2.8.1.1.2": { "d": "brainpoolP160t1", "c": "ECC Brainpool Standard Curves and Curve Generation", "w": false },
"1.3.36.3.3.2.8.1.1.3": { "d": "brainpoolP192r1", "c": "ECC Brainpool Standard Curves and Curve Generation", "w": false },
"1.3.36.3.3.2.8.1.1.4": { "d": "brainpoolP192t1", "c": "ECC Brainpool Standard Curves and Curve Generation", "w": false },
"1.3.36.3.3.2.8.1.1.5": { "d": "brainpoolP224r1", "c": "ECC Brainpool Standard Curves and Curve Generation", "w": false },
"1.3.36.3.3.2.8.1.1.6": { "d": "brainpoolP224t1", "c": "ECC Brainpool Standard Curves and Curve Generation", "w": false },
"1.3.36.3.3.2.8.1.1.7": { "d": "brainpoolP256r1", "c": "ECC Brainpool Standard Curves and Curve Generation", "w": false },
"1.3.36.3.3.2.8.1.1.8": { "d": "brainpoolP256t1", "c": "ECC Brainpool Standard Curves and Curve Generation", "w": false },
"1.3.36.3.3.2.8.1.1.9": { "d": "brainpoolP320r1", "c": "ECC Brainpool Standard Curves and Curve Generation", "w": false },
"1.3.36.3.3.2.8.1.1.10": { "d": "brainpoolP320t1", "c": "ECC Brainpool Standard Curves and Curve Generation", "w": false },
"1.3.36.3.3.2.8.1.1.11": { "d": "brainpoolP384r1", "c": "ECC Brainpool Standard Curves and Curve Generation", "w": false },
"1.3.36.3.3.2.8.1.1.12": { "d": "brainpoolP384t1", "c": "ECC Brainpool Standard Curves and Curve Generation", "w": false },
"1.3.36.3.3.2.8.1.1.13": { "d": "brainpoolP512r1", "c": "ECC Brainpool Standard Curves and Curve Generation", "w": false },
"1.3.36.3.3.2.8.1.1.14": { "d": "brainpoolP512t1", "c": "ECC Brainpool Standard Curves and Curve Generation", "w": false },
"1.3.36.3.4": { "d": "signatureScheme", "c": "Teletrust algorithm", "w": false },
"1.3.36.3.4.1": { "d": "sigS_ISO9796-1", "c": "Teletrust signature scheme", "w": false },
"1.3.36.3.4.2": { "d": "sigS_ISO9796-2", "c": "Teletrust signature scheme", "w": false },
"1.3.36.3.4.2.1": { "d": "sigS_ISO9796-2Withred", "c": "Teletrust signature scheme. Unsure what this is supposed to be", "w": false },
"1.3.36.3.4.2.2": { "d": "sigS_ISO9796-2Withrsa", "c": "Teletrust signature scheme. Unsure what this is supposed to be", "w": false },
"1.3.36.3.4.2.3": { "d": "sigS_ISO9796-2Withrnd", "c": "Teletrust signature scheme. 9796-2 with random number in padding field", "w": false },
"1.3.36.4": { "d": "attribute", "c": "Teletrust attribute", "w": false },
"1.3.36.5": { "d": "policy", "c": "Teletrust policy", "w": false },
"1.3.36.6": { "d": "api", "c": "Teletrust API", "w": false },
"1.3.36.6.1": { "d": "manufacturer-specific_api", "c": "Teletrust API", "w": false },
"1.3.36.6.1.1": { "d": "utimaco-api", "c": "Teletrust API", "w": false },
"1.3.36.6.2": { "d": "functionality-specific_api", "c": "Teletrust API", "w": false },
"1.3.36.7": { "d": "keymgmnt", "c": "Teletrust key management", "w": false },
"1.3.36.7.1": { "d": "keyagree", "c": "Teletrust key management", "w": false },
"1.3.36.7.1.1": { "d": "bsiPKE", "c": "Teletrust key management", "w": false },
"1.3.36.7.2": { "d": "keytrans", "c": "Teletrust key management", "w": false },
"1.3.36.7.2.1": { "d": "encISO9796-2Withrsa", "c": "Teletrust key management. 9796-2 with key stored in hash field", "w": false },
"1.3.36.8.1.1": { "d": "Teletrust SigGConform policyIdentifier", "c": "Teletrust policy", "w": false },
"1.3.36.8.2.1": { "d": "directoryService", "c": "Teletrust extended key usage", "w": false },
"1.3.36.8.3.1": { "d": "dateOfCertGen", "c": "Teletrust attribute", "w": false },
"1.3.36.8.3.2": { "d": "procuration", "c": "Teletrust attribute", "w": false },
"1.3.36.8.3.3": { "d": "admission", "c": "Teletrust attribute", "w": false },
"1.3.36.8.3.4": { "d": "monetaryLimit", "c": "Teletrust attribute", "w": false },
"1.3.36.8.3.5": { "d": "declarationOfMajority", "c": "Teletrust attribute", "w": false },
"1.3.36.8.3.6": { "d": "integratedCircuitCardSerialNumber", "c": "Teletrust attribute", "w": false },
"1.3.36.8.3.7": { "d": "pKReference", "c": "Teletrust attribute", "w": false },
"1.3.36.8.3.8": { "d": "restriction", "c": "Teletrust attribute", "w": false },
"1.3.36.8.3.9": { "d": "retrieveIfAllowed", "c": "Teletrust attribute", "w": false },
"1.3.36.8.3.10": { "d": "requestedCertificate", "c": "Teletrust attribute", "w": false },
"1.3.36.8.3.11": { "d": "namingAuthorities", "c": "Teletrust attribute", "w": false },
"1.3.36.8.3.11.1": { "d": "rechtWirtschaftSteuern", "c": "Teletrust naming authorities", "w": false },
"1.3.36.8.3.11.1.1": { "d": "rechtsanwaeltin", "c": "Teletrust ProfessionInfo", "w": false },
"1.3.36.8.3.11.1.2": { "d": "rechtsanwalt", "c": "Teletrust ProfessionInfo", "w": false },
"1.3.36.8.3.11.1.3": { "d": "rechtsBeistand", "c": "Teletrust ProfessionInfo", "w": false },
"1.3.36.8.3.11.1.4": { "d": "steuerBeraterin", "c": "Teletrust ProfessionInfo", "w": false },
"1.3.36.8.3.11.1.5": { "d": "steuerBerater", "c": "Teletrust ProfessionInfo", "w": false },
"1.3.36.8.3.11.1.6": { "d": "steuerBevollmaechtigte", "c": "Teletrust ProfessionInfo", "w": false },
"1.3.36.8.3.11.1.7": { "d": "steuerBevollmaechtigter", "c": "Teletrust ProfessionInfo", "w": false },
"1.3.36.8.3.11.1.8": { "d": "notarin", "c": "Teletrust ProfessionInfo", "w": false },
"1.3.36.8.3.11.1.9": { "d": "notar", "c": "Teletrust ProfessionInfo", "w": false },
"1.3.36.8.3.11.1.10": { "d": "notarVertreterin", "c": "Teletrust ProfessionInfo", "w": false },
"1.3.36.8.3.11.1.11": { "d": "notarVertreter", "c": "Teletrust ProfessionInfo", "w": false },
"1.3.36.8.3.11.1.12": { "d": "notariatsVerwalterin", "c": "Teletrust ProfessionInfo", "w": false },
"1.3.36.8.3.11.1.13": { "d": "notariatsVerwalter", "c": "Teletrust ProfessionInfo", "w": false },
"1.3.36.8.3.11.1.14": { "d": "wirtschaftsPrueferin", "c": "Teletrust ProfessionInfo", "w": false },
"1.3.36.8.3.11.1.15": { "d": "wirtschaftsPruefer", "c": "Teletrust ProfessionInfo", "w": false },
"1.3.36.8.3.11.1.16": { "d": "vereidigteBuchprueferin", "c": "Teletrust ProfessionInfo", "w": false },
"1.3.36.8.3.11.1.17": { "d": "vereidigterBuchpruefer", "c": "Teletrust ProfessionInfo", "w": false },
"1.3.36.8.3.11.1.18": { "d": "patentAnwaeltin", "c": "Teletrust ProfessionInfo", "w": false },
"1.3.36.8.3.11.1.19": { "d": "patentAnwalt", "c": "Teletrust ProfessionInfo", "w": false },
"1.3.36.8.3.12": { "d": "certInDirSince", "c": "Teletrust OCSP attribute (obsolete)", "w": true },
"1.3.36.8.3.13": { "d": "certHash", "c": "Teletrust OCSP attribute", "w": false },
"1.3.36.8.3.14": { "d": "nameAtBirth", "c": "Teletrust attribute", "w": false },
"1.3.36.8.3.15": { "d": "additionalInformation", "c": "Teletrust attribute", "w": false },
"1.3.36.8.4.1": { "d": "personalData", "c": "Teletrust OtherName attribute", "w": false },
"1.3.36.8.4.8": { "d": "restriction", "c": "Teletrust attribute certificate attribute", "w": false },
"1.3.36.8.5.1.1.1": { "d": "rsaIndicateSHA1", "c": "Teletrust signature algorithm", "w": false },
"1.3.36.8.5.1.1.2": { "d": "rsaIndicateRIPEMD160", "c": "Teletrust signature algorithm", "w": false },
"1.3.36.8.5.1.1.3": { "d": "rsaWithSHA1", "c": "Teletrust signature algorithm", "w": false },
"1.3.36.8.5.1.1.4": { "d": "rsaWithRIPEMD160", "c": "Teletrust signature algorithm", "w": false },
"1.3.36.8.5.1.2.1": { "d": "dsaExtended", "c": "Teletrust signature algorithm", "w": false },
"1.3.36.8.5.1.2.2": { "d": "dsaWithRIPEMD160", "c": "Teletrust signature algorithm", "w": false },
"1.3.36.8.6.1": { "d": "cert", "c": "Teletrust signature attributes", "w": false },
"1.3.36.8.6.2": { "d": "certRef", "c": "Teletrust signature attributes", "w": false },
"1.3.36.8.6.3": { "d": "attrCert", "c": "Teletrust signature attributes", "w": false },
"1.3.36.8.6.4": { "d": "attrRef", "c": "Teletrust signature attributes", "w": false },
"1.3.36.8.6.5": { "d": "fileName", "c": "Teletrust signature attributes", "w": false },
"1.3.36.8.6.6": { "d": "storageTime", "c": "Teletrust signature attributes", "w": false },
"1.3.36.8.6.7": { "d": "fileSize", "c": "Teletrust signature attributes", "w": false },
"1.3.36.8.6.8": { "d": "location", "c": "Teletrust signature attributes", "w": false },
"1.3.36.8.6.9": { "d": "sigNumber", "c": "Teletrust signature attributes", "w": false },
"1.3.36.8.6.10": { "d": "autoGen", "c": "Teletrust signature attributes", "w": false },
"1.3.36.8.7.1.1": { "d": "ptAdobeILL", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.2": { "d": "ptAmiPro", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.3": { "d": "ptAutoCAD", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.4": { "d": "ptBinary", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.5": { "d": "ptBMP", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.6": { "d": "ptCGM", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.7": { "d": "ptCorelCRT", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.8": { "d": "ptCorelDRW", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.9": { "d": "ptCorelEXC", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.10": { "d": "ptCorelPHT", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.11": { "d": "ptDraw", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.12": { "d": "ptDVI", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.13": { "d": "ptEPS", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.14": { "d": "ptExcel", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.15": { "d": "ptGEM", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.16": { "d": "ptGIF", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.17": { "d": "ptHPGL", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.18": { "d": "ptJPEG", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.19": { "d": "ptKodak", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.20": { "d": "ptLaTeX", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.21": { "d": "ptLotus", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.22": { "d": "ptLotusPIC", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.23": { "d": "ptMacPICT", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.24": { "d": "ptMacWord", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.25": { "d": "ptMSWfD", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.26": { "d": "ptMSWord", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.27": { "d": "ptMSWord2", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.28": { "d": "ptMSWord6", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.29": { "d": "ptMSWord8", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.30": { "d": "ptPDF", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.31": { "d": "ptPIF", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.32": { "d": "ptPostscript", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.33": { "d": "ptRTF", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.34": { "d": "ptSCITEX", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.35": { "d": "ptTAR", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.36": { "d": "ptTarga", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.37": { "d": "ptTeX", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.38": { "d": "ptText", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.39": { "d": "ptTIFF", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.40": { "d": "ptTIFF-FC", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.41": { "d": "ptUID", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.42": { "d": "ptUUEncode", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.43": { "d": "ptWMF", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.43": { "d": "ptWordPerfect x", "c": "Teletrust presentation types", "w": false },
"1.3.36.8.7.1.45": { "d": "ptWPGrph", "c": "Teletrust presentation types", "w": false },
"1.3.101.1.4": { "d": "thawte-ce", "c": "Thawte", "w": false },
"1.3.101.1.4.1": { "d": "strongExtranet", "c": "Thawte certificate extension", "w": false },
"1.3.132.0.1": { "d": "sect163k1", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.2": { "d": "sect163r1", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.3": { "d": "sect239k1", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.4": { "d": "sect113r1", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.5": { "d": "sect113r2", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.6": { "d": "secp112r1", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.7": { "d": "secp112r2", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.8": { "d": "secp160r1", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.9": { "d": "secp160k1", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.10": { "d": "secp256k1", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.15": { "d": "sect163r2", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.16": { "d": "sect283k1", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.17": { "d": "sect283r1", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.22": { "d": "sect131r1", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.23": { "d": "sect131r2", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.24": { "d": "sect193r1", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.25": { "d": "sect193r2", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.26": { "d": "sect233k1", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.27": { "d": "sect233r1", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.28": { "d": "secp128r1", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.29": { "d": "secp128r2", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.30": { "d": "secp160r2", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.31": { "d": "secp192k1", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.32": { "d": "secp224k1", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.33": { "d": "secp224r1", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.34": { "d": "secp384r1", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.35": { "d": "secp521r1", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.36": { "d": "sect409k1", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.37": { "d": "sect409r1", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.38": { "d": "sect571k1", "c": "SECG (Certicom) named elliptic curve", "w": false },
"1.3.132.0.39": { "d": "sect571r1", "c": "SECG (Certicom) named elliptic curve", "w": false },
"2.5.4.0": { "d": "objectClass", "c": "X.520 DN component", "w": false },
"2.5.4.1": { "d": "aliasedEntryName", "c": "X.520 DN component", "w": false },
"2.5.4.2": { "d": "knowledgeInformation", "c": "X.520 DN component", "w": false },
"2.5.4.3": { "d": "commonName", "c": "X.520 DN component", "w": false },
"2.5.4.4": { "d": "surname", "c": "X.520 DN component", "w": false },
"2.5.4.5": { "d": "serialNumber", "c": "X.520 DN component", "w": false },
"2.5.4.6": { "d": "countryName", "c": "X.520 DN component", "w": false },
"2.5.4.7": { "d": "localityName", "c": "X.520 DN component", "w": false },
"2.5.4.7.1": { "d": "collectiveLocalityName", "c": "X.520 DN component", "w": false },
"2.5.4.8": { "d": "stateOrProvinceName", "c": "X.520 DN component", "w": false },
"2.5.4.8.1": { "d": "collectiveStateOrProvinceName", "c": "X.520 DN component", "w": false },
"2.5.4.9": { "d": "streetAddress", "c": "X.520 DN component", "w": false },
"2.5.4.9.1": { "d": "collectiveStreetAddress", "c": "X.520 DN component", "w": false },
"2.5.4.10": { "d": "organizationName", "c": "X.520 DN component", "w": false },
"2.5.4.10.1": { "d": "collectiveOrganizationName", "c": "X.520 DN component", "w": false },
"2.5.4.11": { "d": "organizationalUnitName", "c": "X.520 DN component", "w": false },
"2.5.4.11.1": { "d": "collectiveOrganizationalUnitName", "c": "X.520 DN component", "w": false },
"2.5.4.12": { "d": "title", "c": "X.520 DN component", "w": false },
"2.5.4.13": { "d": "description", "c": "X.520 DN component", "w": false },
"2.5.4.14": { "d": "searchGuide", "c": "X.520 DN component", "w": false },
"2.5.4.15": { "d": "businessCategory", "c": "X.520 DN component", "w": false },
"2.5.4.16": { "d": "postalAddress", "c": "X.520 DN component", "w": false },
"2.5.4.16.1": { "d": "collectivePostalAddress", "c": "X.520 DN component", "w": false },
"2.5.4.17": { "d": "postalCode", "c": "X.520 DN component", "w": false },
"2.5.4.17.1": { "d": "collectivePostalCode", "c": "X.520 DN component", "w": false },
"2.5.4.18": { "d": "postOfficeBox", "c": "X.520 DN component", "w": false },
"2.5.4.18.1": { "d": "collectivePostOfficeBox", "c": "X.520 DN component", "w": false },
"2.5.4.19": { "d": "physicalDeliveryOfficeName", "c": "X.520 DN component", "w": false },
"2.5.4.19.1": { "d": "collectivePhysicalDeliveryOfficeName", "c": "X.520 DN component", "w": false },
"2.5.4.20": { "d": "telephoneNumber", "c": "X.520 DN component", "w": false },
"2.5.4.20.1": { "d": "collectiveTelephoneNumber", "c": "X.520 DN component", "w": false },
"2.5.4.21": { "d": "telexNumber", "c": "X.520 DN component", "w": false },
"2.5.4.21.1": { "d": "collectiveTelexNumber", "c": "X.520 DN component", "w": false },
"2.5.4.22": { "d": "teletexTerminalIdentifier", "c": "X.520 DN component", "w": false },
"2.5.4.22.1": { "d": "collectiveTeletexTerminalIdentifier", "c": "X.520 DN component", "w": false },
"2.5.4.23": { "d": "facsimileTelephoneNumber", "c": "X.520 DN component", "w": false },
"2.5.4.23.1": { "d": "collectiveFacsimileTelephoneNumber", "c": "X.520 DN component", "w": false },
"2.5.4.24": { "d": "x121Address", "c": "X.520 DN component", "w": false },
"2.5.4.25": { "d": "internationalISDNNumber", "c": "X.520 DN component", "w": false },
"2.5.4.25.1": { "d": "collectiveInternationalISDNNumber", "c": "X.520 DN component", "w": false },
"2.5.4.26": { "d": "registeredAddress", "c": "X.520 DN component", "w": false },
"2.5.4.27": { "d": "destinationIndicator", "c": "X.520 DN component", "w": false },
"2.5.4.28": { "d": "preferredDeliveryMehtod", "c": "X.520 DN component", "w": false },
"2.5.4.29": { "d": "presentationAddress", "c": "X.520 DN component", "w": false },
"2.5.4.30": { "d": "supportedApplicationContext", "c": "X.520 DN component", "w": false },
"2.5.4.31": { "d": "member", "c": "X.520 DN component", "w": false },
"2.5.4.32": { "d": "owner", "c": "X.520 DN component", "w": false },
"2.5.4.33": { "d": "roleOccupant", "c": "X.520 DN component", "w": false },
"2.5.4.34": { "d": "seeAlso", "c": "X.520 DN component", "w": false },
"2.5.4.35": { "d": "userPassword", "c": "X.520 DN component", "w": false },
"2.5.4.36": { "d": "userCertificate", "c": "X.520 DN component", "w": false },
"2.5.4.37": { "d": "caCertificate", "c": "X.520 DN component", "w": false },
"2.5.4.38": { "d": "authorityRevocationList", "c": "X.520 DN component", "w": false },
"2.5.4.39": { "d": "certificateRevocationList", "c": "X.520 DN component", "w": false },
"2.5.4.40": { "d": "crossCertificatePair", "c": "X.520 DN component", "w": false },
"2.5.4.41": { "d": "name", "c": "X.520 DN component", "w": false },
"2.5.4.42": { "d": "givenName", "c": "X.520 DN component", "w": false },
"2.5.4.43": { "d": "initials", "c": "X.520 DN component", "w": false },
"2.5.4.44": { "d": "generationQualifier", "c": "X.520 DN component", "w": false },
"2.5.4.45": { "d": "uniqueIdentifier", "c": "X.520 DN component", "w": false },
"2.5.4.46": { "d": "dnQualifier", "c": "X.520 DN component", "w": false },
"2.5.4.47": { "d": "enhancedSearchGuide", "c": "X.520 DN component", "w": false },
"2.5.4.48": { "d": "protocolInformation", "c": "X.520 DN component", "w": false },
"2.5.4.49": { "d": "distinguishedName", "c": "X.520 DN component", "w": false },
"2.5.4.50": { "d": "uniqueMember", "c": "X.520 DN component", "w": false },
"2.5.4.51": { "d": "houseIdentifier", "c": "X.520 DN component", "w": false },
"2.5.4.52": { "d": "supportedAlgorithms", "c": "X.520 DN component", "w": false },
"2.5.4.53": { "d": "deltaRevocationList", "c": "X.520 DN component", "w": false },
"2.5.4.54": { "d": "dmdName", "c": "X.520 DN component", "w": false },
"2.5.4.55": { "d": "clearance", "c": "X.520 DN component", "w": false },
"2.5.4.56": { "d": "defaultDirQop", "c": "X.520 DN component", "w": false },
"2.5.4.57": { "d": "attributeIntegrityInfo", "c": "X.520 DN component", "w": false },
"2.5.4.58": { "d": "attributeCertificate", "c": "X.520 DN component", "w": false },
"2.5.4.59": { "d": "attributeCertificateRevocationList", "c": "X.520 DN component", "w": false },
"2.5.4.60": { "d": "confKeyInfo", "c": "X.520 DN component", "w": false },
"2.5.4.61": { "d": "aACertificate", "c": "X.520 DN component", "w": false },
"2.5.4.62": { "d": "attributeDescriptorCertificate", "c": "X.520 DN component", "w": false },
"2.5.4.63": { "d": "attributeAuthorityRevocationList", "c": "X.520 DN component", "w": false },
"2.5.4.64": { "d": "familyInformation", "c": "X.520 DN component", "w": false },
"2.5.4.65": { "d": "pseudonym", "c": "X.520 DN component", "w": false },
"2.5.4.66": { "d": "communicationsService", "c": "X.520 DN component", "w": false },
"2.5.4.67": { "d": "communicationsNetwork", "c": "X.520 DN component", "w": false },
"2.5.4.68": { "d": "certificationPracticeStmt", "c": "X.520 DN component", "w": false },
"2.5.4.69": { "d": "certificatePolicy", "c": "X.520 DN component", "w": false },
"2.5.4.70": { "d": "pkiPath", "c": "X.520 DN component", "w": false },
"2.5.4.71": { "d": "privPolicy", "c": "X.520 DN component", "w": false },
"2.5.4.72": { "d": "role", "c": "X.520 DN component", "w": false },
"2.5.4.73": { "d": "delegationPath", "c": "X.520 DN component", "w": false },
"2.5.6.0": { "d": "top", "c": "X.520 objectClass", "w": false },
"2.5.6.1": { "d": "alias", "c": "X.520 objectClass", "w": false },
"2.5.6.2": { "d": "country", "c": "X.520 objectClass", "w": false },
"2.5.6.3": { "d": "locality", "c": "X.520 objectClass", "w": false },
"2.5.6.4": { "d": "organization", "c": "X.520 objectClass", "w": false },
"2.5.6.5": { "d": "organizationalUnit", "c": "X.520 objectClass", "w": false },
"2.5.6.6": { "d": "person", "c": "X.520 objectClass", "w": false },
"2.5.6.7": { "d": "organizationalPerson", "c": "X.520 objectClass", "w": false },
"2.5.6.8": { "d": "organizationalRole", "c": "X.520 objectClass", "w": false },
"2.5.6.9": { "d": "groupOfNames", "c": "X.520 objectClass", "w": false },
"2.5.6.10": { "d": "residentialPerson", "c": "X.520 objectClass", "w": false },
"2.5.6.11": { "d": "applicationProcess", "c": "X.520 objectClass", "w": false },
"2.5.6.12": { "d": "applicationEntity", "c": "X.520 objectClass", "w": false },
"2.5.6.13": { "d": "dSA", "c": "X.520 objectClass", "w": false },
"2.5.6.14": { "d": "device", "c": "X.520 objectClass", "w": false },
"2.5.6.15": { "d": "strongAuthenticationUser", "c": "X.520 objectClass", "w": false },
"2.5.6.16": { "d": "certificateAuthority", "c": "X.520 objectClass", "w": false },
"2.5.6.17": { "d": "groupOfUniqueNames", "c": "X.520 objectClass", "w": false },
"2.5.6.21": { "d": "pkiUser", "c": "X.520 objectClass", "w": false },
"2.5.6.22": { "d": "pkiCA", "c": "X.520 objectClass", "w": false },
"2.5.8.1.1": { "d": "rsa", "c": "X.500 algorithms.  Ambiguous, since no padding rules specified", "w": true },
"2.5.29.1": { "d": "authorityKeyIdentifier", "c": "X.509 extension.  Deprecated, use 2 5 29 35 instead", "w": true },
"2.5.29.2": { "d": "keyAttributes", "c": "X.509 extension.  Obsolete, use keyUsage/extKeyUsage instead", "w": true },
"2.5.29.3": { "d": "certificatePolicies", "c": "X.509 extension.  Deprecated, use 2 5 29 32 instead", "w": true },
"2.5.29.4": { "d": "keyUsageRestriction", "c": "X.509 extension.  Obsolete, use keyUsage/extKeyUsage instead", "w": true },
"2.5.29.5": { "d": "policyMapping", "c": "X.509 extension.  Deprecated, use 2 5 29 33 instead", "w": true },
"2.5.29.6": { "d": "subtreesConstraint", "c": "X.509 extension.  Obsolete, use nameConstraints instead", "w": true },
"2.5.29.7": { "d": "subjectAltName", "c": "X.509 extension.  Deprecated, use 2 5 29 17 instead", "w": true },
"2.5.29.8": { "d": "issuerAltName", "c": "X.509 extension.  Deprecated, use 2 5 29 18 instead", "w": true },
"2.5.29.9": { "d": "subjectDirectoryAttributes", "c": "X.509 extension", "w": false },
"2.5.29.10": { "d": "basicConstraints", "c": "X.509 extension.  Deprecated, use 2 5 29 19 instead", "w": true },
"2.5.29.11": { "d": "nameConstraints", "c": "X.509 extension.  Deprecated, use 2 5 29 30 instead", "w": true },
"2.5.29.12": { "d": "policyConstraints", "c": "X.509 extension.  Deprecated, use 2 5 29 36 instead", "w": true },
"2.5.29.13": { "d": "basicConstraints", "c": "X.509 extension.  Deprecated, use 2 5 29 19 instead", "w": true },
"2.5.29.14": { "d": "subjectKeyIdentifier", "c": "X.509 extension", "w": false },
"2.5.29.15": { "d": "keyUsage", "c": "X.509 extension", "w": false },
"2.5.29.16": { "d": "privateKeyUsagePeriod", "c": "X.509 extension", "w": false },
"2.5.29.17": { "d": "subjectAltName", "c": "X.509 extension", "w": false },
"2.5.29.18": { "d": "issuerAltName", "c": "X.509 extension", "w": false },
"2.5.29.19": { "d": "basicConstraints", "c": "X.509 extension", "w": false },
"2.5.29.20": { "d": "cRLNumber", "c": "X.509 extension", "w": false },
"2.5.29.21": { "d": "cRLReason", "c": "X.509 extension", "w": false },
"2.5.29.22": { "d": "expirationDate", "c": "X.509 extension.  Deprecated, alternative OID uncertain", "w": true },
"2.5.29.23": { "d": "instructionCode", "c": "X.509 extension", "w": false },
"2.5.29.24": { "d": "invalidityDate", "c": "X.509 extension", "w": false },
"2.5.29.25": { "d": "cRLDistributionPoints", "c": "X.509 extension.  Deprecated, use 2 5 29 31 instead", "w": true },
"2.5.29.26": { "d": "issuingDistributionPoint", "c": "X.509 extension.  Deprecated, use 2 5 29 28 instead", "w": true },
"2.5.29.27": { "d": "deltaCRLIndicator", "c": "X.509 extension", "w": false },
"2.5.29.28": { "d": "issuingDistributionPoint", "c": "X.509 extension", "w": false },
"2.5.29.29": { "d": "certificateIssuer", "c": "X.509 extension", "w": false },
"2.5.29.30": { "d": "nameConstraints", "c": "X.509 extension", "w": false },
"2.5.29.31": { "d": "cRLDistributionPoints", "c": "X.509 extension", "w": false },
"2.5.29.32": { "d": "certificatePolicies", "c": "X.509 extension", "w": false },
"2.5.29.32.0": { "d": "anyPolicy", "c": "X.509 certificate policy", "w": false },
"2.5.29.33": { "d": "policyMappings", "c": "X.509 extension", "w": false },
"2.5.29.34": { "d": "policyConstraints", "c": "X.509 extension.  Deprecated, use 2 5 29 36 instead", "w": true },
"2.5.29.35": { "d": "authorityKeyIdentifier", "c": "X.509 extension", "w": false },
"2.5.29.36": { "d": "policyConstraints", "c": "X.509 extension", "w": false },
"2.5.29.37": { "d": "extKeyUsage", "c": "X.509 extension", "w": false },
"2.5.29.37.0": { "d": "anyExtendedKeyUsage", "c": "X.509 extended key usage", "w": false },
"2.5.29.46": { "d": "freshestCRL", "c": "X.509 extension", "w": false },
"2.5.29.54": { "d": "inhibitAnyPolicy", "c": "X.509 extension", "w": false },
"2.16.840.1.101.2.1.1.1": { "d": "sdnsSignatureAlgorithm", "c": "SDN.700 INFOSEC algorithms", "w": false },
"2.16.840.1.101.2.1.1.2": { "d": "fortezzaSignatureAlgorithm", "c": "SDN.700 INFOSEC algorithms.  Formerly known as mosaicSignatureAlgorithm, this OID is better known as dsaWithSHA-1.", "w": false },
"2.16.840.1.101.2.1.1.3": { "d": "sdnsConfidentialityAlgorithm", "c": "SDN.700 INFOSEC algorithms", "w": false },
"2.16.840.1.101.2.1.1.4": { "d": "fortezzaConfidentialityAlgorithm", "c": "SDN.700 INFOSEC algorithms.  Formerly known as mosaicConfidentialityAlgorithm", "w": false },
"2.16.840.1.101.2.1.1.5": { "d": "sdnsIntegrityAlgorithm", "c": "SDN.700 INFOSEC algorithms", "w": false },
"2.16.840.1.101.2.1.1.6": { "d": "fortezzaIntegrityAlgorithm", "c": "SDN.700 INFOSEC algorithms.  Formerly known as mosaicIntegrityAlgorithm", "w": false },
"2.16.840.1.101.2.1.1.7": { "d": "sdnsTokenProtectionAlgorithm", "c": "SDN.700 INFOSEC algorithms", "w": false },
"2.16.840.1.101.2.1.1.8": { "d": "fortezzaTokenProtectionAlgorithm", "c": "SDN.700 INFOSEC algorithms.  Formerly know as mosaicTokenProtectionAlgorithm", "w": false },
"2.16.840.1.101.2.1.1.9": { "d": "sdnsKeyManagementAlgorithm", "c": "SDN.700 INFOSEC algorithms", "w": false },
"2.16.840.1.101.2.1.1.10": { "d": "fortezzaKeyManagementAlgorithm", "c": "SDN.700 INFOSEC algorithms.  Formerly known as mosaicKeyManagementAlgorithm", "w": false },
"2.16.840.1.101.2.1.1.11": { "d": "sdnsKMandSigAlgorithm", "c": "SDN.700 INFOSEC algorithms", "w": false },
"2.16.840.1.101.2.1.1.12": { "d": "fortezzaKMandSigAlgorithm", "c": "SDN.700 INFOSEC algorithms.  Formerly known as mosaicKMandSigAlgorithm", "w": false },
"2.16.840.1.101.2.1.1.13": { "d": "suiteASignatureAlgorithm", "c": "SDN.700 INFOSEC algorithms", "w": false },
"2.16.840.1.101.2.1.1.14": { "d": "suiteAConfidentialityAlgorithm", "c": "SDN.700 INFOSEC algorithms", "w": false },
"2.16.840.1.101.2.1.1.15": { "d": "suiteAIntegrityAlgorithm", "c": "SDN.700 INFOSEC algorithms", "w": false },
"2.16.840.1.101.2.1.1.16": { "d": "suiteATokenProtectionAlgorithm", "c": "SDN.700 INFOSEC algorithms", "w": false },
"2.16.840.1.101.2.1.1.17": { "d": "suiteAKeyManagementAlgorithm", "c": "SDN.700 INFOSEC algorithms", "w": false },
"2.16.840.1.101.2.1.1.18": { "d": "suiteAKMandSigAlgorithm", "c": "SDN.700 INFOSEC algorithms", "w": false },
"2.16.840.1.101.2.1.1.19": { "d": "fortezzaUpdatedSigAlgorithm", "c": "SDN.700 INFOSEC algorithms.  Formerly known as mosaicUpdatedSigAlgorithm", "w": false },
"2.16.840.1.101.2.1.1.20": { "d": "fortezzaKMandUpdSigAlgorithms", "c": "SDN.700 INFOSEC algorithms.  Formerly known as mosaicKMandUpdSigAlgorithms", "w": false },
"2.16.840.1.101.2.1.1.21": { "d": "fortezzaUpdatedIntegAlgorithm", "c": "SDN.700 INFOSEC algorithms.  Formerly known as mosaicUpdatedIntegAlgorithm", "w": false },
"2.16.840.1.101.2.1.1.22": { "d": "keyExchangeAlgorithm", "c": "SDN.700 INFOSEC algorithms.  Formerly known as mosaicKeyEncryptionAlgorithm", "w": false },
"2.16.840.1.101.2.1.1.23": { "d": "fortezzaWrap80Algorithm", "c": "SDN.700 INFOSEC algorithms", "w": false },
"2.16.840.1.101.2.1.1.24": { "d": "kEAKeyEncryptionAlgorithm", "c": "SDN.700 INFOSEC algorithms", "w": false },
"2.16.840.1.101.2.1.2.1": { "d": "rfc822MessageFormat", "c": "SDN.700 INFOSEC format", "w": false },
"2.16.840.1.101.2.1.2.2": { "d": "emptyContent", "c": "SDN.700 INFOSEC format", "w": false },
"2.16.840.1.101.2.1.2.3": { "d": "cspContentType", "c": "SDN.700 INFOSEC format", "w": false },
"2.16.840.1.101.2.1.2.42": { "d": "mspRev3ContentType", "c": "SDN.700 INFOSEC format", "w": false },
"2.16.840.1.101.2.1.2.48": { "d": "mspContentType", "c": "SDN.700 INFOSEC format", "w": false },
"2.16.840.1.101.2.1.2.49": { "d": "mspRekeyAgentProtocol", "c": "SDN.700 INFOSEC format", "w": false },
"2.16.840.1.101.2.1.2.50": { "d": "mspMMP", "c": "SDN.700 INFOSEC format", "w": false },
"2.16.840.1.101.2.1.2.66": { "d": "mspRev3-1ContentType", "c": "SDN.700 INFOSEC format", "w": false },
"2.16.840.1.101.2.1.2.72": { "d": "forwardedMSPMessageBodyPart", "c": "SDN.700 INFOSEC format", "w": false },
"2.16.840.1.101.2.1.2.73": { "d": "mspForwardedMessageParameters", "c": "SDN.700 INFOSEC format", "w": false },
"2.16.840.1.101.2.1.2.74": { "d": "forwardedCSPMsgBodyPart", "c": "SDN.700 INFOSEC format", "w": false },
"2.16.840.1.101.2.1.2.75": { "d": "cspForwardedMessageParameters", "c": "SDN.700 INFOSEC format", "w": false },
"2.16.840.1.101.2.1.2.76": { "d": "mspMMP2", "c": "SDN.700 INFOSEC format", "w": false },
"2.16.840.1.101.2.1.3.1": { "d": "sdnsSecurityPolicy", "c": "SDN.700 INFOSEC policy", "w": false },
"2.16.840.1.101.2.1.3.2": { "d": "sdnsPRBAC", "c": "SDN.700 INFOSEC policy", "w": false },
"2.16.840.1.101.2.1.3.3": { "d": "mosaicPRBAC", "c": "SDN.700 INFOSEC policy", "w": false },
"2.16.840.1.101.2.1.3.10": { "d": "siSecurityPolicy", "c": "SDN.700 INFOSEC policy", "w": false },
"2.16.840.1.101.2.1.3.10.0": { "d": "siNASP", "c": "SDN.700 INFOSEC policy (obsolete)", "w": true },
"2.16.840.1.101.2.1.3.10.1": { "d": "siELCO", "c": "SDN.700 INFOSEC policy (obsolete)", "w": true },
"2.16.840.1.101.2.1.3.10.2": { "d": "siTK", "c": "SDN.700 INFOSEC policy (obsolete)", "w": true },
"2.16.840.1.101.2.1.3.10.3": { "d": "siDSAP", "c": "SDN.700 INFOSEC policy (obsolete)", "w": true },
"2.16.840.1.101.2.1.3.10.4": { "d": "siSSSS", "c": "SDN.700 INFOSEC policy (obsolete)", "w": true },
"2.16.840.1.101.2.1.3.10.5": { "d": "siDNASP", "c": "SDN.700 INFOSEC policy (obsolete)", "w": true },
"2.16.840.1.101.2.1.3.10.6": { "d": "siBYEMAN", "c": "SDN.700 INFOSEC policy (obsolete)", "w": true },
"2.16.840.1.101.2.1.3.10.7": { "d": "siREL-US", "c": "SDN.700 INFOSEC policy (obsolete)", "w": true },
"2.16.840.1.101.2.1.3.10.8": { "d": "siREL-AUS", "c": "SDN.700 INFOSEC policy (obsolete)", "w": true },
"2.16.840.1.101.2.1.3.10.9": { "d": "siREL-CAN", "c": "SDN.700 INFOSEC policy (obsolete)", "w": true },
"2.16.840.1.101.2.1.3.10.10": { "d": "siREL_UK", "c": "SDN.700 INFOSEC policy (obsolete)", "w": true },
"2.16.840.1.101.2.1.3.10.11": { "d": "siREL-NZ", "c": "SDN.700 INFOSEC policy (obsolete)", "w": true },
"2.16.840.1.101.2.1.3.10.12": { "d": "siGeneric", "c": "SDN.700 INFOSEC policy (obsolete)", "w": true },
"2.16.840.1.101.2.1.3.11": { "d": "genser", "c": "SDN.700 INFOSEC policy", "w": false },
"2.16.840.1.101.2.1.3.11.0": { "d": "genserNations", "c": "SDN.700 INFOSEC policy (obsolete)", "w": true },
"2.16.840.1.101.2.1.3.11.1": { "d": "genserComsec", "c": "SDN.700 INFOSEC policy (obsolete)", "w": true },
"2.16.840.1.101.2.1.3.11.2": { "d": "genserAcquisition", "c": "SDN.700 INFOSEC policy (obsolete)", "w": true },
"2.16.840.1.101.2.1.3.11.3": { "d": "genserSecurityCategories", "c": "SDN.700 INFOSEC policy", "w": false },
"2.16.840.1.101.2.1.3.11.3.0": { "d": "genserTagSetName", "c": "SDN.700 INFOSEC GENSER policy", "w": false },
"2.16.840.1.101.2.1.3.12": { "d": "defaultSecurityPolicy", "c": "SDN.700 INFOSEC policy", "w": false },
"2.16.840.1.101.2.1.3.13": { "d": "capcoMarkings", "c": "SDN.700 INFOSEC policy", "w": false },
"2.16.840.1.101.2.1.3.13.0": { "d": "capcoSecurityCategories", "c": "SDN.700 INFOSEC policy CAPCO markings", "w": false },
"2.16.840.1.101.2.1.3.13.0.1": { "d": "capcoTagSetName1", "c": "SDN.700 INFOSEC policy CAPCO markings", "w": false },
"2.16.840.1.101.2.1.3.13.0.2": { "d": "capcoTagSetName2", "c": "SDN.700 INFOSEC policy CAPCO markings", "w": false },
"2.16.840.1.101.2.1.3.13.0.3": { "d": "capcoTagSetName3", "c": "SDN.700 INFOSEC policy CAPCO markings", "w": false },
"2.16.840.1.101.2.1.3.13.0.4": { "d": "capcoTagSetName4", "c": "SDN.700 INFOSEC policy CAPCO markings", "w": false },
"2.16.840.1.101.2.1.5.1": { "d": "sdnsKeyManagementCertificate", "c": "SDN.700 INFOSEC attributes (superseded)", "w": true },
"2.16.840.1.101.2.1.5.2": { "d": "sdnsUserSignatureCertificate", "c": "SDN.700 INFOSEC attributes (superseded)", "w": true },
"2.16.840.1.101.2.1.5.3": { "d": "sdnsKMandSigCertificate", "c": "SDN.700 INFOSEC attributes (superseded)", "w": true },
"2.16.840.1.101.2.1.5.4": { "d": "fortezzaKeyManagementCertificate", "c": "SDN.700 INFOSEC attributes (superseded)", "w": true },
"2.16.840.1.101.2.1.5.5": { "d": "fortezzaKMandSigCertificate", "c": "SDN.700 INFOSEC attributes (superseded)", "w": true },
"2.16.840.1.101.2.1.5.6": { "d": "fortezzaUserSignatureCertificate", "c": "SDN.700 INFOSEC attributes (superseded)", "w": true },
"2.16.840.1.101.2.1.5.7": { "d": "fortezzaCASignatureCertificate", "c": "SDN.700 INFOSEC attributes (superseded)", "w": true },
"2.16.840.1.101.2.1.5.8": { "d": "sdnsCASignatureCertificate", "c": "SDN.700 INFOSEC attributes (superseded)", "w": true },
"2.16.840.1.101.2.1.5.10": { "d": "auxiliaryVector", "c": "SDN.700 INFOSEC attributes (superseded)", "w": true },
"2.16.840.1.101.2.1.5.11": { "d": "mlReceiptPolicy", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.12": { "d": "mlMembership", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.13": { "d": "mlAdministrators", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.14": { "d": "alid", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.20": { "d": "janUKMs", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.21": { "d": "febUKMs", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.22": { "d": "marUKMs", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.23": { "d": "aprUKMs", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.24": { "d": "mayUKMs", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.25": { "d": "junUKMs", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.26": { "d": "julUKMs", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.27": { "d": "augUKMs", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.28": { "d": "sepUKMs", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.29": { "d": "octUKMs", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.30": { "d": "novUKMs", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.31": { "d": "decUKMs", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.40": { "d": "metaSDNSckl", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.41": { "d": "sdnsCKL", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.42": { "d": "metaSDNSsignatureCKL", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.43": { "d": "sdnsSignatureCKL", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.44": { "d": "sdnsCertificateRevocationList", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.45": { "d": "fortezzaCertificateRevocationList", "c": "SDN.700 INFOSEC attributes (superseded)", "w": true },
"2.16.840.1.101.2.1.5.46": { "d": "fortezzaCKL", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.47": { "d": "alExemptedAddressProcessor", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.48": { "d": "guard", "c": "SDN.700 INFOSEC attributes (obsolete)", "w": true },
"2.16.840.1.101.2.1.5.49": { "d": "algorithmsSupported", "c": "SDN.700 INFOSEC attributes (obsolete)", "w": true },
"2.16.840.1.101.2.1.5.50": { "d": "suiteAKeyManagementCertificate", "c": "SDN.700 INFOSEC attributes (obsolete)", "w": true },
"2.16.840.1.101.2.1.5.51": { "d": "suiteAKMandSigCertificate", "c": "SDN.700 INFOSEC attributes (obsolete)", "w": true },
"2.16.840.1.101.2.1.5.52": { "d": "suiteAUserSignatureCertificate", "c": "SDN.700 INFOSEC attributes (obsolete)", "w": true },
"2.16.840.1.101.2.1.5.53": { "d": "prbacInfo", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.54": { "d": "prbacCAConstraints", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.55": { "d": "sigOrKMPrivileges", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.56": { "d": "commPrivileges", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.57": { "d": "labeledAttribute", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.58": { "d": "policyInformationFile", "c": "SDN.700 INFOSEC attributes (obsolete)", "w": true },
"2.16.840.1.101.2.1.5.59": { "d": "secPolicyInformationFile", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.5.60": { "d": "cAClearanceConstraint", "c": "SDN.700 INFOSEC attributes", "w": false },
"2.16.840.1.101.2.1.7.1": { "d": "cspExtns", "c": "SDN.700 INFOSEC extensions", "w": false },
"2.16.840.1.101.2.1.7.1.0": { "d": "cspCsExtn", "c": "SDN.700 INFOSEC extensions", "w": false },
"2.16.840.1.101.2.1.8.1": { "d": "mISSISecurityCategories", "c": "SDN.700 INFOSEC security category", "w": false },
"2.16.840.1.101.2.1.8.2": { "d": "standardSecurityLabelPrivileges", "c": "SDN.700 INFOSEC security category", "w": false },
"2.16.840.1.101.2.1.10.1": { "d": "sigPrivileges", "c": "SDN.700 INFOSEC privileges", "w": false },
"2.16.840.1.101.2.1.10.2": { "d": "kmPrivileges", "c": "SDN.700 INFOSEC privileges", "w": false },
"2.16.840.1.101.2.1.10.3": { "d": "namedTagSetPrivilege", "c": "SDN.700 INFOSEC privileges", "w": false },
"2.16.840.1.101.2.1.11.1": { "d": "ukDemo", "c": "SDN.700 INFOSEC certificate policy", "w": false },
"2.16.840.1.101.2.1.11.2": { "d": "usDODClass2", "c": "SDN.700 INFOSEC certificate policy", "w": false },
"2.16.840.1.101.2.1.11.3": { "d": "usMediumPilot", "c": "SDN.700 INFOSEC certificate policy", "w": false },
"2.16.840.1.101.2.1.11.4": { "d": "usDODClass4", "c": "SDN.700 INFOSEC certificate policy", "w": false },
"2.16.840.1.101.2.1.11.5": { "d": "usDODClass3", "c": "SDN.700 INFOSEC certificate policy", "w": false },
"2.16.840.1.101.2.1.11.6": { "d": "usDODClass5", "c": "SDN.700 INFOSEC certificate policy", "w": false },
"2.16.840.1.101.2.1.12.0": { "d": "testSecurityPolicy", "c": "SDN.700 INFOSEC test objects", "w": false },
"2.16.840.1.101.2.1.12.0.1": { "d": "tsp1", "c": "SDN.700 INFOSEC test objects", "w": false },
"2.16.840.1.101.2.1.12.0.1.0": { "d": "tsp1SecurityCategories", "c": "SDN.700 INFOSEC test objects", "w": false },
"2.16.840.1.101.2.1.12.0.1.0.0": { "d": "tsp1TagSetZero", "c": "SDN.700 INFOSEC test objects", "w": false },
"2.16.840.1.101.2.1.12.0.1.0.1": { "d": "tsp1TagSetOne", "c": "SDN.700 INFOSEC test objects", "w": false },
"2.16.840.1.101.2.1.12.0.1.0.2": { "d": "tsp1TagSetTwo", "c": "SDN.700 INFOSEC test objects", "w": false },
"2.16.840.1.101.2.1.12.0.2": { "d": "tsp2", "c": "SDN.700 INFOSEC test objects", "w": false },
"2.16.840.1.101.2.1.12.0.2.0": { "d": "tsp2SecurityCategories", "c": "SDN.700 INFOSEC test objects", "w": false },
"2.16.840.1.101.2.1.12.0.2.0.0": { "d": "tsp2TagSetZero", "c": "SDN.700 INFOSEC test objects", "w": false },
"2.16.840.1.101.2.1.12.0.2.0.1": { "d": "tsp2TagSetOne", "c": "SDN.700 INFOSEC test objects", "w": false },
"2.16.840.1.101.2.1.12.0.2.0.2": { "d": "tsp2TagSetTwo", "c": "SDN.700 INFOSEC test objects", "w": false },
"2.16.840.1.101.2.1.12.0.3": { "d": "kafka", "c": "SDN.700 INFOSEC test objects", "w": false },
"2.16.840.1.101.2.1.12.0.3.0": { "d": "kafkaSecurityCategories", "c": "SDN.700 INFOSEC test objects", "w": false },
"2.16.840.1.101.2.1.12.0.3.0.1": { "d": "kafkaTagSetName1", "c": "SDN.700 INFOSEC test objects", "w": false },
"2.16.840.1.101.2.1.12.0.3.0.2": { "d": "kafkaTagSetName2", "c": "SDN.700 INFOSEC test objects", "w": false },
"2.16.840.1.101.2.1.12.0.3.0.3": { "d": "kafkaTagSetName3", "c": "SDN.700 INFOSEC test objects", "w": false },
"2.16.840.1.101.2.1.12.1.1": { "d": "tcp1", "c": "SDN.700 INFOSEC test objects", "w": false },
"2.16.840.1.101.3.1": { "d": "slabel", "c": "CSOR GAK", "w": true },
"2.16.840.1.101.3.2": { "d": "pki", "c": "CSOR GAK", "w": true },
"2.16.840.1.101.3.2.1": { "d": "GAK policyIdentifier", "c": "CSOR GAK policy", "w": true },
"2.16.840.1.101.3.2.1.3.1": { "d": "fbcaRudimentary policyIdentifier", "c": "Federal Bridge CA Policy", "w": false },
"2.16.840.1.101.3.2.1.3.2": { "d": "fbcaBasic policyIdentifier", "c": "Federal Bridge CA Policy", "w": false },
"2.16.840.1.101.3.2.1.3.3": { "d": "fbcaMedium policyIdentifier", "c": "Federal Bridge CA Policy", "w": false },
"2.16.840.1.101.3.2.1.3.4": { "d": "fbcaHigh policyIdentifier", "c": "Federal Bridge CA Policy", "w": false },
"2.16.840.1.101.3.2.2": { "d": "gak", "c": "CSOR GAK extended key usage", "w": true },
"2.16.840.1.101.3.2.2.1": { "d": "kRAKey", "c": "CSOR GAK extended key usage", "w": true },
"2.16.840.1.101.3.2.3": { "d": "extensions", "c": "CSOR GAK extensions", "w": true },
"2.16.840.1.101.3.2.3.1": { "d": "kRTechnique", "c": "CSOR GAK extensions", "w": true },
"2.16.840.1.101.3.2.3.2": { "d": "kRecoveryCapable", "c": "CSOR GAK extensions", "w": true },
"2.16.840.1.101.3.2.3.3": { "d": "kR", "c": "CSOR GAK extensions", "w": true },
"2.16.840.1.101.3.2.4": { "d": "keyRecoverySchemes", "c": "CSOR GAK", "w": true },
"2.16.840.1.101.3.2.5": { "d": "krapola", "c": "CSOR GAK", "w": true },
"2.16.840.1.101.3.3": { "d": "arpa", "c": "CSOR GAK", "w": true },
"2.16.840.1.101.3.4": { "d": "nistAlgorithm", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.1": { "d": "aes", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.1.1": { "d": "aes128-ECB", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.1.2": { "d": "aes128-CBC", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.1.3": { "d": "aes128-OFB", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.1.4": { "d": "aes128-CFB", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.1.21": { "d": "aes192-ECB", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.1.22": { "d": "aes192-CBC", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.1.23": { "d": "aes192-OFB", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.1.24": { "d": "aes192-CFB", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.1.41": { "d": "aes256-ECB", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.1.42": { "d": "aes256-CBC", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.1.43": { "d": "aes256-OFB", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.1.44": { "d": "aes256-CFB", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.2": { "d": "hashAlgos", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.2.1": { "d": "sha-256", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.2.2": { "d": "sha-384", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.2.3": { "d": "sha-512", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.2.4": { "d": "sha-224", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.3.1": { "d": "dsaWithSha224", "c": "NIST Algorithm", "w": false },
"2.16.840.1.101.3.4.3.2": { "d": "dsaWithSha256", "c": "NIST Algorithm", "w": false },
"2.16.840.1.113719.1.2.8": { "d": "novellAlgorithm", "c": "Novell", "w": false },
"2.16.840.1.113719.1.2.8.22": { "d": "desCbcIV8", "c": "Novell encryption algorithm", "w": false },
"2.16.840.1.113719.1.2.8.23": { "d": "desCbcPadIV8", "c": "Novell encryption algorithm", "w": false },
"2.16.840.1.113719.1.2.8.24": { "d": "desEDE2CbcIV8", "c": "Novell encryption algorithm", "w": false },
"2.16.840.1.113719.1.2.8.25": { "d": "desEDE2CbcPadIV8", "c": "Novell encryption algorithm", "w": false },
"2.16.840.1.113719.1.2.8.26": { "d": "desEDE3CbcIV8", "c": "Novell encryption algorithm", "w": false },
"2.16.840.1.113719.1.2.8.27": { "d": "desEDE3CbcPadIV8", "c": "Novell encryption algorithm", "w": false },
"2.16.840.1.113719.1.2.8.28": { "d": "rc5CbcPad", "c": "Novell encryption algorithm", "w": false },
"2.16.840.1.113719.1.2.8.29": { "d": "md2WithRSAEncryptionBSafe1", "c": "Novell signature algorithm", "w": false },
"2.16.840.1.113719.1.2.8.30": { "d": "md5WithRSAEncryptionBSafe1", "c": "Novell signature algorithm", "w": false },
"2.16.840.1.113719.1.2.8.31": { "d": "sha1WithRSAEncryptionBSafe1", "c": "Novell signature algorithm", "w": false },
"2.16.840.1.113719.1.2.8.32": { "d": "lmDigest", "c": "Novell digest algorithm", "w": false },
"2.16.840.1.113719.1.2.8.40": { "d": "md2", "c": "Novell digest algorithm", "w": false },
"2.16.840.1.113719.1.2.8.50": { "d": "md5", "c": "Novell digest algorithm", "w": false },
"2.16.840.1.113719.1.2.8.51": { "d": "ikeHmacWithSHA1-RSA", "c": "Novell signature algorithm", "w": false },
"2.16.840.1.113719.1.2.8.52": { "d": "ikeHmacWithMD5-RSA", "c": "Novell signature algorithm", "w": false },
"2.16.840.1.113719.1.2.8.69": { "d": "rc2CbcPad", "c": "Novell encryption algorithm", "w": false },
"2.16.840.1.113719.1.2.8.82": { "d": "sha-1", "c": "Novell digest algorithm", "w": false },
"2.16.840.1.113719.1.2.8.92": { "d": "rc2BSafe1Cbc", "c": "Novell encryption algorithm", "w": false },
"2.16.840.1.113719.1.2.8.95": { "d": "md4", "c": "Novell digest algorithm", "w": false },
"2.16.840.1.113719.1.2.8.130": { "d": "md4Packet", "c": "Novell keyed hash", "w": false },
"2.16.840.1.113719.1.2.8.131": { "d": "rsaEncryptionBsafe1", "c": "Novell encryption algorithm", "w": false },
"2.16.840.1.113719.1.2.8.132": { "d": "nwPassword", "c": "Novell encryption algorithm", "w": false },
"2.16.840.1.113719.1.2.8.133": { "d": "novellObfuscate-1", "c": "Novell encryption algorithm", "w": false },
"2.16.840.1.113719.1.9": { "d": "pki", "c": "Novell", "w": false },
"2.16.840.1.113719.1.9.4": { "d": "pkiAttributeType", "c": "Novell PKI", "w": false },
"2.16.840.1.113719.1.9.4.1": { "d": "securityAttributes", "c": "Novell PKI attribute type", "w": false },
"2.16.840.1.113719.1.9.4.2": { "d": "relianceLimit", "c": "Novell PKI attribute type", "w": false },
"2.16.840.1.113730.1": { "d": "cert-extension", "c": "Netscape", "w": false },
"2.16.840.1.113730.1.1": { "d": "netscape-cert-type", "c": "Netscape certificate extension", "w": false },
"2.16.840.1.113730.1.2": { "d": "netscape-base-url", "c": "Netscape certificate extension", "w": false },
"2.16.840.1.113730.1.3": { "d": "netscape-revocation-url", "c": "Netscape certificate extension", "w": false },
"2.16.840.1.113730.1.4": { "d": "netscape-ca-revocation-url", "c": "Netscape certificate extension", "w": false },
"2.16.840.1.113730.1.7": { "d": "netscape-cert-renewal-url", "c": "Netscape certificate extension", "w": false },
"2.16.840.1.113730.1.8": { "d": "netscape-ca-policy-url", "c": "Netscape certificate extension", "w": false },
"2.16.840.1.113730.1.9": { "d": "HomePage-url", "c": "Netscape certificate extension", "w": false },
"2.16.840.1.113730.1.10": { "d": "EntityLogo", "c": "Netscape certificate extension", "w": false },
"2.16.840.1.113730.1.11": { "d": "UserPicture", "c": "Netscape certificate extension", "w": false },
"2.16.840.1.113730.1.12": { "d": "netscape-ssl-server-name", "c": "Netscape certificate extension", "w": false },
"2.16.840.1.113730.1.13": { "d": "netscape-comment", "c": "Netscape certificate extension", "w": false },
"2.16.840.1.113730.2": { "d": "data-type", "c": "Netscape", "w": false },
"2.16.840.1.113730.2.1": { "d": "dataGIF", "c": "Netscape data type", "w": false },
"2.16.840.1.113730.2.2": { "d": "dataJPEG", "c": "Netscape data type", "w": false },
"2.16.840.1.113730.2.3": { "d": "dataURL", "c": "Netscape data type", "w": false },
"2.16.840.1.113730.2.4": { "d": "dataHTML", "c": "Netscape data type", "w": false },
"2.16.840.1.113730.2.5": { "d": "certSequence", "c": "Netscape data type", "w": false },
"2.16.840.1.113730.2.6": { "d": "certURL", "c": "Netscape certificate extension", "w": false },
"2.16.840.1.113730.3": { "d": "directory", "c": "Netscape", "w": false },
"2.16.840.1.113730.3.1": { "d": "ldapDefinitions", "c": "Netscape directory", "w": false },
"2.16.840.1.113730.3.1.1": { "d": "carLicense", "c": "Netscape LDAP definitions", "w": false },
"2.16.840.1.113730.3.1.2": { "d": "departmentNumber", "c": "Netscape LDAP definitions", "w": false },
"2.16.840.1.113730.3.1.3": { "d": "employeeNumber", "c": "Netscape LDAP definitions", "w": false },
"2.16.840.1.113730.3.1.4": { "d": "employeeType", "c": "Netscape LDAP definitions", "w": false },
"2.16.840.1.113730.3.2.2": { "d": "inetOrgPerson", "c": "Netscape LDAP definitions", "w": false },
"2.16.840.1.113730.4.1": { "d": "serverGatedCrypto", "c": "Netscape", "w": false },
"2.16.840.1.113733.1.6.3": { "d": "verisignCZAG", "c": "Verisign extension", "w": false },
"2.16.840.1.113733.1.6.6": { "d": "verisignInBox", "c": "Verisign extension", "w": false },
"2.16.840.1.113733.1.6.11": { "d": "verisignOnsiteJurisdictionHash", "c": "Verisign extension", "w": false },
"2.16.840.1.113733.1.6.13": { "d": "Unknown Verisign VPN extension", "c": "Verisign extension", "w": false },
"2.16.840.1.113733.1.6.15": { "d": "verisignServerID", "c": "Verisign extension", "w": false },
"2.16.840.1.113733.1.7.1.1": { "d": "verisignCertPolicies95Qualifier1", "c": "Verisign policy", "w": false },
"2.16.840.1.113733.1.7.1.1.1": { "d": "verisignCPSv1notice", "c": "Verisign policy (obsolete)", "w": false },
"2.16.840.1.113733.1.7.1.1.2": { "d": "verisignCPSv1nsi", "c": "Verisign policy (obsolete)", "w": false },
"2.16.840.1.113733.1.7.23.6": { "d": "verisignEVPolicy", "c": "Verisign extension", "w": false },
"2.16.840.1.113733.1.8.1": { "d": "verisignISSStrongCrypto", "c": "Verisign", "w": false },
"2.16.840.1.113733.1": { "d": "pki", "c": "Verisign extension", "w": false },
"2.16.840.1.113733.1.9": { "d": "pkcs7Attribute", "c": "Verisign PKI extension", "w": false },
"2.16.840.1.113733.1.9.2": { "d": "messageType", "c": "Verisign PKCS #7 attribute", "w": false },
"2.16.840.1.113733.1.9.3": { "d": "pkiStatus", "c": "Verisign PKCS #7 attribute", "w": false },
"2.16.840.1.113733.1.9.4": { "d": "failInfo", "c": "Verisign PKCS #7 attribute", "w": false },
"2.16.840.1.113733.1.9.5": { "d": "senderNonce", "c": "Verisign PKCS #7 attribute", "w": false },
"2.16.840.1.113733.1.9.6": { "d": "recipientNonce", "c": "Verisign PKCS #7 attribute", "w": false },
"2.16.840.1.113733.1.9.7": { "d": "transID", "c": "Verisign PKCS #7 attribute", "w": false },
"2.16.840.1.113733.1.9.8": { "d": "extensionReq", "c": "Verisign PKCS #7 attribute.  Use PKCS #9 extensionRequest instead", "w": true },
"2.23.42.0": { "d": "contentType", "c": "SET", "w": false },
"2.23.42.0.0": { "d": "panData", "c": "SET contentType", "w": false },
"2.23.42.0.1": { "d": "panToken", "c": "SET contentType", "w": false },
"2.23.42.0.2": { "d": "panOnly", "c": "SET contentType", "w": false },
"2.23.42.1": { "d": "msgExt", "c": "SET", "w": false },
"2.23.42.2": { "d": "field", "c": "SET", "w": false },
"2.23.42.2.0": { "d": "fullName", "c": "SET field", "w": false },
"2.23.42.2.1": { "d": "givenName", "c": "SET field", "w": false },
"2.23.42.2.2": { "d": "familyName", "c": "SET field", "w": false },
"2.23.42.2.3": { "d": "birthFamilyName", "c": "SET field", "w": false },
"2.23.42.2.4": { "d": "placeName", "c": "SET field", "w": false },
"2.23.42.2.5": { "d": "identificationNumber", "c": "SET field", "w": false },
"2.23.42.2.6": { "d": "month", "c": "SET field", "w": false },
"2.23.42.2.7": { "d": "date", "c": "SET field", "w": false },
"2.23.42.2.8": { "d": "address", "c": "SET field", "w": false },
"2.23.42.2.9": { "d": "telephone", "c": "SET field", "w": false },
"2.23.42.2.10": { "d": "amount", "c": "SET field", "w": false },
"2.23.42.2.11": { "d": "accountNumber", "c": "SET field", "w": false },
"2.23.42.2.12": { "d": "passPhrase", "c": "SET field", "w": false },
"2.23.42.3": { "d": "attribute", "c": "SET", "w": false },
"2.23.42.3.0": { "d": "cert", "c": "SET attribute", "w": false },
"2.23.42.3.0.0": { "d": "rootKeyThumb", "c": "SET cert attribute", "w": false },
"2.23.42.3.0.1": { "d": "additionalPolicy", "c": "SET cert attribute", "w": false },
"2.23.42.4": { "d": "algorithm", "c": "SET", "w": false },
"2.23.42.5": { "d": "policy", "c": "SET", "w": false },
"2.23.42.5.0": { "d": "root", "c": "SET policy", "w": false },
"2.23.42.6": { "d": "module", "c": "SET", "w": false },
"2.23.42.7": { "d": "certExt", "c": "SET", "w": false },
"2.23.42.7.0": { "d": "hashedRootKey", "c": "SET cert extension", "w": false },
"2.23.42.7.1": { "d": "certificateType", "c": "SET cert extension", "w": false },
"2.23.42.7.2": { "d": "merchantData", "c": "SET cert extension", "w": false },
"2.23.42.7.3": { "d": "cardCertRequired", "c": "SET cert extension", "w": false },
"2.23.42.7.4": { "d": "tunneling", "c": "SET cert extension", "w": false },
"2.23.42.7.5": { "d": "setExtensions", "c": "SET cert extension", "w": false },
"2.23.42.7.6": { "d": "setQualifier", "c": "SET cert extension", "w": false },
"2.23.42.8": { "d": "brand", "c": "SET", "w": false },
"2.23.42.8.1": { "d": "IATA-ATA", "c": "SET brand", "w": false },
"2.23.42.8.4": { "d": "VISA", "c": "SET brand", "w": false },
"2.23.42.8.5": { "d": "MasterCard", "c": "SET brand", "w": false },
"2.23.42.8.30": { "d": "Diners", "c": "SET brand", "w": false },
"2.23.42.8.34": { "d": "AmericanExpress", "c": "SET brand", "w": false },
"2.23.42.8.6011": { "d": "Novus", "c": "SET brand", "w": false },
"2.23.42.9": { "d": "vendor", "c": "SET", "w": false },
"2.23.42.9.0": { "d": "GlobeSet", "c": "SET vendor", "w": false },
"2.23.42.9.1": { "d": "IBM", "c": "SET vendor", "w": false },
"2.23.42.9.2": { "d": "CyberCash", "c": "SET vendor", "w": false },
"2.23.42.9.3": { "d": "Terisa", "c": "SET vendor", "w": false },
"2.23.42.9.4": { "d": "RSADSI", "c": "SET vendor", "w": false },
"2.23.42.9.5": { "d": "VeriFone", "c": "SET vendor", "w": false },
"2.23.42.9.6": { "d": "TrinTech", "c": "SET vendor", "w": false },
"2.23.42.9.7": { "d": "BankGate", "c": "SET vendor", "w": false },
"2.23.42.9.8": { "d": "GTE", "c": "SET vendor", "w": false },
"2.23.42.9.9": { "d": "CompuSource", "c": "SET vendor", "w": false },
"2.23.42.9.10": { "d": "Griffin", "c": "SET vendor", "w": false },
"2.23.42.9.11": { "d": "Certicom", "c": "SET vendor", "w": false },
"2.23.42.9.12": { "d": "OSS", "c": "SET vendor", "w": false },
"2.23.42.9.13": { "d": "TenthMountain", "c": "SET vendor", "w": false },
"2.23.42.9.14": { "d": "Antares", "c": "SET vendor", "w": false },
"2.23.42.9.15": { "d": "ECC", "c": "SET vendor", "w": false },
"2.23.42.9.16": { "d": "Maithean", "c": "SET vendor", "w": false },
"2.23.42.9.17": { "d": "Netscape", "c": "SET vendor", "w": false },
"2.23.42.9.18": { "d": "Verisign", "c": "SET vendor", "w": false },
"2.23.42.9.19": { "d": "BlueMoney", "c": "SET vendor", "w": false },
"2.23.42.9.20": { "d": "Lacerte", "c": "SET vendor", "w": false },
"2.23.42.9.21": { "d": "Fujitsu", "c": "SET vendor", "w": false },
"2.23.42.9.22": { "d": "eLab", "c": "SET vendor", "w": false },
"2.23.42.9.23": { "d": "Entrust", "c": "SET vendor", "w": false },
"2.23.42.9.24": { "d": "VIAnet", "c": "SET vendor", "w": false },
"2.23.42.9.25": { "d": "III", "c": "SET vendor", "w": false },
"2.23.42.9.26": { "d": "OpenMarket", "c": "SET vendor", "w": false },
"2.23.42.9.27": { "d": "Lexem", "c": "SET vendor", "w": false },
"2.23.42.9.28": { "d": "Intertrader", "c": "SET vendor", "w": false },
"2.23.42.9.29": { "d": "Persimmon", "c": "SET vendor", "w": false },
"2.23.42.9.30": { "d": "NABLE", "c": "SET vendor", "w": false },
"2.23.42.9.31": { "d": "espace-net", "c": "SET vendor", "w": false },
"2.23.42.9.32": { "d": "Hitachi", "c": "SET vendor", "w": false },
"2.23.42.9.33": { "d": "Microsoft", "c": "SET vendor", "w": false },
"2.23.42.9.34": { "d": "NEC", "c": "SET vendor", "w": false },
"2.23.42.9.35": { "d": "Mitsubishi", "c": "SET vendor", "w": false },
"2.23.42.9.36": { "d": "NCR", "c": "SET vendor", "w": false },
"2.23.42.9.37": { "d": "e-COMM", "c": "SET vendor", "w": false },
"2.23.42.9.38": { "d": "Gemplus", "c": "SET vendor", "w": false },
"2.23.42.10": { "d": "national", "c": "SET", "w": false },
"2.23.42.10.392": { "d": "Japan", "c": "SET national", "w": false },
"2.23.136.1.1.1": { "d": "mRTDSignatureData", "c": "ICAO MRTD", "w": false },
"2.54.1775.2": { "d": "hashedRootKey", "c": "SET.  Deprecated, use (2 23 42 7 0) instead", "w": true },
"2.54.1775.3": { "d": "certificateType", "c": "SET.  Deprecated, use (2 23 42 7 0) instead", "w": true },
"2.54.1775.4": { "d": "merchantData", "c": "SET.  Deprecated, use (2 23 42 7 0) instead", "w": true },
"2.54.1775.5": { "d": "cardCertRequired", "c": "SET.  Deprecated, use (2 23 42 7 0) instead", "w": true },
"2.54.1775.6": { "d": "tunneling", "c": "SET.  Deprecated, use (2 23 42 7 0) instead", "w": true },
"2.54.1775.7": { "d": "setQualifier", "c": "SET.  Deprecated, use (2 23 42 7 0) instead", "w": true },
"2.54.1775.99": { "d": "setData", "c": "SET.  Deprecated, use (2 23 42 7 0) instead", "w": true }
};
/*!Copyright (c) 2009 pidder <www.pidder.com>*/
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License as
// published by the Free Software Foundation; either version 2 of the
// License, or (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
// 02111-1307 USA or check at http://www.gnu.org/licenses/gpl.html

/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
/* pidCrypt is pidders JavaScript Crypto Library - www.pidder.com/pidcrypt
 * Version 0.04, 10/2009

 *
 * pidCrypt is a combination of different JavaScript functions for client side
 * encryption technologies with enhancements for openssl compatibility cast into
 * a modular class concept.
 *
 * Client side encryption is a must have for developing host proof applications:
 * There must be no knowledge of the clear text data at the server side, all
 * data is enrycpted prior to being submitted to the server.
 * Client side encryption is mandatory for protecting the privacy of the users.
 * "Dont't trust us, check our source code!"
 *
 * "As a cryptography and computer security expert, I have never understood
 * the current fuss about the open source software movement. In the
 * cryptography world, we consider open source necessary for good security;
 * we have for decades. Public security is always more secure than proprietary
 * security. It's true for cryptographic algorithms, security protocols, and
 * security source code. For us, open source isn't just a business model;
 * it's smart engineering practice."
 * Bruce Schneier, Crypto-Gram 1999/09/15
 * copied form keepassx site - keepassx is a cross plattform password manager
 *
 * pidCrypt comes with modules under different licenses and copyright terms.
 * Make sure that you read and respect the individual module license conditions
 * before using it.
 *
 * The pidCrypt base library contains:
 * 1. pidcrypt.js
 *    class pidCrypt: the base class of the library
 * 2. pidcrypt_util.js
 *    base64 en-/decoding as new methods of the JavaScript String class
 *    UTF8 en-/decoding as new methods of the JavaScript String class
 *    String/HexString conversions as new methods of the JavaScript String class
 *
 * The pidCrypt v0.01 modules and the original authors (see files for detailed
 * copyright and license terms) are:
 *
 * - md5.js:      MD5 (Message-Digest Algorithm), www.webtoolkit.info
 * - aes_core.js: AES (Advanced Encryption Standard ) Core algorithm, B. Poettering
 * - aes-ctr.js:  AES CTR (Counter) Mode, Chis Veness
 * - aes-cbc.js:  AES CBC (Cipher Block Chaining) Mode, pidder
 * - jsbn.js:     BigInteger for JavaScript, Tom Wu
 * - prng.js:     PRNG (Pseudo-Random Number Generator), Tom Wu
 * - rng.js:      Random Numbers, Tom Wu
 * - rsa.js:      RSA (Rivest, Shamir, Adleman Algorithm), Tom Wu
 * - oids.js:     oids (Object Identifiers found in ASN.1), Peter Gutmann
 * - asn1.js:     ASN1 (Abstract Syntax Notation One) parser, Lapo Luchini
 * - sha256.js    SHA-256 hashing, Angel Marin 
 * - sha2.js:     SHA-384 and SHA-512 hashing, Brian Turek
 *
 * IMPORTANT:
 * Please report any bugs at http://sourceforge.net/projects/pidcrypt/
 * Vist http://www.pidder.com/pidcrypt for online demo an documentation
 */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

function pidCrypt(){
  //TODO: better radomness!
  function getRandomBytes(len){
    if(!len) len = 8;
    var bytes = new Array(len);
    var field = [];
    for(var i=0;i<256;i++) field[i] = i;
    for(i=0;i<bytes.length;i++)
      bytes[i] = field[Math.floor(Math.random()*field.length)];
    return bytes
  }

  this.setDefaults = function(){
     this.params.nBits = 256;
  //salt should always be a Hex String e.g. AD0E76FF6535AD...
     this.params.salt = getRandomBytes(8);
     this.params.salt = pidCryptUtil.byteArray2String(this.params.salt);
     this.params.salt = pidCryptUtil.convertToHex(this.params.salt);
     this.params.blockSize = 16;
     this.params.UTF8 = true;
     this.params.A0_PAD = true;
  }

  this.debug = true;
  this.params = {};
  //setting default values for params
  this.params.dataIn = '';
  this.params.dataOut = '';
  this.params.decryptIn = '';
  this.params.decryptOut = '';
  this.params.encryptIn = '';
  this.params.encryptOut = '';
  //key should always be a Hex String e.g. AD0E76FF6535AD...
  this.params.key = '';
  //iv should always be a Hex String e.g. AD0E76FF6535AD...
  this.params.iv = '';
  this.params.clear = true;
  this.setDefaults();
  this.errors = '';
  this.warnings = '';
  this.infos = '';
  this.debugMsg = '';
  //set and get methods for base class
  this.setParams = function(pObj){
    if(!pObj) pObj = {};
    for(var p in pObj)
      this.params[p] = pObj[p];
  }
  this.getParams = function(){
    return this.params;
  }
  this.getParam = function(p){
    return this.params[p] || '';
  }
  this.clearParams = function(){
      this.params= {};
  }
  this.getNBits = function(){
    return this.params.nBits;
  }
  this.getOutput = function(){
    return this.params.dataOut;
  }
  this.setError = function(str){
    this.error = str;
  }
  this.appendError = function(str){
    this.errors += str;
    return '';
  }
  this.getErrors = function(){
    return this.errors;
  }
  this.isError = function(){
    if(this.errors.length>0)
      return true;
    return false
  }
  this.appendInfo = function(str){
    this.infos += str;
    return '';
  }
  this.getInfos = function()
  {
    return this.infos;
  }
  this.setDebug = function(flag){
    this.debug = flag;
  }
  this.appendDebug = function(str)
  {
    this.debugMsg += str;
    return '';
  }
  this.isDebug = function(){
    return this.debug;
  }
  this.getAllMessages = function(options){
    var defaults = {lf:'\n',
                    clr_mes: false,
                    verbose: 15//verbose level bits = 1111
        };
    if(!options) options = defaults;
    for(var d in defaults)
      if(typeof(options[d]) == 'undefined') options[d] = defaults[d];
    var mes = '';
    var tmp = '';
    for(var p in this.params){
      switch(p){
        case 'encryptOut':
          tmp = pidCryptUtil.toByteArray(this.params[p].toString());
          tmp = pidCryptUtil.fragment(tmp.join(),64, options.lf)
          break;
        case 'key': 
        case 'iv':
          tmp = pidCryptUtil.formatHex(this.params[p],48);
          break;
        default:
          tmp = pidCryptUtil.fragment(this.params[p].toString(),64, options.lf);
      }  
      mes += '<p><b>'+p+'</b>:<pre>' + tmp + '</pre></p>';
    }  
    if(this.debug) mes += 'debug: ' + this.debug + options.lf;
    if(this.errors.length>0 && ((options.verbose & 1) == 1)) mes += 'Errors:' + options.lf + this.errors + options.lf;
    if(this.warnings.length>0 && ((options.verbose & 2) == 2)) mes += 'Warnings:' +options.lf + this.warnings + options.lf;
    if(this.infos.length>0 && ((options.verbose & 4) == 4)) mes += 'Infos:' +options.lf+ this.infos + options.lf;
    if(this.debug && ((options.verbose & 8) == 8)) mes += 'Debug messages:' +options.lf+ this.debugMsg + options.lf;
    if(options.clr_mes)
      this.errors = this.infos = this.warnings = this.debug = '';
    return mes;
  }
  this.getRandomBytes = function(len){
    return getRandomBytes(len);
  }
  //TODO warnings
}

 /*----------------------------------------------------------------------------*/
 // Copyright (c) 2009 pidder <www.pidder.com>
 // Permission to use, copy, modify, and/or distribute this software for any
 // purpose with or without fee is hereby granted, provided that the above
 // copyright notice and this permission notice appear in all copies.
 //
 // THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 // WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 // MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 // ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 // WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 // ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 // OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
/*----------------------------------------------------------------------------*/
/*  (c) Chris Veness 2005-2008
* You are welcome to re-use these scripts [without any warranty express or
* implied] provided you retain my copyright notice and when possible a link to
* my website (under a LGPL license). §ection numbers relate the code back to
* sections in the standard.
/*----------------------------------------------------------------------------*/
/* Helper methods (base64 conversion etc.) needed for different operations in
 * encryption.

/*----------------------------------------------------------------------------*/
/* Intance methods extanding the String object                                */
/*----------------------------------------------------------------------------*/
/**
 * Encode string into Base64, as defined by RFC 4648 [http://tools.ietf.org/html/rfc4648]
 * As per RFC 4648, no newlines are added.
 *
 * @param utf8encode optional parameter, if set to true Unicode string is
 *                   encoded into UTF-8 before conversion to base64;
 *                   otherwise string is assumed to be 8-bit characters
 * @return coded     base64-encoded string
 */
pidCryptUtil = {};
pidCryptUtil.encodeBase64 = function(str,utf8encode) {  // http://tools.ietf.org/html/rfc4648
  if(!str) str = "";
  var b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
  utf8encode =  (typeof utf8encode == 'undefined') ? false : utf8encode;
  var o1, o2, o3, bits, h1, h2, h3, h4, e=[], pad = '', c, plain, coded;

  plain = utf8encode ? pidCryptUtil.encodeUTF8(str) : str;

  c = plain.length % 3;  // pad string to length of multiple of 3
  if (c > 0) { while (c++ < 3) { pad += '='; plain += '\0'; } }
  // note: doing padding here saves us doing special-case packing for trailing 1 or 2 chars

  for (c=0; c<plain.length; c+=3) {  // pack three octets into four hexets
    o1 = plain.charCodeAt(c);
    o2 = plain.charCodeAt(c+1);
    o3 = plain.charCodeAt(c+2);

    bits = o1<<16 | o2<<8 | o3;

    h1 = bits>>18 & 0x3f;
    h2 = bits>>12 & 0x3f;
    h3 = bits>>6 & 0x3f;
    h4 = bits & 0x3f;

    // use hextets to index into b64 string
    e[c/3] = b64.charAt(h1) + b64.charAt(h2) + b64.charAt(h3) + b64.charAt(h4);
  }
  coded = e.join('');  // join() is far faster than repeated string concatenation

  // replace 'A's from padded nulls with '='s
  coded = coded.slice(0, coded.length-pad.length) + pad;
  return coded;
}

/**
 * Decode string from Base64, as defined by RFC 4648 [http://tools.ietf.org/html/rfc4648]
 * As per RFC 4648, newlines are not catered for.
 *
 * @param utf8decode optional parameter, if set to true UTF-8 string is decoded
 *                   back into Unicode after conversion from base64
 * @return           decoded string
 */
pidCryptUtil.decodeBase64 = function(str,utf8decode) {
  if(!str) str = "";
  var b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
  utf8decode =  (typeof utf8decode == 'undefined') ? false : utf8decode;
  var o1, o2, o3, h1, h2, h3, h4, bits, d=[], plain, coded;

  coded = utf8decode ? pidCryptUtil.decodeUTF8(str) : str;

  for (var c=0; c<coded.length; c+=4) {  // unpack four hexets into three octets
    h1 = b64.indexOf(coded.charAt(c));
    h2 = b64.indexOf(coded.charAt(c+1));
    h3 = b64.indexOf(coded.charAt(c+2));
    h4 = b64.indexOf(coded.charAt(c+3));

    bits = h1<<18 | h2<<12 | h3<<6 | h4;

    o1 = bits>>>16 & 0xff;
    o2 = bits>>>8 & 0xff;
    o3 = bits & 0xff;

    d[c/4] = String.fromCharCode(o1, o2, o3);
    // check for padding
    if (h4 == 0x40) d[c/4] = String.fromCharCode(o1, o2);
    if (h3 == 0x40) d[c/4] = String.fromCharCode(o1);
  }
  plain = d.join('');  // join() is far faster than repeated string concatenation

  plain = utf8decode ? pidCryptUtil.decodeUTF8(plain) : plain

  return plain;
}

/**
 * Encode multi-byte Unicode string into utf-8 multiple single-byte characters
 * (BMP / basic multilingual plane only)
 *
 * Chars in range U+0080 - U+07FF are encoded in 2 chars, U+0800 - U+FFFF in 3 chars
 *
 * @return encoded string
 */
pidCryptUtil.encodeUTF8 = function(str) {
  if(!str) str = "";
  // use regular expressions & String.replace callback function for better efficiency
  // than procedural approaches
  str = str.replace(
      /[\u0080-\u07ff]/g,  // U+0080 - U+07FF => 2 bytes 110yyyyy, 10zzzzzz
      function(c) {
        var cc = c.charCodeAt(0);
        return String.fromCharCode(0xc0 | cc>>6, 0x80 | cc&0x3f); }
    );
  str = str.replace(
      /[\u0800-\uffff]/g,  // U+0800 - U+FFFF => 3 bytes 1110xxxx, 10yyyyyy, 10zzzzzz
      function(c) {
        var cc = c.charCodeAt(0);
        return String.fromCharCode(0xe0 | cc>>12, 0x80 | cc>>6&0x3F, 0x80 | cc&0x3f); }
    );
  return str;
}

// If you encounter problems with the UTF8 encode function (e.g. for use in a
// Firefox) AddOn) you can use the following instead.
// code from webtoolkit.com

//pidCryptUtil.encodeUTF8 = function(str) {
//		str = str.replace(/\r\n/g,"\n");
//		var utftext = "";
//
//		for (var n = 0; n < str.length; n++) {
//
//			var c = str.charCodeAt(n);
//
//			if (c < 128) {
//				utftext += String.fromCharCode(c);
//			}
//			else if((c > 127) && (c < 2048)) {
//				utftext += String.fromCharCode((c >> 6) | 192);
//				utftext += String.fromCharCode((c & 63) | 128);
//			}
//			else {
//				utftext += String.fromCharCode((c >> 12) | 224);
//				utftext += String.fromCharCode(((c >> 6) & 63) | 128);
//				utftext += String.fromCharCode((c & 63) | 128);
//			}
//
//		}
//
//  return utftext;
//}



/**
 * Decode utf-8 encoded string back into multi-byte Unicode characters
 *
 * @return decoded string
 */
pidCryptUtil.decodeUTF8 = function(str) {
  if(!str) str = "";
  str = str.replace(
      /[\u00c0-\u00df][\u0080-\u00bf]/g,                 // 2-byte chars
      function(c) {  // (note parentheses for precence)
        var cc = (c.charCodeAt(0)&0x1f)<<6 | c.charCodeAt(1)&0x3f;
        return String.fromCharCode(cc); }
    );
  str = str.replace(
      /[\u00e0-\u00ef][\u0080-\u00bf][\u0080-\u00bf]/g,  // 3-byte chars
      function(c) {  // (note parentheses for precence)
        var cc = ((c.charCodeAt(0)&0x0f)<<12) | ((c.charCodeAt(1)&0x3f)<<6) | ( c.charCodeAt(2)&0x3f);
        return String.fromCharCode(cc); }
    );
  return str;
}

// If you encounter problems with the UTF8 decode function (e.g. for use in a
// Firefox) AddOn) you can use the following instead.
// code from webtoolkit.com

//pidCryptUtil.decodeUTF8 = function(utftext) {
//    var str = "";
//		var i = 0;
//		var c = 0;
//    var c1 = 0;
//    var c2 = 0;
//
//		while ( i < utftext.length ) {
//
//			c = utftext.charCodeAt(i);
//
//			if (c < 128) {
//				str += String.fromCharCode(c);
//				i++;
//			}
//			else if((c > 191) && (c < 224)) {
//				c1 = utftext.charCodeAt(i+1);
//				str += String.fromCharCode(((c & 31) << 6) | (c1 & 63));
//				i += 2;
//			}
//			else {
//				c1 = utftext.charCodeAt(i+1);
//				c2 = utftext.charCodeAt(i+2);
//				str += String.fromCharCode(((c & 15) << 12) | ((c1 & 63) << 6) | (c2 & 63));
//				i += 3;
//			}
//
//		}
//
//
//  return str;
//}




/**
 * Converts a string into a hexadecimal string
 * returns the characters of a string to their hexadecimal charcode equivalent
 * Works only on byte chars with charcode < 256. All others chars are converted
 * into "xx"
 *
 * @return hex string e.g. "hello world" => "68656c6c6f20776f726c64"
 */
pidCryptUtil.convertToHex = function(str) {
  if(!str) str = "";
  var hs ='';
  var hv ='';
  for (var i=0; i<str.length; i++) {
    hv = str.charCodeAt(i).toString(16);
    hs += (hv.length == 1) ? '0'+hv : hv;
  }
  return hs;
}

/**
 * Converts a hex string into a string
 * returns the characters of a hex string to their char of charcode
 *
 * @return hex string e.g. "68656c6c6f20776f726c64" => "hello world"
 */
pidCryptUtil.convertFromHex = function(str){
  if(!str) str = "";
  var s = "";
  for(var i= 0;i<str.length;i+=2){
    s += String.fromCharCode(parseInt(str.substring(i,i+2),16));
  }
  return s
}

/**
 * strips off all linefeeds from a string
 * returns the the strong without line feeds
 *
 * @return string
 */
pidCryptUtil.stripLineFeeds = function(str){
  if(!str) str = "";
//  var re = RegExp(String.fromCharCode(13),'g');//\r
//  var re = RegExp(String.fromCharCode(10),'g');//\n
  var s = '';
  s = str.replace(/\n/g,'');
  s = s.replace(/\r/g,'');
  return s;
}

/**
 * Converts a string into an array of char code bytes
 * returns the characters of a hex string to their char of charcode
 *
 * @return hex string e.g. "68656c6c6f20776f726c64" => "hello world"
 */
 pidCryptUtil.toByteArray = function(str){
  if(!str) str = "";
  var ba = [];
  for(var i=0;i<str.length;i++)
     ba[i] = str.charCodeAt(i);

  return ba;
}


/**
 * Fragmentize a string into lines adding a line feed (lf) every length
 * characters
 *
 * @return string e.g. length=3 "abcdefghi" => "abc\ndef\nghi\n"
 */
pidCryptUtil.fragment = function(str,length,lf){
  if(!str) str = "";
  if(!length || length>=str.length) return str;
  if(!lf) lf = '\n'
  var tmp='';
  for(var i=0;i<str.length;i+=length)
    tmp += str.substr(i,length) + lf;
  return tmp;
}

/**
 * Formats a hex string in two lower case chars + : and lines of given length
 * characters
 *
 * @return string e.g. "68656C6C6F20" => "68:65:6c:6c:6f:20:\n"
*/
pidCryptUtil.formatHex = function(str,length){
  if(!str) str = "";
    if(!length) length = 45;
    var str_new='';
    var j = 0;
    var hex = str.toLowerCase();
    for(var i=0;i<hex.length;i+=2)
      str_new += hex.substr(i,2) +':';
    hex = this.fragment(str_new,length);

  return hex;
}


/*----------------------------------------------------------------------------*/
/* End of intance methods of the String object                                */
/*----------------------------------------------------------------------------*/

pidCryptUtil.byteArray2String = function(b){
//  var out ='';
  var s = '';
  for(var i=0;i<b.length;i++){
     s += String.fromCharCode(b[i]);
//     out += b[i]+':';
  }
//  alert(out);
  return s;
}
//  Author: Tom Wu
//  tjw@cs.Stanford.EDU
// prng4.js - uses Arcfour as a PRNG

function Arcfour() {
  this.i = 0;
  this.j = 0;
  this.S = new Array();
}

// Initialize arcfour context from key, an array of ints, each from [0..255]
function ARC4init(key) {
  var i, j, t;
  for(i = 0; i < 256; ++i)
    this.S[i] = i;
  j = 0;
  for(i = 0; i < 256; ++i) {
    j = (j + this.S[i] + key[i % key.length]) & 255;
    t = this.S[i];
    this.S[i] = this.S[j];
    this.S[j] = t;
  }
  this.i = 0;
  this.j = 0;
}

function ARC4next() {
  var t;
  this.i = (this.i + 1) & 255;
  this.j = (this.j + this.S[this.i]) & 255;
  t = this.S[this.i];
  this.S[this.i] = this.S[this.j];
  this.S[this.j] = t;
  return this.S[(t + this.S[this.i]) & 255];
}

Arcfour.prototype.init = ARC4init;
Arcfour.prototype.next = ARC4next;

// Plug in your RNG constructor here
function prng_newstate() {
  return new Arcfour();
}

// Pool size must be a multiple of 4 and greater than 32.
// An array of bytes the size of the pool will be passed to init()
var rng_psize = 256;
//  Author: Tom Wu
//  tjw@cs.Stanford.EDU
// Random number generator - requires a PRNG backend, e.g. prng4.js

// For best results, put code like
// <body onClick='rng_seed_time();' onKeyPress='rng_seed_time();'>
// in your main HTML document.

function SecureRandom() {
  this.rng_state;
  this.rng_pool;
  this.rng_pptr;


    // Mix in a 32-bit integer into the pool
    this.rng_seed_int = function(x) {
      this.rng_pool[this.rng_pptr++] ^= x & 255;
      this.rng_pool[this.rng_pptr++] ^= (x >> 8) & 255;
      this.rng_pool[this.rng_pptr++] ^= (x >> 16) & 255;
      this.rng_pool[this.rng_pptr++] ^= (x >> 24) & 255;
      if(this.rng_pptr >= rng_psize) this.rng_pptr -= rng_psize;
    }

    // Mix in the current time (w/milliseconds) into the pool
    this.rng_seed_time = function() {
      this.rng_seed_int(new Date().getTime());
    }

    // Initialize the pool with junk if needed.
    if(this.rng_pool == null) {
      this.rng_pool = new Array();
      this.rng_pptr = 0;
      var t;
      if(navigator.appName == "Netscape" && navigator.appVersion < "5" && window.crypto) {
        // Extract entropy (256 bits) from NS4 RNG if available
        var z = window.crypto.random(32);
        for(t = 0; t < z.length; ++t)
          this.rng_pool[this.rng_pptr++] = z.charCodeAt(t) & 255;
      }
      while(this.rng_pptr < rng_psize) {  // extract some randomness from Math.random()
        t = Math.floor(65536 * Math.random());
        this.rng_pool[this.rng_pptr++] = t >>> 8;
        this.rng_pool[this.rng_pptr++] = t & 255;
      }
      this.rng_pptr = 0;
      this.rng_seed_time();
      //this.rng_seed_int(window.screenX);
      //this.rng_seed_int(window.screenY);
    }

    this.rng_get_byte = function() {
      if(this.rng_state == null) {
       this.rng_seed_time();
        this.rng_state = prng_newstate();
        this.rng_state.init(this.rng_pool);
        for(this.rng_pptr = 0; this.rng_pptr < this.rng_pool.length; ++this.rng_pptr)
          this.rng_pool[this.rng_pptr] = 0;
        this.rng_pptr = 0;
        //this.rng_pool = null;
      }
      // TODO: allow reseeding after first request
      return this.rng_state.next();
    }
    
    //public function
    this.nextBytes = function(ba) {
      var i;
      for(i = 0; i < ba.length; ++i) ba[i] = this.rng_get_byte();
    }
}



 /*----------------------------------------------------------------------------*/
 // Copyright (c) 2009 pidder <www.pidder.com>
 // Permission to use, copy, modify, and/or distribute this software for any
 // purpose with or without fee is hereby granted, provided that the above
 // copyright notice and this permission notice appear in all copies.
 //
 // THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 // WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 // MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 // ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 // WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 // ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 // OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
/*----------------------------------------------------------------------------*/
/**
*
*  PKCS#1 encryption-style padding (type 2) En- / Decryption for use in
*  pidCrypt Library. The pidCrypt RSA module is based on the implementation
*  by Tom Wu.
*  See http://www-cs-students.stanford.edu/~tjw/jsbn/ for details and for his
*  great job.
*
*  Depends on pidCrypt (pidcrypt.js, pidcrypt_util.js), BigInteger (jsbn.js),
*  random number generator (rng.js) and a PRNG backend (prng4.js) (the random
*  number scripts are only needed for key generation).
/*----------------------------------------------------------------------------*/
 /*
 * Copyright (c) 2003-2005  Tom Wu
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS-IS" AND WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS, IMPLIED OR OTHERWISE, INCLUDING WITHOUT LIMITATION, ANY
 * WARRANTY OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
 *
 * IN NO EVENT SHALL TOM WU BE LIABLE FOR ANY SPECIAL, INCIDENTAL,
 * INDIRECT OR CONSEQUENTIAL DAMAGES OF ANY KIND, OR ANY DAMAGES WHATSOEVER
 * RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER OR NOT ADVISED OF
 * THE POSSIBILITY OF DAMAGE, AND ON ANY THEORY OF LIABILITY, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * In addition, the following condition applies:
 *
 * All redistributions must retain an intact copy of this copyright notice
 * and disclaimer.
 */
//Address all questions regarding this license to:
//  Tom Wu
//  tjw@cs.Stanford.EDU
/*----------------------------------------------------------------------------*/
if(typeof(pidCrypt) != 'undefined' &&
   typeof(BigInteger) != 'undefined' &&//must have for rsa
   typeof(SecureRandom) != 'undefined' &&//only needed for key generation
   typeof(Arcfour) != 'undefined'//only needed for key generation
)
{

//  Author: Tom Wu
//  tjw@cs.Stanford.EDU
    // convert a (hex) string to a bignum object
        function parseBigInt(str,r) {
          return new BigInteger(str,r);
        }

        function linebrk(s,n) {
          var ret = "";
          var i = 0;
          while(i + n < s.length) {
            ret += s.substring(i,i+n) + "\n";
            i += n;
          }
          return ret + s.substring(i,s.length);
        }

        function byte2Hex(b) {
          if(b < 0x10)
            return "0" + b.toString(16);
          else
            return b.toString(16);
        }

        // Undo PKCS#1 (type 2, random) padding and, if valid, return the plaintext
        function pkcs1unpad2(d,n) {
          var b = d.toByteArray();
          var i = 0;
          while(i < b.length && b[i] == 0) ++i;
          if(b.length-i != n-1 || b[i] != 2)
            return null;
          ++i;
          while(b[i] != 0)
            if(++i >= b.length) return null;
          var ret = "";
          while(++i < b.length)
            ret += String.fromCharCode(b[i]);
          return ret;
        }

    // PKCS#1 (type 2, random) pad input string s to n bytes, and return a bigint
        function pkcs1pad2(s,n) {
          if(n < s.length + 11) {
            alert("Message too long for RSA");
            return null;
          }
          var ba = new Array();
          var i = s.length - 1;
          while(i >= 0 && n > 0) {ba[--n] = s.charCodeAt(i--);};
          ba[--n] = 0;
          var rng = new SecureRandom();
          var x = new Array();
          while(n > 2) { // random non-zero pad
            x[0] = 0;
            while(x[0] == 0) rng.nextBytes(x);
            ba[--n] = x[0];
          }
          ba[--n] = 2;
          ba[--n] = 0;
          return new BigInteger(ba);
        }
    //RSA key constructor
    pidCrypt.RSA = function() {
      this.n = null;
      this.e = 0;
      this.d = null;
      this.p = null;
      this.q = null;
      this.dmp1 = null;
      this.dmq1 = null;
      this.coeff = null;

    }
    // protected
    // Perform raw private operation on "x": return x^d (mod n)
    pidCrypt.RSA.prototype.doPrivate = function(x) {
      if(this.p == null || this.q == null)
        return x.modPow(this.d, this.n);

      // TODO: re-calculate any missing CRT params
      var xp = x.mod(this.p).modPow(this.dmp1, this.p);
      var xq = x.mod(this.q).modPow(this.dmq1, this.q);

      while(xp.compareTo(xq) < 0)
        xp = xp.add(this.p);
      return xp.subtract(xq).multiply(this.coeff).mod(this.p).multiply(this.q).add(xq);
    }


    // Set the public key fields N and e from hex strings
    pidCrypt.RSA.prototype.setPublic = function(N,E,radix) {
      if (typeof(radix) == 'undefined') radix = 16;

      if(N != null && E != null && N.length > 0 && E.length > 0) {
        this.n = parseBigInt(N,radix);
        this.e = parseInt(E,radix);
      }
      else
        alert("Invalid RSA public key");

//       alert('N='+this.n+'\nE='+this.e);
//document.writeln('Schlüssellaenge = ' + this.n.toString().length +'<BR>');
    }

    // Perform raw public operation on "x": return x^e (mod n)
    pidCrypt.RSA.prototype.doPublic = function(x) {
      return x.modPowInt(this.e, this.n);
    }

    // Return the PKCS#1 RSA encryption of "text" as an even-length hex string
    pidCrypt.RSA.prototype.encryptRaw = function(text) {
      var m = pkcs1pad2(text,(this.n.bitLength()+7)>>3);
      if(m == null) return null;
      var c = this.doPublic(m);
      if(c == null) return null;
      var h = c.toString(16);
      if((h.length & 1) == 0) return h; else return "0" + h;
    }

    pidCrypt.RSA.prototype.encrypt = function(text) {
      //base64 coding for supporting 8bit chars
      text = pidCryptUtil.encodeBase64(text);
      return this.encryptRaw(text)
    }
    // Return the PKCS#1 RSA decryption of "ctext".
    // "ctext" is an even-length hex string and the output is a plain string.
    pidCrypt.RSA.prototype.decryptRaw = function(ctext) {
//     alert('N='+this.n+'\nE='+this.e+'\nD='+this.d+'\nP='+this.p+'\nQ='+this.q+'\nDP='+this.dmp1+'\nDQ='+this.dmq1+'\nC='+this.coeff);
      var c = parseBigInt(ctext, 16);
      var m = this.doPrivate(c);
      if(m == null) return null;
      return pkcs1unpad2(m, (this.n.bitLength()+7)>>3)
    }

    pidCrypt.RSA.prototype.decrypt = function(ctext) {
      var str = this.decryptRaw(ctext)
      //base64 coding for supporting 8bit chars
      str = (str) ? pidCryptUtil.decodeBase64(str) : "";
      return str;
    }

/*
    // Return the PKCS#1 RSA encryption of "text" as a Base64-encoded string
    pidCrypt.RSA.prototype.b64_encrypt = function(text) {
      var h = this.encrypt(text);
      if(h) return hex2b64(h); else return null;
    }
*/
    // Set the private key fields N, e, and d from hex strings
    pidCrypt.RSA.prototype.setPrivate = function(N,E,D,radix) {
      if (typeof(radix) == 'undefined') radix = 16;

      if(N != null && E != null && N.length > 0 && E.length > 0) {
        this.n = parseBigInt(N,radix);
        this.e = parseInt(E,radix);
        this.d = parseBigInt(D,radix);
      }
      else
        alert("Invalid RSA private key");
    }

    // Set the private key fields N, e, d and CRT params from hex strings
    pidCrypt.RSA.prototype.setPrivateEx = function(N,E,D,P,Q,DP,DQ,C,radix) {
        if (typeof(radix) == 'undefined') radix = 16;

        if(N != null && E != null && N.length > 0 && E.length > 0) {
        this.n = parseBigInt(N,radix);//modulus
        this.e = parseInt(E,radix);//publicExponent
        this.d = parseBigInt(D,radix);//privateExponent
        this.p = parseBigInt(P,radix);//prime1
        this.q = parseBigInt(Q,radix);//prime2
        this.dmp1 = parseBigInt(DP,radix);//exponent1
        this.dmq1 = parseBigInt(DQ,radix);//exponent2
        this.coeff = parseBigInt(C,radix);//coefficient
      }
      else
        alert("Invalid RSA private key");
//     alert('N='+this.n+'\nE='+this.e+'\nD='+this.d+'\nP='+this.p+'\nQ='+this.q+'\nDP='+this.dmp1+'\nDQ='+this.dmq1+'\nC='+this.coeff);

    }

    // Generate a new random private key B bits long, using public expt E
    pidCrypt.RSA.prototype.generate = function(B,E) {
      var rng = new SecureRandom();
      var qs = B>>1;
      this.e = parseInt(E,16);
      var ee = new BigInteger(E,16);
      for(;;) {
        for(;;) {
          this.p = new BigInteger(B-qs,1,rng);
          if(this.p.subtract(BigInteger.ONE).gcd(ee).compareTo(BigInteger.ONE) == 0 && this.p.isProbablePrime(10)) break;
        }
        for(;;) {
          this.q = new BigInteger(qs,1,rng);
          if(this.q.subtract(BigInteger.ONE).gcd(ee).compareTo(BigInteger.ONE) == 0 && this.q.isProbablePrime(10)) break;
        }
        if(this.p.compareTo(this.q) <= 0) {
          var t = this.p;
          this.p = this.q;
          this.q = t;
        }
        var p1 = this.p.subtract(BigInteger.ONE);
        var q1 = this.q.subtract(BigInteger.ONE);
        var phi = p1.multiply(q1);
        if(phi.gcd(ee).compareTo(BigInteger.ONE) == 0) {
          this.n = this.p.multiply(this.q);
          this.d = ee.modInverse(phi);
          this.dmp1 = this.d.mod(p1);
          this.dmq1 = this.d.mod(q1);
          this.coeff = this.q.modInverse(this.p);
          break;
        }
      }
    }


//pidCrypt extensions start
//
    pidCrypt.RSA.prototype.getASNData = function(tree) {
        var params = {};
        var data = [];
        var p=0;

        if(tree.value && tree.type == 'INTEGER')
          data[p++] = tree.value;
        if(tree.sub)
           for(var i=0;i<tree.sub.length;i++)
           data = data.concat(this.getASNData(tree.sub[i]));

      return data;
    }

//
//
//get parameters from ASN1 structure object created from pidCrypt.ASN1.toHexTree
//e.g. A RSA Public Key gives the ASN structure object:
// {
//   SEQUENCE:
//              {
//                  INTEGER: modulus,
//                  INTEGER: public exponent
//              }
//}
    pidCrypt.RSA.prototype.setKeyFromASN = function(key,asntree) {
       var keys = ['N','E','D','P','Q','DP','DQ','C'];
       var params = {};

       var asnData = this.getASNData(asntree);
       switch(key){
           case 'Public':
           case 'public':
                for(var i=0;i<asnData.length;i++)
                  params[keys[i]] = asnData[i].toLowerCase();
                this.setPublic(params.N,params.E,16);
            break;
           case 'Private':
           case 'private':
                for(var i=1;i<asnData.length;i++)
                  params[keys[i-1]] = asnData[i].toLowerCase();
                this.setPrivateEx(params.N,params.E,params.D,params.P,params.Q,params.DP,params.DQ,params.C,16);
//                  this.setPrivate(params.N,params.E,params.D);
            break;
        }

    }

/**
 * Init RSA Encryption with public key.
 * @param  asntree: ASN1 structure object created from pidCrypt.ASN1.toHexTree
*/
   pidCrypt.RSA.prototype.setPublicKeyFromASN = function(asntree) {
        this.setKeyFromASN('public',asntree);

    }

/**
 * Init RSA Encryption with private key.
 * @param  asntree: ASN1 structure object created from pidCrypt.ASN1.toHexTree
*/
    pidCrypt.RSA.prototype.setPrivateKeyFromASN = function(asntree) {
        this.setKeyFromASN('private',asntree);
    }
/**
 * gets the current paramters as object.
 * @return params: object with RSA parameters
*/
    pidCrypt.RSA.prototype.getParameters = function() {
      var params = {}
      if(this.n != null) params.n = this.n;
      params.e = this.e;
      if(this.d != null) params.d = this.d;
      if(this.p != null) params.p = this.p;
      if(this.q != null) params.q = this.q;
      if(this.dmp1 != null) params.dmp1 = this.dmp1;
      if(this.dmq1 != null) params.dmq1 = this.dmq1;
      if(this.coeff != null) params.c = this.coeff;

      return params;
    }


//pidCrypt extensions end


}

/**
*
*  SHA1 (Secure Hash Algorithm) for use in pidCrypt Library
*  Depends on pidCrypt (pidcrypt.js, pidcrypt_util.js)
*
*  For original source see http://www.webtoolkit.info/
*  Download: 02.03.2009 from http://www.webtoolkit.info/javascript-sha1.html
**/

if(typeof(pidCrypt) != 'undefined') {
  pidCrypt.SHA1 = function(msg) {

    function rotate_left(n,s) {
      var t4 = ( n<<s ) | (n>>>(32-s));
      return t4;
    };

    function lsb_hex(val) {
      var str="";
      var i;
      var vh;
      var vl;

      for( i=0; i<=6; i+=2 ) {
        vh = (val>>>(i*4+4))&0x0f;
        vl = (val>>>(i*4))&0x0f;
        str += vh.toString(16) + vl.toString(16);
      }
      return str;
    };

    function cvt_hex(val) {
      var str="";
      var i;
      var v;

      for( i=7; i>=0; i-- ) {
        v = (val>>>(i*4))&0x0f;
        str += v.toString(16);
      }
      return str;
    };

    //**	function Utf8Encode(string) removed. Aready defined in pidcrypt_utils.js
   
    var blockstart;
    var i, j;
    var W = new Array(80);
    var H0 = 0x67452301;
    var H1 = 0xEFCDAB89;
    var H2 = 0x98BADCFE;
    var H3 = 0x10325476;
    var H4 = 0xC3D2E1F0;
    var A, B, C, D, E;
    var temp;

    //msg = pidCryptUtil.encodeUTF8(msg);

    var msg_len = msg.length;

    var word_array = new Array();
    for( i=0; i<msg_len-3; i+=4 ) {
      j = msg.charCodeAt(i)<<24 | msg.charCodeAt(i+1)<<16 |
      msg.charCodeAt(i+2)<<8 | msg.charCodeAt(i+3);
      word_array.push( j );
    }

    switch( msg_len % 4 ) {
      case 0:
        i = 0x080000000;
      break;
      case 1:
        i = msg.charCodeAt(msg_len-1)<<24 | 0x0800000;
      break;

      case 2:
        i = msg.charCodeAt(msg_len-2)<<24 | msg.charCodeAt(msg_len-1)<<16 | 0x08000;
      break;

      case 3:
        i = msg.charCodeAt(msg_len-3)<<24 | msg.charCodeAt(msg_len-2)<<16 | msg.charCodeAt(msg_len-1)<<8	| 0x80;
      break;
    }

    word_array.push( i );

    while( (word_array.length % 16) != 14 ) word_array.push( 0 );

    word_array.push( msg_len>>>29 );
    word_array.push( (msg_len<<3)&0x0ffffffff );


    for ( blockstart=0; blockstart<word_array.length; blockstart+=16 ) {

      for( i=0; i<16; i++ ) W[i] = word_array[blockstart+i];
      for( i=16; i<=79; i++ ) W[i] = rotate_left(W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1);

      A = H0;
      B = H1;
      C = H2;
      D = H3;
      E = H4;

      for( i= 0; i<=19; i++ ) {
        temp = (rotate_left(A,5) + ((B&C) | (~B&D)) + E + W[i] + 0x5A827999) & 0x0ffffffff;
        E = D;
        D = C;
        C = rotate_left(B,30);
        B = A;
        A = temp;
      }

      for( i=20; i<=39; i++ ) {
        temp = (rotate_left(A,5) + (B ^ C ^ D) + E + W[i] + 0x6ED9EBA1) & 0x0ffffffff;
        E = D;
        D = C;
        C = rotate_left(B,30);
        B = A;
        A = temp;
      }

      for( i=40; i<=59; i++ ) {
        temp = (rotate_left(A,5) + ((B&C) | (B&D) | (C&D)) + E + W[i] + 0x8F1BBCDC) & 0x0ffffffff;
        E = D;
        D = C;
        C = rotate_left(B,30);
        B = A;
        A = temp;
      }

      for( i=60; i<=79; i++ ) {
        temp = (rotate_left(A,5) + (B ^ C ^ D) + E + W[i] + 0xCA62C1D6) & 0x0ffffffff;
        E = D;
        D = C;
        C = rotate_left(B,30);
        B = A;
        A = temp;
      }

      H0 = (H0 + A) & 0x0ffffffff;
      H1 = (H1 + B) & 0x0ffffffff;
      H2 = (H2 + C) & 0x0ffffffff;
      H3 = (H3 + D) & 0x0ffffffff;
      H4 = (H4 + E) & 0x0ffffffff;

    }

    var temp = cvt_hex(H0) + cvt_hex(H1) + cvt_hex(H2) + cvt_hex(H3) + cvt_hex(H4);

    return temp.toLowerCase();
  }
}/**
*
*  SHA256 (Secure Hash Algorithm) for use in pidCrypt Library
*  Depends on pidCrypt (pidcrypt.js, pidcrypt_util.js)
*
*  For original source see http://anmar.eu.org/projects/jssha2/
*  Download: 09.06.2009 from http://anmar.eu.org/projects/jssha2/
* 
**/
/* A JavaScript implementation of the Secure Hash Algorithm, SHA-256
 * Version 0.3 Copyright Angel Marin 2003-2004 - http://anmar.eu.org/
 * Distributed under the BSD License
 * Some bits taken from Paul Johnston's SHA-1 implementation
 */

if(typeof(pidCrypt) != 'undefined') {
  pidCrypt.SHA256 = function(s) {

/* A JavaScript implementation of the Secure Hash Algorithm, SHA-256
 * Version 0.3 Copyright Angel Marin 2003-2004 - http://anmar.eu.org/
 * Distributed under the BSD License
 * Some bits taken from Paul Johnston's SHA-1 implementation
 */
    var chrsz = 8;  /* bits per input character. 8 - ASCII; 16 - Unicode  */
    function safe_add (x, y) {
      var lsw = (x & 0xFFFF) + (y & 0xFFFF);
      var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
      return (msw << 16) | (lsw & 0xFFFF);
    }
    function S (X, n) {return ( X >>> n ) | (X << (32 - n));}
    function R (X, n) {return ( X >>> n );}
    function Ch(x, y, z) {return ((x & y) ^ ((~x) & z));}
    function Maj(x, y, z) {return ((x & y) ^ (x & z) ^ (y & z));}
    function Sigma0256(x) {return (S(x, 2) ^ S(x, 13) ^ S(x, 22));}
    function Sigma1256(x) {return (S(x, 6) ^ S(x, 11) ^ S(x, 25));}
    function Gamma0256(x) {return (S(x, 7) ^ S(x, 18) ^ R(x, 3));}
    function Gamma1256(x) {return (S(x, 17) ^ S(x, 19) ^ R(x, 10));}
    function core_sha256 (m, l) {
        var K = new Array(0x428A2F98,0x71374491,0xB5C0FBCF,0xE9B5DBA5,0x3956C25B,0x59F111F1,0x923F82A4,0xAB1C5ED5,0xD807AA98,0x12835B01,0x243185BE,0x550C7DC3,0x72BE5D74,0x80DEB1FE,0x9BDC06A7,0xC19BF174,0xE49B69C1,0xEFBE4786,0xFC19DC6,0x240CA1CC,0x2DE92C6F,0x4A7484AA,0x5CB0A9DC,0x76F988DA,0x983E5152,0xA831C66D,0xB00327C8,0xBF597FC7,0xC6E00BF3,0xD5A79147,0x6CA6351,0x14292967,0x27B70A85,0x2E1B2138,0x4D2C6DFC,0x53380D13,0x650A7354,0x766A0ABB,0x81C2C92E,0x92722C85,0xA2BFE8A1,0xA81A664B,0xC24B8B70,0xC76C51A3,0xD192E819,0xD6990624,0xF40E3585,0x106AA070,0x19A4C116,0x1E376C08,0x2748774C,0x34B0BCB5,0x391C0CB3,0x4ED8AA4A,0x5B9CCA4F,0x682E6FF3,0x748F82EE,0x78A5636F,0x84C87814,0x8CC70208,0x90BEFFFA,0xA4506CEB,0xBEF9A3F7,0xC67178F2);
        var HASH = new Array(0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19);
        var W = new Array(64);
        var a, b, c, d, e, f, g, h, i, j;
        var T1, T2;
        /* append padding */
        m[l >> 5] |= 0x80 << (24 - l % 32);
        m[((l + 64 >> 9) << 4) + 15] = l;
        for ( var i = 0; i<m.length; i+=16 ) {
            a = HASH[0]; b = HASH[1]; c = HASH[2]; d = HASH[3]; e = HASH[4]; f = HASH[5]; g = HASH[6]; h = HASH[7];
            for ( var j = 0; j<64; j++) {
                if (j < 16) W[j] = m[j + i];
                else W[j] = safe_add(safe_add(safe_add(Gamma1256(W[j - 2]), W[j - 7]), Gamma0256(W[j - 15])), W[j - 16]);
                T1 = safe_add(safe_add(safe_add(safe_add(h, Sigma1256(e)), Ch(e, f, g)), K[j]), W[j]);
                T2 = safe_add(Sigma0256(a), Maj(a, b, c));
                h = g; g = f; f = e; e = safe_add(d, T1); d = c; c = b; b = a; a = safe_add(T1, T2);
            }
            HASH[0] = safe_add(a, HASH[0]); HASH[1] = safe_add(b, HASH[1]); HASH[2] = safe_add(c, HASH[2]); HASH[3] = safe_add(d, HASH[3]); HASH[4] = safe_add(e, HASH[4]); HASH[5] = safe_add(f, HASH[5]); HASH[6] = safe_add(g, HASH[6]); HASH[7] = safe_add(h, HASH[7]);
        }
        return HASH;
    }
    function str2binb (str) {
      var bin = Array();
      var mask = (1 << chrsz) - 1;
      for(var i = 0; i < str.length * chrsz; i += chrsz)
        bin[i>>5] |= (str.charCodeAt(i / chrsz) & mask) << (24 - i%32);
      return bin;
    }
    function binb2hex (binarray) {
      var hexcase = 0; /* hex output format. 0 - lowercase; 1 - uppercase */
      var hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
      var str = "";
      for (var i = 0; i < binarray.length * 4; i++) {
        str += hex_tab.charAt((binarray[i>>2] >> ((3 - i%4)*8+4)) & 0xF) + hex_tab.charAt((binarray[i>>2] >> ((3 - i%4)*8  )) & 0xF);
      }
      return str;
    }
    function hex_sha256(s){return binb2hex(core_sha256(str2binb(s),s.length * chrsz));}
    //s = pidCryptUtil.encodeUTF8(s);
    return binb2hex(core_sha256(str2binb(s), s.length * chrsz));

  }
}/**
*
*  SHA512 (Secure Hash Algorithm) for use in pidCrypt Library
*  Depends on pidCrypt (pidcrypt.js, pidcrypt_util.js)
*
*
**/
/* A JavaScript implementation of the SHA family of hashes, as defined in FIPS PUB 180-2
 * Version 1.11 Copyright Brian Turek 2008
 * Distributed under the BSD License
 * See http://jssha.sourceforge.net/ for more information
 *
 * Several functions taken from Paul Johnson
 */
if(typeof(pidCrypt) != 'undefined')
{

  function Int_64(msint_32,lsint_32)
  {
    this.highOrder=msint_32;
    this.lowOrder=lsint_32;
  }
  function jsSHA(srcString)
  {
    jsSHA.charSize=8;
    jsSHA.b64pad ="";
    jsSHA.hexCase=0;
    var sha384=null;
    var sha512=null;
    var str2binb=function(str)
    {
      var bin=[];
      var mask =(1 << jsSHA.charSize)- 1;
      var length=str.length*jsSHA.charSize;
      for(var i=0;i<length;i += jsSHA.charSize)
      {
        bin[i >> 5] |=(str.charCodeAt(i/jsSHA.charSize)& mask)<<(32-jsSHA.charSize-i%32);
      }
      return bin;
    };
    var strBinLen=srcString.length*jsSHA.charSize;
    var strToHash=str2binb(srcString);

    var binb2hex=function(binarray)
    {
      var hex_tab=jsSHA.hexCase?"0123456789ABCDEF":"0123456789abcdef";
      var str="";
      var length=binarray.length*4;
      for(var i=0;i<length;i++)
      {
        str += hex_tab.charAt((binarray[i >> 2] >>((3-i%4)* 8+4))& 0xF)+ hex_tab.charAt((binarray[i >> 2] >>((3-i%4)* 8))& 0xF);
      }
      return str;
    };

    var binb2b64=function(binarray)
    {
      var tab="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
      var str="";
      var length=binarray.length*4;
      for(var i=0;i<length;i += 3)
      {
        var triplet =(((binarray[i >> 2] >> 8 *(3-i%4))& 0xFF)<< 16)|(((binarray[i+1 >> 2] >> 8 *(3 -(i+1)% 4))& 0xFF)<< 8)|((binarray[i+2 >> 2] >> 8 *(3 -(i+2)% 4))& 0xFF);
        for(var j=0;j<4;j++)
        {
          if(i*8+j*6>binarray.length*32)
          {
            str += jsSHA.b64pad;
          }
          else
          {
            str += tab.charAt((triplet >> 6 *(3-j))& 0x3F);
          }
        }
      }
      return str;
    };

    var rotr=function(x,n)
    {
      if(n<32)
      {
        return new Int_64((x.highOrder >>> n)|(x.lowOrder <<(32-n)),(x.lowOrder >>> n)|(x.highOrder <<(32-n)));
      }
      else if(n===32)
           {
               return new Int_64(x.lowOrder,x.highOrder);
           }
           else
           {
             return rotr(rotr(x,32),n-32);
           }
    };

    var shr=function(x,n){if(n<32){return new Int_64(x.highOrder >>> n,x.lowOrder >>> n |(x.highOrder <<(32-n)));
    }
    else if(n===32)
           {
             return new Int_64(0,x.highOrder);
           }
           else
           {
             return shr(shr(x,32),n-32);
           }
    };

    var ch=function(x,y,z)
    {
      return new Int_64((x.highOrder & y.highOrder)^(~x.highOrder & z.highOrder),(x.lowOrder & y.lowOrder)^(~x.lowOrder & z.lowOrder));
    };

    var maj=function(x,y,z)
    {
      return new Int_64((x.highOrder & y.highOrder)^(x.highOrder & z.highOrder)^(y.highOrder & z.highOrder),(x.lowOrder & y.lowOrder)^(x.lowOrder & z.lowOrder)^(y.lowOrder & z.lowOrder));
    };

    var sigma0=function(x)
    {
      var rotr28=rotr(x,28);
      var rotr34=rotr(x,34);
      var rotr39=rotr(x,39);
      return new Int_64(rotr28.highOrder ^ rotr34.highOrder ^ rotr39.highOrder,rotr28.lowOrder ^ rotr34.lowOrder ^ rotr39.lowOrder);
    };

    var sigma1=function(x)
    {
      var rotr14=rotr(x,14);
      var rotr18=rotr(x,18);
      var rotr41=rotr(x,41);
      return new Int_64(rotr14.highOrder ^ rotr18.highOrder ^ rotr41.highOrder,rotr14.lowOrder ^ rotr18.lowOrder ^ rotr41.lowOrder);
    };

    var gamma0=function(x)
    {
      var rotr1=rotr(x,1);
      var rotr8=rotr(x,8);
      var shr7=shr(x,7);
      return new Int_64(rotr1.highOrder ^ rotr8.highOrder ^ shr7.highOrder,rotr1.lowOrder ^ rotr8.lowOrder ^ shr7.lowOrder);
    };

    var gamma1=function(x)
    {
      var rotr19=rotr(x,19);
      var rotr61=rotr(x,61);
      var shr6=shr(x,6);
      return new Int_64(rotr19.highOrder ^ rotr61.highOrder ^ shr6.highOrder,rotr19.lowOrder ^ rotr61.lowOrder ^ shr6.lowOrder);
    };

    var safeAdd=function(x,y)
    {
      var lsw =(x.lowOrder & 0xFFFF)+(y.lowOrder & 0xFFFF);
      var msw =(x.lowOrder >>> 16)+(y.lowOrder >>> 16)+(lsw >>> 16);
      var lowOrder =((msw & 0xFFFF)<< 16)|(lsw & 0xFFFF);
      lsw =(x.highOrder & 0xFFFF)+(y.highOrder & 0xFFFF)+(msw >>> 16);
      msw =(x.highOrder >>> 16)+(y.highOrder >>> 16)+(lsw >>> 16);
      var highOrder =((msw & 0xFFFF)<< 16)|(lsw & 0xFFFF);
      return new Int_64(highOrder,lowOrder);
    };

    var coreSHA2=function(variant)
    {
      var W=[];
      var a,b,c,d,e,f,g,h;
      var T1,T2;
      var H;
      var K=[new Int_64(0x428a2f98,0xd728ae22),new Int_64(0x71374491,0x23ef65cd),new Int_64(0xb5c0fbcf,0xec4d3b2f),new Int_64(0xe9b5dba5,0x8189dbbc),new Int_64(0x3956c25b,0xf348b538),new Int_64(0x59f111f1,0xb605d019),new Int_64(0x923f82a4,0xaf194f9b),new Int_64(0xab1c5ed5,0xda6d8118),new Int_64(0xd807aa98,0xa3030242),new Int_64(0x12835b01,0x45706fbe),new Int_64(0x243185be,0x4ee4b28c),new Int_64(0x550c7dc3,0xd5ffb4e2),new Int_64(0x72be5d74,0xf27b896f),new Int_64(0x80deb1fe,0x3b1696b1),new Int_64(0x9bdc06a7,0x25c71235),new Int_64(0xc19bf174,0xcf692694),new Int_64(0xe49b69c1,0x9ef14ad2),new Int_64(0xefbe4786,0x384f25e3),new Int_64(0x0fc19dc6,0x8b8cd5b5),new Int_64(0x240ca1cc,0x77ac9c65),new Int_64(0x2de92c6f,0x592b0275),new Int_64(0x4a7484aa,0x6ea6e483),new Int_64(0x5cb0a9dc,0xbd41fbd4),new Int_64(0x76f988da,0x831153b5),new Int_64(0x983e5152,0xee66dfab),new Int_64(0xa831c66d,0x2db43210),new Int_64(0xb00327c8,0x98fb213f),new Int_64(0xbf597fc7,0xbeef0ee4),new Int_64(0xc6e00bf3,0x3da88fc2),new Int_64(0xd5a79147,0x930aa725),new Int_64(0x06ca6351,0xe003826f),new Int_64(0x14292967,0x0a0e6e70),new Int_64(0x27b70a85,0x46d22ffc),new Int_64(0x2e1b2138,0x5c26c926),new Int_64(0x4d2c6dfc,0x5ac42aed),new Int_64(0x53380d13,0x9d95b3df),new Int_64(0x650a7354,0x8baf63de),new Int_64(0x766a0abb,0x3c77b2a8),new Int_64(0x81c2c92e,0x47edaee6),new Int_64(0x92722c85,0x1482353b),new Int_64(0xa2bfe8a1,0x4cf10364),new Int_64(0xa81a664b,0xbc423001),new Int_64(0xc24b8b70,0xd0f89791),new Int_64(0xc76c51a3,0x0654be30),new Int_64(0xd192e819,0xd6ef5218),new Int_64(0xd6990624,0x5565a910),new Int_64(0xf40e3585,0x5771202a),new Int_64(0x106aa070,0x32bbd1b8),new Int_64(0x19a4c116,0xb8d2d0c8),new Int_64(0x1e376c08,0x5141ab53),new Int_64(0x2748774c,0xdf8eeb99),new Int_64(0x34b0bcb5,0xe19b48a8),new Int_64(0x391c0cb3,0xc5c95a63),new Int_64(0x4ed8aa4a,0xe3418acb),new Int_64(0x5b9cca4f,0x7763e373),new Int_64(0x682e6ff3,0xd6b2b8a3),new Int_64(0x748f82ee,0x5defb2fc),new Int_64(0x78a5636f,0x43172f60),new Int_64(0x84c87814,0xa1f0ab72),new Int_64(0x8cc70208,0x1a6439ec),new Int_64(0x90befffa,0x23631e28),new Int_64(0xa4506ceb,0xde82bde9),new Int_64(0xbef9a3f7,0xb2c67915),new Int_64(0xc67178f2,0xe372532b),new Int_64(0xca273ece,0xea26619c),new Int_64(0xd186b8c7,0x21c0c207),new Int_64(0xeada7dd6,0xcde0eb1e),new Int_64(0xf57d4f7f,0xee6ed178),new Int_64(0x06f067aa,0x72176fba),new Int_64(0x0a637dc5,0xa2c898a6),new Int_64(0x113f9804,0xbef90dae),new Int_64(0x1b710b35,0x131c471b),new Int_64(0x28db77f5,0x23047d84),new Int_64(0x32caab7b,0x40c72493),new Int_64(0x3c9ebe0a,0x15c9bebc),new Int_64(0x431d67c4,0x9c100d4c),new Int_64(0x4cc5d4be,0xcb3e42b6),new Int_64(0x597f299c,0xfc657e2a),new Int_64(0x5fcb6fab,0x3ad6faec),new Int_64(0x6c44198c,0x4a475817)];
      if(variant==="SHA-384")
      {
        H=[new Int_64(0xcbbb9d5d,0xc1059ed8),new Int_64(0x0629a292a,0x367cd507),new Int_64(0x9159015a,0x3070dd17),new Int_64(0x152fecd8,0xf70e5939),new Int_64(0x67332667,0xffc00b31),new Int_64(0x98eb44a87,0x68581511),new Int_64(0xdb0c2e0d,0x64f98fa7),new Int_64(0x47b5481d,0xbefa4fa4)];
      }
      else
      {
        H=[new Int_64(0x6a09e667,0xf3bcc908),new Int_64(0xbb67ae85,0x84caa73b),new Int_64(0x3c6ef372,0xfe94f82b),new Int_64(0xa54ff53a,0x5f1d36f1),new Int_64(0x510e527f,0xade682d1),new Int_64(0x9b05688c,0x2b3e6c1f),new Int_64(0x1f83d9ab,0xfb41bd6b),new Int_64(0x5be0cd19,0x137e2179)];
      }
      var message=strToHash.slice();
      message[strBinLen >> 5] |= 0x80 <<(24-strBinLen%32);
      message[((strBinLen+1+128 >> 10)<< 5)+ 31]=strBinLen;
      var appendedMessageLength=message.length;
      for(var i=0;i<appendedMessageLength;i += 32)
      {
        a=H[0];
        b=H[1];
        c=H[2];
        d=H[3];
        e=H[4];
        f=H[5];
        g=H[6];
        h=H[7];
        for(var t=0;t<80;t++)
        {
          if(t<16)
          {
            W[t]=new Int_64(message[t*2+i],message[t*2+i+1]);
          }
          else
          {
            W[t]=safeAdd(safeAdd(safeAdd(gamma1(W[t-2]),W[t-7]),gamma0(W[t-15])),W[t-16]);
          }
          T1=safeAdd(safeAdd(safeAdd(safeAdd(h,sigma1(e)),ch(e,f,g)),K[t]),W[t]);
          T2=safeAdd(sigma0(a),maj(a,b,c));
          h=g;
          g=f;
          f=e;
          e=safeAdd(d,T1);
          d=c;
          c=b;
          b=a;
          a=safeAdd(T1,T2);
        }
        H[0]=safeAdd(a,H[0]);
        H[1]=safeAdd(b,H[1]);
        H[2]=safeAdd(c,H[2]);
        H[3]=safeAdd(d,H[3]);
        H[4]=safeAdd(e,H[4]);
        H[5]=safeAdd(f,H[5]);
        H[6]=safeAdd(g,H[6]);
        H[7]=safeAdd(h,H[7]);
      }
      switch(variant)
      {
        case "SHA-384":
          return[H[0].highOrder,H[0].lowOrder,H[1].highOrder,H[1].lowOrder,H[2].highOrder,H[2].lowOrder,H[3].highOrder,H[3].lowOrder,H[4].highOrder,H[4].lowOrder,H[5].highOrder,H[5].lowOrder];
        case "SHA-512":
          return[H[0].highOrder,H[0].lowOrder,H[1].highOrder,H[1].lowOrder,H[2].highOrder,H[2].lowOrder,H[3].highOrder,H[3].lowOrder,H[4].highOrder,H[4].lowOrder,H[5].highOrder,H[5].lowOrder,H[6].highOrder,H[6].lowOrder,H[7].highOrder,H[7].lowOrder];
        default:return [];
      }
    };

    this.getHash=function(variant,format)
    {
      var formatFunc=null;
      switch(format)
      {
        case "HEX":
          formatFunc=binb2hex;
        break;
        case "B64":
          formatFunc=binb2b64;
        break;
        default:
          return "FORMAT NOT RECOGNIZED";
      }
      switch(variant)
      {
        case "SHA-384":
          if(sha384===null)
          {
            sha384=coreSHA2(variant);
          }
          return formatFunc(sha384);
        case "SHA-512":
          if(sha512===null)
          {
            sha512=coreSHA2(variant);
          }
          return formatFunc(sha512);
        default:
          return "HASH NOT RECOGNIZED";
      }
    };
  }

  pidCrypt.SHA512 = function(str,format)
  {
    if(!format) format = 'HEX';
    var sha = new jsSHA(str);
    return sha.getHash('SHA-512', format);
  }

  pidCrypt.SHA384 = function(str,format)
  {
    if(!format) format = 'HEX';
    var sha = new jsSHA(str);
    return sha.getHash('SHA-384', format);
  }
}/*----------------------------------------------------------------------------*/
 // Copyright (c) 2010 pidder <www.pidder.com>
 // Permission to use, copy, modify, and/or distribute this software for any
 // purpose with or without fee is hereby granted, provided that the above
 // copyright notice and this permission notice appear in all copies.
 //
 // THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 // WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 // MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 // ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 // WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 // ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 // OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
/*----------------------------------------------------------------------------*/
/*
*  Maps the pidcrypt utillity functions for string operations to the
*  javascript core class String
*
*
/*----------------------------------------------------------------------------*/
String.prototype.encodeBase64 = function(utf8encode)
{
  return pidCryptUtil.encodeBase64(this,utf8encode);
}
String.prototype.decodeBase64 = function(utf8decode)
{
  return pidCryptUtil.decodeBase64(this,utf8decode);
}
String.prototype.encodeUTF8 = function()
{
  return pidCryptUtil.encodeUTF8(this);
}
String.prototype.decodeUTF8  = function()
{
  return pidCryptUtil.decodeUTF8(this);
}
String.prototype.convertToHex = function()
{
  return pidCryptUtil.convertToHex(this);
}
String.prototype.convertFromHex = function()
{
  return pidCryptUtil.convertFromHex(this);
}
String.prototype.stripLineFeeds = function()
{
  return pidCryptUtil.stripLineFeeds(this);
}
String.prototype.toByteArray =  function()
{
  return pidCryptUtil.toByteArray(this);
}
String.prototype.fragment = function(length,lf)
{
  return pidCryptUtil.fragment(this,length,lf);
}
String.prototype.formatHex = function(length)
{
  return pidCryptUtil.formatHex(this,length);
}
