// these variables will be filled when generating the file - the template format is 'variable_name'
const staticryptInitiator = (function () {
  const exports = {};
  const cryptoEngine = (function () {
    const exports = {};
    const { subtle } = crypto;

    const IV_BITS = 16 * 8;
    const HEX_BITS = 4;
    const ENCRYPTION_ALGO = "AES-CBC";

    /**
     * Translates between utf8 encoded hexadecimal strings
     * and Uint8Array bytes.
     */
    const HexEncoder = {
      /**
       * hex string -> bytes
       * @param {string} hexString
       * @returns {Uint8Array}
       */
      parse: function (hexString) {
        if (hexString.length % 2 !== 0) throw "Invalid hexString";
        const arrayBuffer = new Uint8Array(hexString.length / 2);

        for (let i = 0; i < hexString.length; i += 2) {
          const byteValue = parseInt(hexString.substring(i, i + 2), 16);
          if (isNaN(byteValue)) {
            throw "Invalid hexString";
          }
          arrayBuffer[i / 2] = byteValue;
        }
        return arrayBuffer;
      },

      /**
       * bytes -> hex string
       * @param {Uint8Array} bytes
       * @returns {string}
       */
      stringify: function (bytes) {
        const hexBytes = [];

        for (let i = 0; i < bytes.length; ++i) {
          let byteString = bytes[i].toString(16);
          if (byteString.length < 2) {
            byteString = "0" + byteString;
          }
          hexBytes.push(byteString);
        }
        return hexBytes.join("");
      },
    };

    /**
     * Translates between utf8 strings and Uint8Array bytes.
     */
    const UTF8Encoder = {
      parse: function (str) {
        return new TextEncoder().encode(str);
      },

      stringify: function (bytes) {
        return new TextDecoder().decode(bytes);
      },
    };

    /**
     * Salt and encrypt a msg with a password.
     */
    async function encrypt(msg, hashedPassword) {
      // Must be 16 bytes, unpredictable, and preferably cryptographically random. However, it need not be secret.
      // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt#parameters
      const iv = crypto.getRandomValues(new Uint8Array(IV_BITS / 8));

      const key = await subtle.importKey(
        "raw",
        HexEncoder.parse(hashedPassword),
        ENCRYPTION_ALGO,
        false,
        ["encrypt"]
      );

      const encrypted = await subtle.encrypt(
        {
          name: ENCRYPTION_ALGO,
          iv: iv,
        },
        key,
        UTF8Encoder.parse(msg)
      );

      // iv will be 32 hex characters, we prepend it to the ciphertext for use in decryption
      return (
        HexEncoder.stringify(iv) +
        HexEncoder.stringify(new Uint8Array(encrypted))
      );
    }
    exports.encrypt = encrypt;

    /**
     * Decrypt a salted msg using a password.
     *
     * @param {string} encryptedMsg
     * @param {string} hashedPassword
     * @returns {Promise<string>}
     */
    async function decrypt(encryptedMsg, hashedPassword) {
      const ivLength = IV_BITS / HEX_BITS;
      const iv = HexEncoder.parse(encryptedMsg.substring(0, ivLength));
      const encrypted = encryptedMsg.substring(ivLength);

      const key = await subtle.importKey(
        "raw",
        HexEncoder.parse(hashedPassword),
        ENCRYPTION_ALGO,
        false,
        ["decrypt"]
      );

      const outBuffer = await subtle.decrypt(
        {
          name: ENCRYPTION_ALGO,
          iv: iv,
        },
        key,
        HexEncoder.parse(encrypted)
      );

      return UTF8Encoder.stringify(new Uint8Array(outBuffer));
    }
    exports.decrypt = decrypt;

    /**
     * Salt and hash the password so it can be stored in localStorage without opening a password reuse vulnerability.
     *
     * @param {string} password
     * @param {string} salt
     * @returns {Promise<string>}
     */
    async function hashPassword(password, salt) {
      // we hash the password in multiple steps, each adding more iterations. This is because we used to allow less
      // iterations, so for backward compatibility reasons, we need to support going from that to more iterations.
      let hashedPassword = await hashLegacyRound(password, salt);

      hashedPassword = await hashSecondRound(hashedPassword, salt);

      return hashThirdRound(hashedPassword, salt);
    }
    exports.hashPassword = hashPassword;

    /**
     * This hashes the password with 1k iterations. This is a low number, we need this function to support backwards
     * compatibility.
     *
     * @param {string} password
     * @param {string} salt
     * @returns {Promise<string>}
     */
    function hashLegacyRound(password, salt) {
      return pbkdf2(password, salt, 1000, "SHA-1");
    }
    exports.hashLegacyRound = hashLegacyRound;

    /**
     * Add a second round of iterations. This is because we used to use 1k, so for backwards compatibility with
     * remember-me/autodecrypt links, we need to support going from that to more iterations.
     *
     * @param hashedPassword
     * @param salt
     * @returns {Promise<string>}
     */
    function hashSecondRound(hashedPassword, salt) {
      return pbkdf2(hashedPassword, salt, 14000, "SHA-256");
    }
    exports.hashSecondRound = hashSecondRound;

    /**
     * Add a third round of iterations to bring total number to 600k. This is because we used to use 1k, then 15k, so for
     * backwards compatibility with remember-me/autodecrypt links, we need to support going from that to more iterations.
     *
     * @param hashedPassword
     * @param salt
     * @returns {Promise<string>}
     */
    function hashThirdRound(hashedPassword, salt) {
      return pbkdf2(hashedPassword, salt, 585000, "SHA-256");
    }
    exports.hashThirdRound = hashThirdRound;

    /**
     * Salt and hash the password so it can be stored in localStorage without opening a password reuse vulnerability.
     *
     * @param {string} password
     * @param {string} salt
     * @param {int} iterations
     * @param {string} hashAlgorithm
     * @returns {Promise<string>}
     */
    async function pbkdf2(password, salt, iterations, hashAlgorithm) {
      const key = await subtle.importKey(
        "raw",
        UTF8Encoder.parse(password),
        "PBKDF2",
        false,
        ["deriveBits"]
      );

      const keyBytes = await subtle.deriveBits(
        {
          name: "PBKDF2",
          hash: hashAlgorithm,
          iterations,
          salt: UTF8Encoder.parse(salt),
        },
        key,
        256
      );

      return HexEncoder.stringify(new Uint8Array(keyBytes));
    }

    function generateRandomSalt() {
      const bytes = crypto.getRandomValues(new Uint8Array(128 / 8));

      return HexEncoder.stringify(new Uint8Array(bytes));
    }
    exports.generateRandomSalt = generateRandomSalt;

    async function signMessage(hashedPassword, message) {
      const key = await subtle.importKey(
        "raw",
        HexEncoder.parse(hashedPassword),
        {
          name: "HMAC",
          hash: "SHA-256",
        },
        false,
        ["sign"]
      );
      const signature = await subtle.sign(
        "HMAC",
        key,
        UTF8Encoder.parse(message)
      );

      return HexEncoder.stringify(new Uint8Array(signature));
    }
    exports.signMessage = signMessage;

    function getRandomAlphanum() {
      const possibleCharacters =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

      let byteArray;
      let parsedInt;

      // Keep generating new random bytes until we get a value that falls
      // within a range that can be evenly divided by possibleCharacters.length
      do {
        byteArray = crypto.getRandomValues(new Uint8Array(1));
        // extract the lowest byte to get an int from 0 to 255 (probably unnecessary, since we're only generating 1 byte)
        parsedInt = byteArray[0] & 0xff;
      } while (parsedInt >= 256 - (256 % possibleCharacters.length));

      // Take the modulo of the parsed integer to get a random number between 0 and totalLength - 1
      const randomIndex = parsedInt % possibleCharacters.length;

      return possibleCharacters[randomIndex];
    }

    /**
     * Generate a random string of a given length.
     *
     * @param {int} length
     * @returns {string}
     */
    function generateRandomString(length) {
      let randomString = "";

      for (let i = 0; i < length; i++) {
        randomString += getRandomAlphanum();
      }

      return randomString;
    }
    exports.generateRandomString = generateRandomString;

    return exports;
  })();
  const codec = (function () {
    const exports = {};
    /**
     * Initialize the codec with the provided cryptoEngine - this return functions to encode and decode messages.
     *
     * @param cryptoEngine - the engine to use for encryption / decryption
     */
    function init(cryptoEngine) {
      const exports = {};

      /**
       * Top-level function for encoding a message.
       * Includes password hashing, encryption, and signing.
       *
       * @param {string} msg
       * @param {string} password
       * @param {string} salt
       *
       * @returns {string} The encoded text
       */
      async function encode(msg, password, salt) {
        const hashedPassword = await cryptoEngine.hashPassword(password, salt);

        const encrypted = await cryptoEngine.encrypt(msg, hashedPassword);

        // we use the hashed password in the HMAC because this is effectively what will be used a password (so we can store
        // it in localStorage safely, we don't use the clear text password)
        const hmac = await cryptoEngine.signMessage(hashedPassword, encrypted);

        return hmac + encrypted;
      }
      exports.encode = encode;

      /**
       * Encode using a password that has already been hashed. This is useful to encode multiple messages in a row, that way
       * we don't need to hash the password multiple times.
       *
       * @param {string} msg
       * @param {string} hashedPassword
       *
       * @returns {string} The encoded text
       */
      async function encodeWithHashedPassword(msg, hashedPassword) {
        const encrypted = await cryptoEngine.encrypt(msg, hashedPassword);

        // we use the hashed password in the HMAC because this is effectively what will be used a password (so we can store
        // it in localStorage safely, we don't use the clear text password)
        const hmac = await cryptoEngine.signMessage(hashedPassword, encrypted);

        return hmac + encrypted;
      }
      exports.encodeWithHashedPassword = encodeWithHashedPassword;

      /**
       * Top-level function for decoding a message.
       * Includes signature check and decryption.
       *
       * @param {string} signedMsg
       * @param {string} hashedPassword
       * @param {string} salt
       * @param {int} backwardCompatibleAttempt
       * @param {string} originalPassword
       *
       * @returns {Object} {success: true, decoded: string} | {success: false, message: string}
       */
      async function decode(
        signedMsg,
        hashedPassword,
        salt,
        backwardCompatibleAttempt = 0,
        originalPassword = ""
      ) {
        const encryptedHMAC = signedMsg.substring(0, 64);
        const encryptedMsg = signedMsg.substring(64);
        const decryptedHMAC = await cryptoEngine.signMessage(
          hashedPassword,
          encryptedMsg
        );

        if (decryptedHMAC !== encryptedHMAC) {
          // we have been raising the number of iterations in the hashing algorithm multiple times, so to support the old
          // remember-me/autodecrypt links we need to try bringing the old hashes up to speed.
          originalPassword = originalPassword || hashedPassword;
          if (backwardCompatibleAttempt === 0) {
            const updatedHashedPassword = await cryptoEngine.hashThirdRound(
              originalPassword,
              salt
            );

            return decode(
              signedMsg,
              updatedHashedPassword,
              salt,
              backwardCompatibleAttempt + 1,
              originalPassword
            );
          }
          if (backwardCompatibleAttempt === 1) {
            let updatedHashedPassword = await cryptoEngine.hashSecondRound(
              originalPassword,
              salt
            );
            updatedHashedPassword = await cryptoEngine.hashThirdRound(
              updatedHashedPassword,
              salt
            );

            return decode(
              signedMsg,
              updatedHashedPassword,
              salt,
              backwardCompatibleAttempt + 1,
              originalPassword
            );
          }

          return { success: false, message: "Signature mismatch" };
        }

        return {
          success: true,
          decoded: await cryptoEngine.decrypt(encryptedMsg, hashedPassword),
        };
      }
      exports.decode = decode;

      return exports;
    }
    exports.init = init;

    return exports;
  })();
  const decode = codec.init(cryptoEngine).decode;

  /**
   * Initialize the staticrypt module, that exposes functions callbable by the password_template.
   *
   * @param {{
   *  staticryptEncryptedMsgUniqueVariableName: string,
   *  isRememberEnabled: boolean,
   *  rememberDurationInDays: number,
   *  staticryptSaltUniqueVariableName: string,
   * }} staticryptConfig - object of data that is stored on the password_template at encryption time.
   *
   * @param {{
   *  rememberExpirationKey: string,
   *  rememberPassphraseKey: string,
   *  replaceHtmlCallback: function,
   *  clearLocalStorageCallback: function,
   * }} templateConfig - object of data that can be configured by a custom password_template.
   */
  function init(staticryptConfig, templateConfig) {
    const exports = {};

    /**
     * Decrypt our encrypted page, replace the whole HTML.
     *
     * @param {string} hashedPassword
     * @returns {Promise<boolean>}
     */
    async function decryptAndReplaceHtml(hashedPassword) {
      const {
        staticryptEncryptedMsgUniqueVariableName,
        staticryptSaltUniqueVariableName,
      } = staticryptConfig;
      const { replaceHtmlCallback } = templateConfig;

      const result = await decode(
        staticryptEncryptedMsgUniqueVariableName,
        hashedPassword,
        staticryptSaltUniqueVariableName
      );
      if (!result.success) {
        return false;
      }
      const plainHTML = result.decoded;

      // if the user configured a callback call it, otherwise just replace the whole HTML
      if (typeof replaceHtmlCallback === "function") {
        replaceHtmlCallback(plainHTML);
      } else {
        document.write(plainHTML);
        document.close();
      }

      return true;
    }

    /**
     * Attempt to decrypt the page and replace the whole HTML.
     *
     * @param {string} password
     *
     * @returns {Promise<{isSuccessful: boolean, hashedPassword?: string}>} - we return an object, so that if we want to
     *   expose more information in the future we can do it without breaking the password_template
     */
    async function handleDecryptionOfPage(password) {
      const {
        rememberDurationInDays,
        staticryptSaltUniqueVariableName,
      } = staticryptConfig;
      const { rememberExpirationKey, rememberPassphraseKey } = templateConfig;

      // decrypt and replace the whole page
      const hashedPassword = await cryptoEngine.hashPassword(
        password,
        staticryptSaltUniqueVariableName
      );

      const isDecryptionSuccessful = await decryptAndReplaceHtml(
        hashedPassword
      );

      if (!isDecryptionSuccessful) {
        return {
          isSuccessful: false,
          hashedPassword,
        };
      }

      // remember the hashedPassword and set its expiration if necessary
      
        window.localStorage.setItem(rememberPassphraseKey, hashedPassword);

        // set the expiration if the duration isn't 0 (meaning no expiration)
        if (rememberDurationInDays > 0) {
          window.localStorage.setItem(
            rememberExpirationKey,
            (
              new Date().getTime() +
              rememberDurationInDays * 24 * 60 * 60 * 1000
            ).toString()
          );
      }

      return {
        isSuccessful: true,
        hashedPassword,
      };
    }
    exports.handleDecryptionOfPage = handleDecryptionOfPage;

    /**
     * Clear localstorage from staticrypt related values
     */
    function clearLocalStorage() {
      const {
        clearLocalStorageCallback,
        rememberExpirationKey,
        rememberPassphraseKey,
      } = templateConfig;

      if (typeof clearLocalStorageCallback === "function") {
        clearLocalStorageCallback();
      } else {
        localStorage.removeItem(rememberPassphraseKey);
        localStorage.removeItem(rememberExpirationKey);
      }
    }

    async function handleDecryptOnLoad() {
      let isSuccessful = await decryptOnLoadFromUrl();

      if (!isSuccessful) {
        isSuccessful = await decryptOnLoadFromRememberMe();
      }

      return { isSuccessful };
    }
    exports.handleDecryptOnLoad = handleDecryptOnLoad;

    /**
     * Clear storage if we are logging out
     *
     * @returns {boolean} - whether we logged out
     */
    function logoutIfNeeded() {
      const logoutKey = "logout";

      // handle logout through query param
      const queryParams = new URLSearchParams(window.location.search);
      if (queryParams.has(logoutKey)) {
        clearLocalStorage();
        return true;
      }

      // handle logout through URL fragment
      const hash = window.location.hash.substring(1);
      if (hash.includes(logoutKey)) {
        clearLocalStorage();
        return true;
      }

      return false;
    }

    /**
     * To be called on load: check if we want to try to decrypt and replace the HTML with the decrypted content, and
     * try to do it if needed.
     *
     * @returns {Promise<boolean>} true if we derypted and replaced the whole page, false otherwise
     */
    async function decryptOnLoadFromRememberMe() {
      const { rememberDurationInDays } = staticryptConfig;
      const { rememberExpirationKey, rememberPassphraseKey } = templateConfig;

      // if we are login out, terminate
      if (logoutIfNeeded()) {
        return false;
      }

      // if there is expiration configured, check if we're not beyond the expiration
      if (rememberDurationInDays && rememberDurationInDays > 0) {
        const expiration = localStorage.getItem(rememberExpirationKey),
          isExpired = expiration && new Date().getTime() > parseInt(expiration);

        if (isExpired) {
          clearLocalStorage();
          return false;
        }
      }

      const hashedPassword = localStorage.getItem(rememberPassphraseKey);

      if (hashedPassword) {
        // try to decrypt
        const isDecryptionSuccessful = await decryptAndReplaceHtml(
          hashedPassword
        );

        // if the decryption is unsuccessful the password might be wrong - silently clear the saved data and let
        // the user fill the password form again
        if (!isDecryptionSuccessful) {
          clearLocalStorage();
          return false;
        }

        return true;
      }

      return false;
    }

    function decryptOnLoadFromUrl() {
      const passwordKey = "staticrypt_pwd";

      // get the password from the query param
      const queryParams = new URLSearchParams(window.location.search);
      const hashedPasswordQuery = queryParams.get(passwordKey);

      // get the password from the url fragment
      const hashRegexMatch = window.location.hash
        .substring(1)
        .match(new RegExp(passwordKey + "=(.*)"));
      const hashedPasswordFragment = hashRegexMatch ? hashRegexMatch[1] : null;

      const hashedPassword = hashedPasswordFragment || hashedPasswordQuery;

      if (hashedPassword) {
        return decryptAndReplaceHtml(hashedPassword);
      }

      return false;
    }

    return exports;
  }
  exports.init = init;

  return exports;
})();
const templateError = "template_error",
  isRememberEnabled = true,
  staticryptConfig = {
    staticryptEncryptedMsgUniqueVariableName:
      "bf3ecb3480363daa95dc00034a2199279cdd01cba9a18acaa679b4be4d806150eaaec4daa5d696a318c07948a22f10018d2ae0a0dd7952ad6e0181249c62b785531b9f8c06cbf1a71b238fe7bc4b9a3432953c4a40722fb9919e7e4588a5059c2d4319e7f688248f64ef6d6172b4ef862b4703ff6c2a152a4e2021e57bb5689a5303048e51afb5bba90cfa347b57c8d50db117245fe30259aba866dec77911d19cc0dc496ad9b71f4e8293229351bf43a6a2d17d4aac49cf471263cb4ba49191c2a70813881e9c4be14a3e0c27c5650af910b989ee0e14b5347636cfc33e3a674b1bd21956b9afd8c33bc23b061f17c08bfb430c8436c71a54f1559743c23a3e5da5fd308ee0db91f89ff87b37bb1c3b6a5c2289ef9dabeb4f6e86010d062d1ad22324787e93ab0d1f22072f39e3fd6e2d27da08fc59b78a5689f60f12bc45f7026ea4642c46c0a8babd38d01ede809645ecfebcd864c1c3b6c68380738805a1c966d0b96e861aacff7dbf69ea518228dedd6910c15fd6593387a9ffacdb51355a217f64ef3f8ca9950a3cd9fbd37bc5bcc7566df779cf6da46fa990791214c5a7f20f471fddf19eaffd322aa9664bc134418060f8ae221709355f5c7ad43f0f99c92daf9cd557ebf9a0f6053c5d252f6ff766f016e58bd6d61b0a76ee88ef838cad2f3afd099f0c2d19b88bb38dd1f2670c9bc206c9f255f0363bd3993ee3dc44695dd875a4ad1199552157c30a9cc717546f97d9d41d8c3bc3b372ceabca79f318e9648d10cf52528515859034fa0eb45772a226803888686922e08b4556fc611d6eb3e8eb304cc2f41675499b2d529e34bdcb2e399fcd0b61bb5365abf49794ae444e80ed19c240853d5bdcd83f57ac0c88780dfe12c1ec1d8650860e9b9c568b9c5944f9dbf8fc5658415b438fdcba4000d7fe8c6ab2c754e891825cc5d5db2543ae4714efba42083a7b3e22af89642a4581f46ae406178c167d79ccfd8f8780ecdcc2ff94be67ad2ac30b6b1cbd8519285fbd421e2b157ac4fa2c00114f9bb61c95e859912db02ae2b4646829744bd1f77787f6e127ac34187095e2fe36b478efa22d1a17957aa4b796b1d406df0c991794804a8dd3e4d84f2f14728a18e3f61240f546b0d1f2961477558cc17ba5d51a6548d16324d90773491149b6345458c9775893105047528c9b913d1852a24b3f8cffa7400f0437d237c9565ba8289b1d8e75586a7eb9b99bf318dc10bd46891cc77e9e9d95e31836e7d290be1783154d071a6019e90b2c75f2268b2d1d2ab26ca4513a3138b8285482a9bb1ff8c68ea8c7a361c468163ee905a181a632f768a3f94f8b8d5e2b7eff4c55d57eb24e2acfd23a9bf751e369cfeff0703f8d310c90356e61ebe9047e0411eae68b89ade7ef496d09b9344bbbc2b0615100ac183fa59fb44c2a89a882508996e06f42005b98daf3128ae58acfec7f92523a315915aa04ff85ed67407a5925dfaef49465daf38a65041272988039c660eda1fab529674fe1cfc6232b346a8ed5d989a5ccb615231c4f5645e47223e58c09308bfed65d7cd4c8182ff93e76fbbcd1cbf0967e712bc9e2bbca08a21f51a6b9c32b6e0f2094557f18c0cbbcbacd1993aa3a9ee0c3ffc00ebc10daba940275ef872b809b5a8b884c1396476ceb897382fd62a4d769af8bc99d1577ec88ccc2b80503bf70e78278e2696b49efbd1c76a5ae9cf542f6ac5cc03548b5a27e4ca6674b728515db26e857a79b21fb68e0359ae05551ecd24e87f37964d7f11e19a0b33c0705809d2539922ebc144eb6f72eb6ff8a1c04d18b5cae2c6e9bc9069818da27492cde2f60cb8cb699ce905ee61e655a100da028c0ea39832e38de4b8601dc303058bd21af57060c56de55b4853def8212c9acc9b7fba41643cc1e83da9b252bf5249b10cc36b3bf023c6e371bc0cafdb8676b1b79e24409a4edef01cd1cbc4f9a8eb5d2df366dffadd25d8ac8608930e24054299dc19a04e0447680d650e0b80b3eecaa2a0e7aba0bc66e02e67c111ee625cdd830dab6fb5cfcb57dbe11602224802d557ced29b0a44e8c12fef1c34e33308bef17885372a5256eed9659ccb56f9252ab0c7b6db36d975aad7d0ed7c7ad7ee7262d5ca975a1ada03cfcb52b9a0a3a1c92219456ae32562acd49652c8b508dd750681b71e4ef1e6e8fdca0d808943821e689f4621ec01d5460caaba100ef76e28a674e049deb48e68a4739775dc2db74d0c70dd1c511b30e93de7a5f451bdc99e554f6db17fd94b24d9e21549f45880d4744aa0dfa7b838fc272a40cec4333cf69b110306490ec3f329caae9aa92eb055620a078e1468e768230372db850941c5b6775c8ead0578cb377a5b64ca3d3d620ddc3fed229d3b8900e4aa89fc95c9fcda1250a459c66b3ca9f47d8e96ad395d5083e781b3b28f79ddd0656adef00510b3fbb4b77084fc30502965d454beddfb1d0ec431b13247c55aa7e480ce1259cd26aae614797d0f0f2ea0eedd5860bb26b8da1050a8db2792c01980d41d0d25bc9929d0f287f342f98ff51603572bc4f9430b9754a61b457012f735d403d90ab5cd0dfa694e7768c438506974effa5f05f2186d6fd7ee0c53913dacfb1675c791c7f1a9c011abc2290e446b94833fcffae34136dd234a58bc8153ed74c7ede88cf68edd0575d58c998cd71e6de7c00f296dc5bdccc90f1e49ecb4ea3479c8fba18504a1ee0649d58089f7a13ae1f65e721b6798cee83f15ff562a833232170f7c00c124d2757239a62caba53b4a6ba1afffd0cc17b7a0e003dda8d8bb9aca4454936b1d18546c339ae38c34dd14fb130cf95f8351829f5c9a123224227384966b0a048c0fb3a9ac18916edc0348043210b570b28fca71d1a0d67d254d4f4c2f61b16b6e155b07a3556162cd3ac94f186de1c5364d09bf6cb072b519e14dc8c0acfe8760f6b32f1aafa2a4be4d140a90715e1d7c986c26d76d1c2ca93af09c98b8b8fcf2fea9fa69482ab3a66c4004a40ea2b4e78ecf2290537c5782f7c077f58e3bff2d1751632c2fc6650830b3372f273b8c10dce2d1caeffa11a12369c6f5998e046f2812c89df716eb8c9754b4fef9716f8deefc1e7f3336043b0094e98ed571e8cb810f82d065471e7043fb7cec2bf9959773e83ff7007d1ba58b0279a85a391e447f4e8cd75dc52aa7e67992786cab1a3f2f8f3f9e02b0b9d140f221bb78f4ba97508708f30c27f3faa611fe49345fd5766e043c6fb02c14499e74556817ef844f764477f7ea3fcd01b5101c3911ff42d841bee38a3fd4b5ed35670d271fbb53f3c6805497b3c1f56d298d165dcb725ab9047e0e8c65d9815b697185cb718898f096f90e88f973651ee9ec0edb86e056de2fb0e572e25e0bfff26b355b59e36b8be888eb0c55391252f9965c7dbd9f519fa2db56f19b5e051265ec0b1522517af626ea0e06bc9f093022e880d95e6ae3ec938159caa564af53e92c4c9ac101fc68f5bf97d6351fb3eaf74286accc174bbfe994dea771b29b5ae48f87718f4c299c270037a81e5f002e13a3fb07e9ea3712dc97080fda0ebcc00fb91745253ebc84f36e927aedcff2d607c1c0616d6d9d3900b8f1ae03509aa6a2eb3ae75e94b2b48303bf0a6b9e73de1a377d3f56967accca25fe9a37f1f7028c832980544b96e4c42e3232ace7e2273bf2ceb85beec25623e03386486deb15714425d39e41b255392893523859a4a51c70521a31d4a4dab27a25bb30d40dd7a021a862f1b42344b94c96c5704b7d6579a5c38d4830e31f8cd1e97adecb13fb4942d47093a6599265a74858a2acfc0763ed012ff225fbfd860faf92e1d760e8a6700ba68daa955cf1acfe4cd50a17dfd6e204424764a1878d172aa8beb9dda7e125a03968fd1dbf8d0538c17a4b109af98a14b5070da65635d64aca70b555b5a3615223f947e4bd31a94f94e977ffbb8bc35cab8ea28d2973150c0be567025cbba5a23df40487ce9a79154c827ea135db7dccfcda1a2f6d61a419a3ea53fa9c5040c4ff3ea1f95dc40240d58d895f69842fa76c8c57f28ee499ce71952c6defb5d22ab6397c4a9be1eea7a80e66859448b4fe30533a0c39e0aab9251947c820780612e654a5d8d6ec09db57dca87cd973236ca0e49acbf1e31650d9a193c89c4b85b9a2d289e06c84992e27c7467a0ef5fc4bef51296981293b10fa454f8da08d4955f0af8835d5393eb49059c6e9285f44e392d417227cec606c5a8a530e19ca8e70afe7703d5b09a19291db494cc8c93efadef4aa959f803d29c07a8e9ace681855c1dacf89bb70eb5eb145d68162cb16fcf84e94e3278abdad7f2ae53b2f480190c7cc2191cd1ac311ff8b2bb2696844d18e009cbce61ccb34faf21f756e9db6af4499e10b7c475d21b775765bb6b3a425be2b4e43647f83d53a3e07f24befef69c6a2028b1620e3e40db2581a039c04d17135a5fc5dab98037f4a6e606b58723e54f2e6faa84e11280b1447cefe274117737c13d01bb88d1fe1340752a2b440d61c9b606a30980c23fea61c11f7a0d152c41db536da0f05397426124ccd662160adb5401f39c9db274e0d9606c27753faec2eeea78218f00d377ef88b0610b0d4e9504e04bdbbe23522d020a8ce4136cb1ce94fc766da0457bb8fa50b4ee715369fa7faa10801f8487efbdf9e474054a2938e03b0d9fde35ad2bd617a65408a582f1650ba5d86212b76202a912bee7202b5f733f2be68862181c963949bf168a33cd0fcba3f4cdb2734075447ac3b5f4196934ab6133ff1c51d4745160f14bbc8543011d279e7976c8bf698b89e459f7cfea73ec096dadb607d9764c09f9401f28fd8e3c36507379a775055f6e96924b3e4e7854c072f25559433a65085dae9fd794198394f6838811f8f5e528511ed20d1340a0828493b54b6fee769aa455f5607d82f7cef229b2bca509f85f2e051c82b18fabc31f75d70f5cded36b602da38b69343693e17921571cc50a4576f524acd68ef1b1389a5ad4bd7754fdbc3c1707af16a413569ef41623870c0d84c1558e2676d4089d4e3232e35db00c7320fe694ea5de88be69d0d4a4db7b3d8d7c74a4c0b50832628d3ad01fcd7ddec197a449dee47c3925aeb311160ce169c91276dda0f9d2feae956d4eefb4efc6c6906f2229a89b2ddb2bf99ff52fa3b98f607e722d07dd433f8fe84a662974582ad93132dbaf08eda60979b14f41603849a92e84bf85693dce0a166a9ea1786fa689a3114090db172ac3a122bbf9f9908562c532a010c06d3ea23c852c40f95b926fa0c9848ac9afd8ab4cf888a1e0bf445ad20af03bba1c854c39e08b5052974f252e740e94c6925ed0a885a839559c653522c649e254bc396157c3bce10a5fcbabae7a1600c275ea4ddd1d55a27a823bf8a1314189891a62e0cfeb86ce8ceb5ad6ef3ae9466370e05ff78709935091a146a066dc34ff075a4e0aeb2f119085c49987a20dc08948b8e4bc039a045fc3c082b61c96fbf5602d79cb9589ec12fe038843a1fdcd6fe6be3e8682974994052f9b2488f2d423a9bf0c34753d6272a1a4f6b6a470530733b6c899b3f95de0ddb1b718af4215466c7360eb9361889a9bbc97b47b890406535dc6100ae3bec62e9b51a95f00564ea32cd6408ba86e77c037f3ba2d7b20ec7cdd1d56abfc4c19b84539c5fa25ca7c91b99b99170ed4afb0eed05e1ac6b87c2fc7c997c7e15bd1cd4e822fea419c1286e1dd6994a183326393e5c89089e228bb660dec00baa229ca4fcdd3273ab60d1fa323288a35b76228cf8b6629cc573f86119bb0756e0e575f5f20718a42b5e3843a7a1677cdc5de47664a82b0b5201a995e42c2fd77ee69f7f4a988ed93bc9993aaa5b3e05d65880f3254ddff6e73765c409e45adfe171b20266bc73864842dd4d2d9a9e3cc8964e8f0a0e8c23bf44c4becff02e2d18402104a28f3f0247af0cd7d8ddae52996ea81c358cc80bb80707175f4dc11a589b6611e195f986baf755ce0c5ff11dea00447081d923933d5afaa7c1184b5a6bba3f4625dca43593429d69b0dd5381021e6844b72c50fa2c0a720e32231380eec893f23041ebb945744b04f4acf68d5aa5df092456c6d20a99f1648379e007a4957f083e8f75eab542daecb6d8ebc6aba282f1339360e12e86ccfcbc8d1e00af28eab1e11338896999e29b70fe805f27aa0cf2f9153f0a52446db16832dd9b1601d2fcc60c6f14bcb3d0db9bee8a1740613cc35d19dfaaecd7a69c1b15c7605bd66ff4d267fa2ef549f930be0716508355bc496c7f46371e4ad8f6d45f44589719201d5905c6fb91c246cdc3f9d459b4fa16e681be5ab16fd66e13c435c4ab95e44aee769cbe466018cf7146093bc698a9b7f221999c9c33f534f28f37dfa154d710363b036c8f3458f082af2d8faeeb86466facb4db3ae607ca46460cc9ed92f833077996167f64fe2a13919e5d621f3c5b9b8429ba1dc7b56fd1cbc2291b79e37bc5e30a3689829e164ffaacc7f407b4c39a2d4a4024cfa8844c9a01285494caf675c243e8b018d4cf3991b5bce4cf999375a0fc85d282ff637fe7f77ec0a9bdb687f7e039be6af41a675d8399d7655a1576d2194096293223e22852b8c2677cc573a6d8179c583cb6ddabc78bfc882bce6761d6d6974a0815f668918b62e617537f8dc45d48e6273ea91e1a0116604c9acecf54ebd3c00396803425c2eb837bffd1ee0fdc56a90224519246d389a6db61f7a53208b916f8321ae8248aca4d710dc8f96c62a366be0347a09a4fab5ffb64bf3a34305665fccb196b5e5d8b324e1d74326a05ea4a2e05e8b368d91518e42dfb39170a2c6f8efbfe56dfb7c57a99b40263d7756eec2e67c0c6581a4b6765540ca061e77dfe660b42faab6bedaf507dcfa864d7498a24d72a54c4be45c7263da1e21876097aacf3ab5cbf515dbf8ace4a9c17dbbd74596e2ceb6a4cf72c2df08391c9340272ee860d7e577099be3b7a781e0b2c9bcf42e3eca3b0bf557e5baf2360dbbeb96adaf93714b12018218b30f5d03dc19dba975a6803b973e1a96d1d38886228fb4f6583f636101357d966031416070b9a58c31574d5efb5e30f5e9e690dd6fb822ad6c3ad2e54262f343201d6b0d09d9aca98618ea91b4c16465fb4ed01273c5820d6808c8a13cd60b65399a94c6ce2342726779d5ba8018bdf7d92f616a1ae9abdbd69ca0057ee6c9969a063d00a7a9ba2ecd1c56560e92442b983cb569f467076a0b447d4dd047272a76cee86602c4332e1e9452b2d3548fc26b27025da7504e7726360cdf882412f7de95606edf5c475ef9fea26254667542115aa3669631b2672afb1ee2854a7ae1c839ba5fc4de25b2fee067a54e75ec749567dc0b3ed4719ab29f245be5276fcc4a9ab1c7bc7fed3837ffd43415515dd0f66a8ff09558ee8bdbe63df4ca2d7492d278cee5576c5d1a011041d7e7a1bce6fa6c0e10c51e462f2c4c717ba980d8048a14436c4ff0e98768fb8145dd14eede578cf5fe1b77dc9dc47fbe6c7c783120c4aaa07a57e25ce6a3abf74a5404faedfa8ddcebc311f6c6c834606bbc8681e6cedda8a0bb20f9e7798fee44478960c14ce18fd21edef421a512c37d8709a4ebd3cee7050007312a2b6f6165c6f0bb121a68dccc540dc69d21c22593170c4c23b71e85f23303a8c207d4ed7fc473c48a833159974521863a5f374671f47fea7b0f5387475104a05b7cfbb65ec620363a414869b4ac3453a72b04e986d3d1721de91142a3244bf2a14f0ba3b4b91d39fa272cd877b99eb745b5ffa524b50e2bb8162b0deaced444216ba0bca990399283ec76b581413fb35c23ac5630ba44ad27bb81dd1701f5222a1c8d8e2f9acdac76aaa97ba25bb7dcbfa08434ad0556ea586518b74a66fb18b68ee45364a24c6b29d140192174d062ed6cec025f8c7a5da86159fc9df5330c42ec07c5eb7d3b47ac226924cfeb7949b4857f632128adacec34852a55c18a47d267b8daf31c1550a7d92892bd9427a38914a72f45b38e4bed1bebab201460342927174ac28c00495cc2551bd95099c9185e8b48b4c686a2a177827f44485c031b78b2f037f52dc8763396ba5011172f6579ac265c712ac6116f6ed05bde9370f4c99520a8a27c8df22daafb38baf11fefae67f181889b76e3d8418e754096828af95b32a6068946987fb05a2bfe9a9da829e1db20d64a835a698ad9cdefcb82c469d9dc8d160170689e958cd5ccebe304b88b1fee392646462b6a8dc5ca8e183dd05db03c6bb3d7b29d17f7595c1c6c8d87efac8b9ab7b6c8730a3ef943a547f421be5a4dfc6ad1551ee69173fe55da597397587eb8442555d0d857ec394f01e88fd65d8ef494e7d1e68b8cfc5385786af215f779b3d9e5101b33f5e0268c9acef9bcc4fc43a33483998a1500bb671d59694a2801a25c9ca0ba3b0bf087dbab67e8a044dda40c09fb21bd4f35e6df6c1119ab0af4757edbb6eb5d3a8b3fbe992f5d827dcb789ab512ae684681eb6c976fe18fad122ed4dcae778470334a878d7fe6253f2e40aeb195d53f59fdd8ea4f84c18d4a127411342553abdce7faaf040b6cfac1637ae54c0af306eb3989ed87106ea35cc566c75df585e3e39e93c9f129ed5ec1709558888415a46a417f2d5cec7576efee91fd0dbbce0eef15f11f391e41afff1142efb316ef66945f427ec94930d341296037df06793a7c78956439a8141a73c3310649c6e35e6e4d7559357c072f81a6c325535c91766c9f13a7e308c9eda86b2e5818ea9975219efcba0ec55a7153f576a6331eb03f2e622c07fab8a2f2740c2184ba7e5320c3aaca41c3c11bb09221dd7e9678a62a6b456bcff49c2fb0365faf266224883adf71a95474739ab2609c067fb4cfb06542fdafcbd40bea8d3db4f38b80a904f653733654a501c8f1b9c5ab8071e5f714188800f3f7882d9eedffdd0ba0bc5e7649f4eadacec2d646335c013be478dbf8ba101f512cfd912f287ed7fa9232697d1abae3ef8983ae081c2a38dc6a8ee7abe6999f998927dd3c1b34c67b134b1290b6334c30a02f9792aa8ecfa2e94d87a15ef72a1effb5df1d1984f7102873b1b9930e143db5911653829302cb30df2c75670518815ac17a6d145a6f9e605d1e28987d6e01386f84e9db67767f2a513fddb5f662d8277231f414bac1f5c4c099340cb780e27fd00f6d033ce856e0c535b03654f2235b061b9b7826f49897dd2ff1c4fcdc4e36bba24af62ebff52fda3e39aeebb37e2c02a9fbbd84c958550da37fe67c3f23c27e0ef06b7aa03cae328580063a43a28fbd9075c470d2ca0ad629c0ea50a21bcd641e3582fb4affd2cf1636f7f049e8786d165720a73f4fbe420d7c93f2e041de1d608e4a42f186855843ddb863fed157ed778f2fc5855f5fd4ff27d9bb8c3677d8cd36f18794f7373965acd65dd983470a70f4b35705ecbe6dd7a5f2b1ead7e7d3103c3997b5c79f80f31bcf32bf22caeb8ebf47aa7be273b50457aadc7ea41130697047f91716df505ae96ff1bb0724aa33e47e49abeb687d242111fa605500bc34c298e59cc295aee76a7c15500a334ec5451222a4789ab73752249526014638dae49e54e1a229916a6845e2c6b22384fda247b9b76389186aba2d154269945a9cd3d7e88a98f4e523f339788fc464c9c676bc6a1bd9ec0b67f3b9be25a9657b213c31c8c6a181636f374a7deffdbc6861b96c3c9b7d17743134199baf847280f9bde25dd479d9c8cb1aac1e00cc834c7c34de54f7efb5926bd610b2485f2f2823908f5e69e43ce8bc5cf97854e93e2f41ba34d5952ee0029744c1eb03eaf150f105ecf254423a49f64369292e64e6a204d3a7f1c55aeb7114e5c7e9c0d1e3fba59c11fce619c53264d43f66a9b4e5f1c276ab480de012bac7b847a6dcb4e8409d23cd09052ef524f7b766a6c38c6e9feae6aad2447e2cb10f76132234e71a9d6ba96abaab2673d6a4bed1a36d381fd250fc514dc81ecfdd6298284b589843e0f1a321eb48dffa6db2f37cb2427fb2628a5dd4e103310e3e66e34fee5fcfe666f511017d6aecb578a2b7f90c20065b31f865f7d1ebcbc375f793dc1fb574c1efa9a66c827819259a4cac288af5f77c974b912707ceac441113277d96011148302cd89a93328c1c4ae974e8a4dfddaaef94166e16e936c5e6f196b06baa13db0e97872fd0f27652fbe2d5bf91aff97d12b11e16b102eb9ace05349e77bf27a59723e38ea15ee3a077a22c1ed2f72c6b8c5e4468c36366e45388805955eb513607ffa71e53a0fc87571bd03c416dff1eed86017dc7904b4082a6c46f4818f81b332fc8f786d636c216a62d693d91705f8868aab23be68587235ee06f823712f45031972794374e6615d7beb15e4f653260326a1a94ef77d15d2e9fab5ef93f5690f9f3ba988771d2f59e0fdb6ed1ea85d5cd440e4b964ff2b950b77e4362dc91e2fe8c99c35d5b1c4321d15a921165fb644ec92ccd783747018655527e7083d1e3057118c41ddbe0f43aca2572245e783bf8902cb3ec2ddfaaa4ea077ff82d41e1321baa5e4336f46ac63e0b2b32f0a18a941084fdb305b8d3480125fbdcaeddb5adf0279dbbd21dd899ac64eb7214d4e7dc8f2c78bb5e8521300895ce049247b51d7ce4139df85c77aad30e8983e7e130d097d564c6cb29e032ad86af70ded0f7688cd527624127e93f3fda7de6e469488a9a1f329b1ff7d754207ae8ff81e49728e87ae58b744f60e8821e3c5c3ea8e0bd0980283e34d6c443b371a20bed66e476e05841f4c73cacac010cc9c2d637c6049402806bdfc9350cf369b7143659aa761b9236cd222c518b7d1a39c8db22749f4f7d1cbf9c6795e5023c59af67405ccec91e827bec17fe82ae4dec2d649c6a0a630181b1f261236f294829902c883faa05cff4329479296d486389b2d55fe46dda6908158da018a4f04e35b3d4ba934a029b802467307a26f8f724f60b2ed2d4eeb88e625e503b0513f1afccbb3903dd5707ecc8ba42b0a37e50fcd9c4c058ca4ef45abb760caeed90c5cc1ea4eaecd09826ddda89febae6f1545800f5febee26547a2addee9626ec29b79e0b8b41472847ea45012a91eabb658617a823d97f1d5345d1ac1f27b20ae6793c03012cb69807617f247d087aaee88d998379073b20108e390034c1f34130e071a98c5bc64347f8603856da4ceab7d26db9ec2bdf7ec8a7046a7a53495387dc1e1397abca4f947e2f9237fbd52f06165bc3dd9930e4bcc00a0112b5deee3887bd5ff4362a603781ccbfcb7e20f1a41ab55be6f9112e8316bb72a0cd6a49ecaa02a7e6d98f6b2621a046b471fc5f073723a394d095b1720b6f695723259df4433a64f2577de563f53cd17e2f8dd63ceb68ba3e3a2782c253d716bbeed30face0d4103df32e40f328353b1ed4665cddc84b2b5f9266f773525fe891d29f251f4095693ab1c7bc519f18ffbef65dfa6a25c5e06a53dc56df890e4fa92e67a38b151f259699e209c878d38d06425a0947204d3ab85ef7eb955e0ddb21c4eb7cca22c250c5bde4a0925006519378d8ed47ce05cb0752e9b118b02c945aeb143cc31e1382a5a7f0a780a96de3f01b2ff4cd52638ea8f1f514fe2accf1817d436d39b5315a3dbddc727a847b2cea4476052997dee81c7c2c64acc3bd3e436cb78c73ee896b4e1b7d5272ed7149c4695d2ed2ea4fbbb54680824dba957b60ebc71db04a32d99e71e8dd575f2837e9ed1634f86775f2ae578055f2f3c319189f8de0c40373ebd4b469c4d8870e95303267fdac5cdc3144ec1044e4261b404d4881469764abed155950b5eb2e55a06c4d76a617d6e52d5c10bb2c77b23bb9ab9636a0d4c9421b495beb1c814fe1f732bbb4e3b655df929811769734acde1e600f2598d46c4f4b4ee9cbccc8c24711dbb128c5f651aab7fa0fc2d9d09f60fb2f352ed77243eb358ef8d70aa5905fa8c8dd70db271d93b052cd77d3b7eb83a578817f98e7c7d77b03171aa1f6c6b4bc34fa2463f0034b98cb2b5de1432cbfad0efd397157103be6ea31b665062f968b22f819ecfb7af8fce6f235c6b70e27ceb8c6f7f81e624aa68dda5597f099b4a7449674585f31da05090912468a6e6b12a905c8671b3be14b37bdf1f487d98aaad73c6df2783b5c498813402cb76d4bdf26a55eb32aae382fe6afa367bdf815eadef1662e1847f5d9c23c208ac884f808e58c9ec21ebc2c47acda8eaffe83fac9d41f7fb7db825500c8914edcf0afa70f09503379dc35bed6dc21c10a70d1e1226f9f02997b836780e0546f5dbaa8d0a6af76dba1f8e3a8af6845f0393b27dab624ef1b5899883df727755d3e922b3be3b4b0d2c79be1be525d70e2c6ec500bb7d0b8506d26dde52a8c85248a40a7e328ffdef09bd23e7c06d16abfca6d74dcd19b085eb7738c12feba16290dfb8075468cd59966929d57a509fd736dbda2afc5074f4da2a4fdbc05cff0f2d1ce7f6123af514c43226b3c2da7b84df8fe71293557d670b94a5e3ad61b8648dc4d3ff1f74eb18658f03e77f58d7a174e9c2dba286786265670e3232350cc08d977f56d37e216f916c2cf9853e0518c653a434c4e9522269ad9e96586106590f4e4103c491d32a6059fbbd309d246cfa0807ae0387d67e6df3149f55e6f5eb3e46027598a98ab90986ebbf11ee942d6b507c1696c50f350c702b192cc03f31b2fe029a1d0bb45370aa4113a94932341d5e5b7b4adf0b269311170a12e6537ddf162f80472ef26732c7623d754579c77bff70589e7a1a8580f872c57f512c5a1747432051113a408ad6320cb372751df0bb2cb7ad06d3f7eeaeecf6d3f08d4176ee06ccd09da8f24b5ea943171d253a93805a2b7f66019f1622d709f399c4363b02f90a9c22028a3ebf6e1ac7f5d0f7af852db0a028f7ca78d8d9c018b9bf6014adc41608c45d968dadaf87c40890caefaf8b8c2eee0aa08976299ef0406a6bfd788c4f33a4067bf5d0c7d0e98bd8c6d448e5aa3bfb33c15e29a4221a48972ee25ef2992da43c62d80e2171435f92598b21a25898dd2f6209e0c3a16e606b9e2656d49cc9296dfe1f68519e27267995b910b7d6c519a984282fc6c277d68abd77af1e8129c2b3d39c5855fb5de00adbd0028030f19e6a88a6263455f7d6de4a7081763dbddb3bb8cfeac476474fb58a44599320ae47426a05acf8374e4a0c72fe8946212edf3a5f33df97ae3b88f057e83fbfca1441306da76a56aa33e7c528ca62122a25840b10c2232352aef50d53d8a7f6e042b7c9cdb63626436a045522283cf67a90459e801c594ad505ce0073b7d70c8d9f1266332064d902fa60c382a118a15940cda52b900d6e1e829aff39faa0334db9302be67a9f7c2db995504fd8751ee240c552fc4ea58560850edb21cd31cbc3c6f9878f691b5a1a39375c44dc3002cff05056ff643b992c1fc4ea9683d6c2c92555e9878534d63c7ec1e082163468e7062fc3da16606922209d6e4013a829b8416b2b83b2149785f5144934f9171179345f67adf5a6663089c52dff44986157ae2f6c5f74a4bf5a2f6345883ddea3733233646f7ea7992fb8f50cb297bfb59d977de926676bc4d9a2e1275ca2bee23368523f5efc1de6099d73116a91e715889564f139dde58dcdbb514dec95dc8a0e6c8c0fec508b6ccc3eb17f8fa340788a50a159368c9fa694c38e7fc0100ac60367fc936be9cc37b56f898217254ba5d30d515989ac5d4d02ee10dd4e29b35329efd4e1457df0112bd4da733d07a53b4eef92a0196ab6ed14de66b4263f5470649385a17d955caf61abd8d52a688f701a44e827a2f833e98cf5340113c679243eeda86e4b70bdb8d638af853889718ef838536a0c0bdef537eafa83b11bf85fa804119a5b81ee90ceff5c27b6278a056fbe50dde0287571c957b6ec05bd8c3a6e18e4ff9b7ef2057082f46f0a896595f61743dbd4a25195f6aa5059f6238b863a7729a7a12eb6e1c988be48eccb9f2889b5f0d462eff93e8846990911a311b291782b2f2e2f1ac92772ade25adcd7476b9f69dac508e8ced2e81e06cae4c41e3ee5b3bb0560ef4ddab9044470bf0d345b42acfc095d6c5ab6324e55061b602f786050fac44f2116f49c13152a4841f20e56a7af1dd5fb4a19b36db78806ddd4667cf03b34e0a077fd995f9cd80b46297f957fcf9ec8bd9747df8b66442971bfcfff4282ddd0aa4c33329e01ac9fb8ee27e99b9ef7e273b20cecf3af4c1ec0e13617039eef63c1909b10b63b077ee71135cde0cf46f18c46476531059656f7b47a42c6ca11288444350718206a7f8b8b0714c647a6ef153740aa88c6da896b5d8d1e72d720653a6bf7006e8db1f2311c704c93c2448f9e58521dae758980dae6ef3f70ab6b0247cf6d216695982f97f2ef65f9cc4734c6415da4281eab1aff0c796012389318a621dc5da525133a506dc70eb6594799f7dcb8077925dd5eb916d37b8212bea8027bad5e678d92dec816e7519c2f019f31b0610d034ef058a260af98a57e8e7ee9bc8a178092616ae48155bfb636e6d9792761649fdfafaf6d71ac572bdfd28b6861478737fa45bb4051d1175afd81d6a20fd1a0e44f4dcf317dd05c29636e6397244dc1fbbdc6d55a65760b0b42375cae510542dca0a4a32057f973ef61cc90a04382f77483c8dbf157de58dec6ba0faedcb98842b04a57ac360180cda976a694dbd0d77d242497b7f85ae8c9e81b559154d4b3dec071b6b5fc3b6636eef187320d564fa7d952d24dbea1e6d07570ba12e22ae79812b5781df35b2c6fff9a1ca6b76ec089598e0c8ebf6192b960f0b401fc14c85cf22b6124f6d0980577c1c5ddf4e57bf215c89f497e1bcf2f716c803d56694e3dce4270b5f859ad8e4448bba833a1f1059a6904c24cbcfd45b164f136d43c989c661c8d5548ab4f89d6e27c8f003860140af16bd366301721a415e490603efbd1cf8973814504346013bbbac41889037679d5deff4b77df14871f6ab1fb1d0e86cd44c3c37aa6207ff457e600740198f692b615c0258003453a8018318659edea5858058cb49036a2441a7856507c1e26a0d76dbae2444f9f2496cc360dbc24c5ed057065d71ed0bc8ec171327d4e7a1d7fc186e206ffe647bfc7c512f6d4141dfe5c5501f43fed3d586dc5e66368d1846a8716ca795c5d0eb673926b02fc7529e9fa2df1c118707aba963c9167ed6d4d15158d9525ada2b3e9896defe94ba6d09e6aeb0dce42de693600e49c8d611c2a04902ae6385e1e118ec4c085bca351202182ff085e8bfb01e2bbdefd1ff43facaee8f37d9b279c30d4fed214af7fa3b3c035f5ed406083a9e12d42f4c062f40ee76fec999f29b598e567e9aa105daf5bfefd5c373587ba2215b543f385da747caa866a8a10cde78db98c7f6438c650a8518c15a5b233fa808774584c4c1db2496e6f5aa46b32de169be4f6cd4d3054e9057ef94f516a6d1d4614dd90f82beac83b31ae0ba44df2834cd3786868d655ae45e40784242dac678707cdb40f1734c19a84063b31adbad1a549847d19afdb2e09355206e77f326c47c9c52f1f644de7526c11ad3eb3e49fedc3fb3f805c34760e3a0c5d6f1bdec1bf95697e95cff96e9228a33f647d0869d0688916e09b9e24228c708745d5a7f14881c7a4544e73be0869e896aa1e0a6584f0dee6753a3d33fa5f35b3c6515ab0e8f4bae0766806fa15aedd7087896760091ca56384fd313f7114223af355639bdd7af2113416c5d6d375917e2c970e5d20a116b32f67ece68081018a4c9437fbb5c29a852e89da04a78f45018c561ff8becf1ce09582333a65b67408e7034d25d142b5b28d23cbba4f9e30323808f159e7ddf7cd89361a3568aaa065ef07e35455b9f89ac3abb540121ff8b0ea65169eaeeccf41416bc2ff0dc79cdad7de66f6e8c6f929c79cbce75b32d745300a112be41e3a7269e2a4998a26fcb9500490c9dd3070c5fccbd06feef5858271f3735b97a1c71cbc4c2932a698dfcedbf4bd9702e3ae7c04a3a8bf77358220a4cbfd25d74eafc3bb10d2c2bf619e90b9131d5387b9b321c352b1cbaf0bca97b9f9fa1e3c8605824cd5b8f89c2dd846d1abf01b070a40b83582e1abb536e5a431ed9f85eabb8d397cb8be4f4f54fa77e88a761565fc107dd7f981733b8467d5b4bcb4086ac8c3cb81e4ed9a79ee6d3149b9a5300478cc7c7c3f5c0466f77b566d3c2589f24b25dac9dabe776d35aa5c06b29277abdc0766e68081cdca418b289017a2fbe312474fd5d11d356bcc3614b85592e634898702ac9d40715545df397d695fb55b89bffb3c795cc3ef425d29e955997df413f32fadcbcffcc0bdb3742cc8cdc4d3912ab2d7ef5a0c24d631a131cbd16a8f8540ffb589c83aaf27c96ed474ca861d5679aa480d5d983836b8758873ceec61f9c508d59bc4865d3cfbb0dbda6a7040280f35de09e03d600e1c9196c9b2055c148ec4814ad0c20bf55828da251541797514d716b4a3d8b9c4e7d7efc3e566c9755683088b7979a242f4f6e5d547eb05b9fdd0d0d6b11a191c507bc0c234e815bbbdfac2242e8e87c474768b2cfa6762e23e154052833be388842ab4b91ffc5e31d6c84066d4c47dff76767744d7a1971ef588f11d225670aa73932c9996c053fd5ce5113861f54b50ee19e494612122cd1217e84dd0c1b81eaabfa02ad971bc04a23240c258049a02342500526cc76fbed1e02ab7f1cbd16c422384673135d900254afa694ca6bca6d01e187f25bb1369c466c6935b527c2056c8ca2abb3f29f48bbe35c92ef80be8e6c170a354b69a5ee21497984e6bf78cffcaf366bf1c92b0f3f0fa4a76ff1384cc6507cc9ff22e260a0e81ac9a6f43256dc4ef036b0d6b2f9b08624c8e2343fb4df3f989fb85ac7a77d6bb9d213f1f7914560617c3d5c499e203cfc31224e03c30b15aca1c6590e1e71ce18d68efd6d0a5d6f8ae6cc1b00dfdf01a60054b911c364c4947b86910a9718bab4530b4e780200905fe40ed951e06a43db11ff8cc5e442b5e40166fb7734df0715765975a7b29134fcb7f513809f349fcc0d07b3217b3346d551eaa7ecd5f7538a0232c287ebeddd874491101d049919ee7eaabce85d90bd1353998f3332d2b7257f77f3ddd913053650cb23f5c37678d89904d1fa3ad1ad41c6b541b3b577532d981ce794c7fdf2c851b1ed2d6178d08f8b5d55a2f2ec9835c355350d8259a9074106e89040f8ada5d37364c1b3eac3c28ee0b64e142cd307288f9c6e6fdd709e82b47d123d83bc7aca0f087fee30bb1d59285b02cb4124e1f99fd334ff8817f0f98e66c3d6a9f4fc326bfa0ba850374f9be5261d9dab510d60e44764c38d0cdcff076e9566fa67b419ef54b4ce97def8105850de9737b36cba8bf3c1f20c9693a779741e3288a1f1e80bbc56c1a0db74650eaf8a8c56c16982d4180531a72a17c618174d50aa215d72e43f1e9e865cf29a562c95cf123fea23a7306a9223588b8b74788fd1500bdf0c2e268e0d149cfe76a1e7b83fcf41d8221fb8344d11c3a3f7a1043f57c846977d4d5a2c3309d7f83daf05b2edb9c791e08630e137ce7284552ecdc460e57173f1a1488e09b48b238734d94584bdee402db58c5146081ebc1cc199a376f858cc74ff637f7a36031b443e478ab58e4ce825a662ede010e3f96ce13586d0bdbd624daee8d1b2e829a11868ee85f29e137b32ab1121ad25ad51aaa2ce8bd60a40f8b62d0d9f901027940006e940ae2fca65076a9839753feed36544d7addb9a2d1acf02813782d819cfe7cdceb2c59df9edba20a7459b7151e9e745d45fa8f7a897b2fcc9406eb722faf8db4a5079ab55d8fe4e19759a07f80971e401ebf970eeac6c1e5c9d79483e2b3843c1c1f3c7f3168fbcaedebd3cd31b60e0dabffaba28f49ccb2f159c0410e26ac0e4e32fde7e06eaac1725a7496795a5989ba41e9b2361bb904581d6792947e276d6c965eaa7212aeadd2dc825e35c154618911d31db3c20a5dbfd2be74a915eadf0ecfa6b245dcb394bef10af57974065436143a87d1f0d2bf2fb0e0fd6cb39c2fe086735d1e9c0a2d31cf54c2eca233f57c00ef0eadc48dd512bc959e144a355a64c30627446a732907861845367df7a8f29308229028f9da5195844f42ba2dfc7d6b664715416903a1ee2bd6ff800eb561bb62a5a5b852e9d7bccb3cbf722cd1746c62050e805ea7c2bab22a88e0e738b8090d922f1b7bad3be83730dedc5c5a042f1a552371660b826da3a4f3fa7a6f07e8e7ff99f406c3d9cf2ab8b6be9749e94b00142feabc58df3460ecdaa573ad196bdfbbbccd5c2d98e7d0737294d658d77ba8b4dbc6abc295a3cbbfd863eba26371af282a269f5d258c60ea719e1eab91fdc6779cee9d49ad128f898e77c523bbb222491a68f3729f6dcc1aeb77c4d0d719526a74fc27ac5df5d6f99e891cb65a006de9108118cf90e2d469f0a20bc9db511fb97f1e702c8b5495e4227d6053a84b52bae21b94f9c50245584d09a42d00754ecc8dfd7e1d84f2a9030bcf06576bc3975466c0cf660d3f10fe84e710fd93f26df09b8c79d0754f24a1541606a3419ee970459f6b6419c9022eb4a083991776c7dbe86f6a120fd1be4917791770fd3a36c58ccb36ee270ebf48f5c340fc02b388f750c853f94f821192b5c50f1932dd7644c536f6eab0c38a1ab35ca5bfa7cb64c44fd05e289841dee1a32b278ed0bfbdaf994261d86ba77feb8c4fd8e7ae16fddf7fbb84ddcc0e4f9a1eb0630c4cfd7132fae5f0c6323aa3c6aa7713b9a4f609a0b1b5385ebc2c0da0e51c76ecfb6f5cbe65f3a3513380d0595104871c2c32eade7ba66fe6c014db25d239c3e0abd15b1cec1bbd1c409ef98219fbb77a8464225463618457c390c1b35d1a84ddc10826ab85d5ce72da6dd494d61cda4ab8eec00233c1ed802d880a67ba06ee9eec0db971401d2bb9af5a284df4be739bc5bc7dac16f4ccadeeb9cafd8d8b3573e968216d14a59fdce5c606fea123dfeb9248f0329288f84b0a273994647b0dd2925424baf207436e5b7414e058f1590c63c2b96431231cfaff4243b0963ac97f83f756a0250913c324ba6519260c35503c420331bea6f95a592c24d25bcd4d79ab90cbec3192cd14fb29097879acd5b6d91c4f7f8081f092c9628c93e749fbd456fca42639d01a4ba1c962f2d98b5c059da2cfe0fab0fad3222a6234aad470c9123498ab299b9d360e0d7580394fd9e97e8cc2077cbc73b3adcd3232cf48b0e2ab721156d4df27d99c6f6f7164b4acdabf6470486f8c44528fc42e3d3ca0dc376ab2bfad2dfd32c9e48850b240ea300056f870dae989d0a4cca68bcb202139484fd27f8bb75d1bb3f86c9173bb2191234d982e5c7c2bc1189856a010a6db03fc8e7fe25326390e7e23be4e350e84b8b9e6de054f74112faa391129de4e183e04aade0e7b0cab791d144578b058ddc559029cf7bdc530e20c9d5cc36c65e3c39f6de31a1229f6fa8741e6c088f8d69a7e0667d38e2d4cfd1928b071457d913abb703c76f38810676a5347146857df9b91d801fd27558f7c58cfa27bb0abbf81b3dd0183f790670d81a3192d763c2735166080c3c9e64de47a4c737c4ca3bc1ba2084ee7dbf985d2430705c5cf814e11bd1931784ec2fb0924bae4bc17be6497ac330dadf930841e202a4a346462c3de6cbbf319d712845b398b63479cdbafdc829207b1c2b2a256d06d801c9fd7b465dc250d395c9f2b95f13bc94cc41b8c1b57cf1919ad8d7376472e5c103aac55e0ae17bde43b8c9aeab0580bc4ad03565d55dfd26e7f03f87c214a0dbe4c6e11e3a5b34d79939e5908a6c949955b156408e94b71905c1aa6277dc1e9cefe28a3410dbf1d51c53c62c6781261162be88d1326ef90e6c5677dfa8dbdf9362c366343549ec76383d2927da7b6a2b9d95f1698140a177b82997c4207e0045a8e78ef20a41ede30bcacdc4ee2839c0bb64917ad91c46dda5acac6ba49ff78a25be8340a5f0440a8e3e12754e24a2f8c51c574b5f27372f70912fd8df1c0ad8ca3eec150fb90cd31423bde8ae573c9700f71f83d6f0aaf231bedfabd73270f8bb34ebb62a33234701264d64f3bb016892a138f312ade01f83054bd050759c65311614a8b4bff0c9882882079cd2a76e71f663fb835c040d4fa71f01dca052c5fa7f452dec1540fedf601744ab614dbae7fd97a46a1b0d842327516e8fe72be94c8ff998e6006db5e49142032a6a75d363a5c4624abeb7e4a13f3662aa962b4e49503401f00ba5d6c6e53d60ddd3d17cee063ceb7c8141e3f32d4d36ff6934ad66b90f71fe40b8585163bbbbbebcf75b55ae95bb16d31e2bea18114fdf5d51cf9c7ad87d40837ab129d6a81e77f0b79cf263302942c0f0caf6409680f0b08a28f09fa72f0e567eef9ebb3609938a30b66df2341e59e1da25e0641ca3f8082eed327abf10b3c4ecb6f47bd0137e0f4da0ccae923dee78d36e791b2a3818686ef962bef2f63e2028e9b86e5f37b1e6d36e9d8b9aedf50f63b98f6a639918b51e46876bf4801e080c931febb882290926f07a9fb2748e8394ac5d0523d57a698a3d6caad35d09bc148619744ba9b7125cb3b83163151c6dd31c51e89c1175d41ae5a50991ab77cdff5087f6cb64d97e6c3a4ea412759121d6dd52845bf6612649ffbb44e9eb1eb9c62297cbfb1ed71c3c733f1995f1289bfaa2b62cb4d54184c304c0019a02fb0517f0e05d96fbd35348d3a213dbf819f42abca8dda3a882b9eb0b87ed0d4580f926cda8df24bbdada7d68379fba8984f7dee4ecd5247725b633d3686f8bc8fcdc48190bb66f078757c336c75e8876cc22cc66ddbd7e289a148cd7c68a12413022de8a7957757b441b3006678da5d7349f139eb3b0ddafdceedde8ce32f18a0694597c1074dbe75a87276b606f988d1d32b409f71364c7ffb81109503c5ae3f8ebff444c766d710dc6b4dc560d564f76bfb6b9de87391f4f9fb734dd63810d390037a2341b7415f75fd830da9fff4c275d68feb510a1896a9df0d019ff58a3ecc25bfc14e66617a4210ce7522bd7590fdf92fd985c186e42442f6c5475ccecf2adf177b86f7377293adf8c3886f99b68e73e24fcbe35dfee26f91f3b3e215d36a9c1f899129a62893d68b4a1240a9f2e9bddac0e778624f7997733d48b705e70fa980e1ff3aaadc460aa9eec07ea00844414bd1aa7ad6885ed4c1a459ba8c50d798d840a8003e215d77b785284d791800a6b53c956e52cc3c415c4ce6fbd32e8bdfc8b1c41e3eb467d3bc4371e0bac3dca135414aa1a47c458994ea8310cdf89b951a0e9f5475a38b7fc402d8a1c9f654035067b1d79a52e5ebcac9d337b2e10eeb8c7528abbc19a774b67db22ba03d94af1fbbbf6b93d97c0fa87222c3a2f84d74e84546cb410d5f3b4f88c7f8e0696ad303938e6ec6997624276600d2af67178681880bc5d2ba03a1e50f84e3e3ccbe5a276d868e0022b3907ee3c165cacb3555fb386ae27608c59879622e50d6f8bec64c5184d0e19ebc441f5522368921d26176620ccf6b7cd7a0ea55789fbb02ded7bce41299bd5b82e0572f6f5ba56983328d510146bbca48975432fcebcd31fdefd4178ac85c17b601a7f9fe68f28d11ec8c678cb1d156a2a3b414609ecb4d0c2ecf31cb013095f7b0fbd91027a229a6ec027a3c57d7b6ae9e2cde1b40da05e89ea0f1359e248abe0474b72b28c020c1dd165acac72d989c4e06169b46a3748f844c16838a4b3c364dc2291e5d0a10f5c9b7713eb0c1a31cf546d5c05f195a23313d350088cf2db184a63662d8050b32f04dfa37f4488fdb819630ebcbebb9ba8bf593e364767d9da0a89d1b13f69aae7aec7dc35f9f5be13a92f9e67cdb56b4d2150d9be2f2d03ce3a4aa747352f3f2d3edc629f9df73212762b6767d5a1d49ab1e1aa5e268d99df7cd634cad9f86c362c80c7fb5038dd2f822596c4930e96204189b64def4e76bb08fb105c4f9c920318b6d9f93fa404785724e11a3a64475ae47c801468abd1543a42ecef17f2a852bdce66aeb0fe1fa51c5386449893a7541f4dc70e955dcac0fdedf4c13716682e836c56582d65dc993e7669ca5350c56d04ee99188cf57207d593fc5b9ebbec04dd2452b4e7106529a92c5482aac67fa4aa9f8cd6516795660184756c3eb139f22a4580f45168b415a8ef2ab85482f51270d0c6f82c2038286125554116358ab69dfd913ba943b3a1f518ec207e072f4bfc3486f909e002bf70d7148fe4fe6228a2b57bae9634a2c06e7f29558c27dc6eb3de3d0c52f0687322a132b6fb5a099f8b0cffdb8d7016a9bb20a76ce8aa516f954cc5c357ee1064d5ae5327a85aace91848bfa7646ee15c8d80e92b73c3d324a8020d1b15e3fedcb887cb74c059c58912442f552ced4fdf7a758cf9611a89ac2e99ea7125bceaf5b8d09f14cbadac36b4e3d36d0285ab0b04c189e1cd9c309777610daa788011f01fd25df23db712a79e0fe3a2c32a01530d7af19fc436527cd3e1821aa874a029f0e9285a894d4e6c471a61133b11ff0f60668d8325c6d2e315c8a9bd05c2c38bb89475dd530a49d2bbb9e3c6176f7f48c681b2b654ce0a63d0999ad07b355d229772c18cd357c46ee4cab44564d2d49a877606dfdc960182bc1ee748b306c3f4cc0d5f30de17d697eca0d629da81018f7bb2df119bece56741d44f5df3bef3350ac6891777db9b6684647c3c998c2e078caef9e0e50670311e0f2f7125d42493653a0de7995f8493b49313fbce581b211049275e07f9f7ea9e134ab0d48e16cf6a00b51b84a11a461988773a29f86a22b62d830c01723adcba99559dccc9c9a38ce74576e6fcbf42954a99f9c6da9c9f50a7ba5e0d7c48eeae965dbcbcfec28b439ed36a26a7dc59d5191d0790f1d6143342a448c57563ab2e25bd117ca2deda73f9b2409cecee2197924b9263bbd1a0c1f45a07538fd4ec7f76524843034e050e58b392b995f83199d34d8c36b4712eabfd0829a9cc43a7e85ab08603c8184d112e8cd975a0c25b20630604b20f7c7fbea720f781ae29b8001658475e0e1bbab38a1b018adcea4e35dc129caec2fedb0767d7238741c036c698f520dd2237a798ebf22441cbc64dcadae004f895c71bb59ea308a9db1baab51eefa1d8a00bc1e3e6f7a9723e3b74845e5bf00e454e6e2b2739fca9b9eb5234f0a51a7a87288cb06af6281fa21b8c2666733383abe17036455e88d10b22d03898cb4c1ac0f233307976c27785cd7bf9a64610a977f10edfc751234b7ca0d16649f8ed60a16e792c4ab8c8c9baa0dba8274fe8323ebc72f1a58abab058676e999fa382c2263c2fe8cc614c572a113f53d0b717cabcce66c3363e33f1b7a69c869e8a86fc3d1ced7f05861272dc7c18555e41ced7e96246fdd8ba7ea760f9cbaf5fbd5d955669eca1e8ebdccb5af5199ba94fda9f72c008cae3b022af91456847a30946c64733842b79da67b0fc66a492179c1c17a21960f3011aa52423e5d366f96196b358ab388bd773d7b3b2a232f9f05f5c9cad722030985597113f83722d6df0288768b7a2903aeec9a2d0b37b399bb2d8f4f76d9012ed79dfae7d90ecc95cbb95f49224d1c8464b85aa09bb544c255fb2968639a3602c150c31e2f2a3a1ec13d132bbd801c9a488403a98da1810adb0107ca1fa9569236fa86c109ca2512be45fcf89899d43e11db8845aaffc5aea475e78837adba663cc59992cf9b3017411976f9fc2f50ab06bbb0aca75e8aa88acb03aa95a58bdf801a50672bb3c8a26bd355f58da9f3a597e1f27f3cfc61edabd8faa7367e4995773a224ec086462a1cf8ed336451981671b2f5e386df7210ba377cd2941da75c6da7f286db61224f7f4dd244cb141db4900420add2526da1f0f7219b84fd575f87cb6391b71fe834573ca40d76a1d10fbffd938b13246fc31dc449076ce22bf169c325755c3047e776b491fa74e751de712de819cdcadc9a22d84dd7b59c8314b0db521475a174f20634a9a9643340408b21fb9fa2cef920b89b35ff6eb0657a2c1b7fa64536a1ef1d86794bdbfbeab36e5082db11c7b07b6102ab1bc31bf02f2155c3ba74ff191fc08bce178a79f9cef3759167a4598c2eeb28b21c450b6ec170f008b7dfa99873d498827263e6277d61bcb96b4f12bb6950eb9ceb964b4173d0351f08f2e1a86d2d83527a32fc6ab81662d13e9ed8b656828f1aef6a74c00b5667a68c84307530f64f9df5983d2fbddf5eaa5018f4a9dfb6c066c92df5956b8a09c58e48c1338db7cb83a8b5cf1a6ff20d580756ac930d29b63e64c06c15144644519ac8c853d52344e654c76e873c2e002494528568c2d7c7c4c2aeae2691a137ee6493c0b00488ad57316028469802094fb6dfe63a2ff677f066649ad51887adf6e6135fc9c06ed87d48e705176e6a15cdd8320166bbff6cceb2ea9470b661f560f529e4d4c008f99c8c634ab1c72cea9e959e05ab999d89a080749bff5dc92f037653427dec8ee365fb8271ce21faf3919ab49a55083f98d6e5aaa5b64cdf6228a52ecbf1a2061c549aeb864dc8e24515e19416912ecaff30d23d5dd801a47b4f302d0461e005b57724bcfc99ddaabcf51d2b7d88fbf2e1066b50241f8fe22983a5e2c50da0ab087d9e93f7dc5dd6dd1bb9bcee686bab3f6981bb1aa6c37ee8ecc2f8153c85b0ae31ea541122e71f3a4aab36f1ff594ed8765fde2fad7c982819ea79b1263fd38ee460650c20216508332a2af2cb9d6812dd16a72e7f1daea0361dc43d4ccae5cde675800849a7e91ca09625a7540d4cb4fdfbdd3f86a2f568977adfc05b13719fdeaba9c673187974e390eb05fdd7f6e7f61cdbc71da78ae1881807c2201be001ec176a219c90c90da7558d84e7ea225b9b5b393ccaa301c5ea4ac12454ef29d1d9c3516f867d3c30d75d9c6022a44b9c2b663f162290c29c149bb0e2768e16825ca08f902d3770602223cec1a39b3853059d53ad88ca448aa5c06ff6ee28a4dcc2ea44e562e114f2163f99c81a9d21c99e5bc0e34fd2a0e93ac618ce00ae9a0daaa3a7059c02924a911a2086b20e2b6119dad70b43c526650af0603a73a481f4282fa4219c73638dd04d858f3878b96365a8fb57b0bea13b0528d20c23667e1a603453750dddd31cbb0137523470b891ae9a4a226aef76fa0d9ed8f77cf3a319a7e89f6f0bc7803943c0ba5208cf4fe2ba405159652973a827e0e7b52bcc5fb7c521bb7862da1248d95a611339239b1a5d83951bfcb1c63d012ef6af6d8d9991749bb0b8b75cc9e31ae5d33d01b7723800b5e05d57ee4678fa8cb4afbb1c1d2131e3d2372e0325a5f438ee38c69844c10132ae76cf3d2dd75d7fc4a3f6dfc3dc36dd8abdf2c918a38aa9cffb0221cf6bad08a237d4485125d879491205952af94a4741e7390ffc95e13d1694cd0c50b35d60136d087c991ffe21c167377eca71e75db0fe460e44da609a1aa1d62f4622ffde6f4167a012fe0d557e4928f3b10213fc6e63f753020c38889d03559757a3aa54fcbc7153372ecffb650ea0dbd7edc6be580f1e5f1142689ce2c1e29e92733aac31c75b68dfb0dba333ba225f33e483a4ba4e2b77db44159b9e214037a4d932c4e0dae27ca4f5164ae33b11e8b37b17ea078e58ff09e5a99cdcedd703ff653c954b9e3abdccd2e34978587cb13cd7a11da1e793c7b0e061fcd7777055893a1435b51334ea9883d767cc0d3fd8849378e4010dbf148b1786f0c473d479d69e06933d235d7165836210fced84c2c0e6b81f4e76d8bc8c4becb275f2fed6e6b2e861a279ca4ffb29cbe824f2a6c22a64dbaddc49a276bfe171bfb4afb9394443fe8ecee7260b087d1edfd3e8b086bbe8d3359f4b697e1ec298ed09ae93f6d9a483f6985d70ba381946c650ff8e7b30651457a47aab96bec6e198fccf303212cf80071634cb8066a028cb8b65c78f4cb1a9b57aab3d52622ce3a952270bf6b7030d34a1b319a1a5bdec1e16fce895db47072ad6ab8a2fb1e797df332261177a81abd41cd1a52862a480d04cac1cd422e5032480a2fe13e1acfc3b098fd0de48782908cca7247d05a6a9610bc8c7a02f698b903375b5a40252bd20f9fc3373a801ff49b5d7f385bbda0d039e8d68b5a15573ff807a436ca97b2cd57da5389174b90c90e14812bf592d742bc9dfe4fb1332900237bbfa88d3f6e884279fca058f3267c973d35cca3adf93725fa1cf373be2bce85a64c2e3fc896d81d3c08f2c19535f3429b0f7da4fd80be6903d3bb42dd69a0e037aa23b68f6f4747028c97cf9f0cfab45ae634d8214201e842876953eac646172ac0a13f0bbd59cc6be5cdf63830baa1c0196c6efcd631f071ee43f332599f0d43eca24dd63de7f2d73af0b5d8df4b04af14f40a7ac8eac955c4ee7e0b52558253df013d9561562a4e18246aeb62fefef0a6311f2361cc14762eb914a42c3fdcec877bf8fc853f32095d520d1e42c487a3b4ea3162e7aefd3344b2d61a7844b09805cf29a07475d40fc231a123608ea8fd5f63563ce8aee096b9dd89f5873f5c39476880e2a19f67bcca8ee66c955f3ff1e9ff890907f2888d40b1d8d6db192293e481a1f98a56e9b94576f6d453a04d00374cbe53528653e53a2646cb92889cac758d5a9e08cbab3d2b658e0d9a675b66a671eed4c40b1218ce3e9e46e4edecad2870007a2b52a21d285990beab40cb1c0c29070cb1c936c0c60b3e5896fd064379b61b62153058b536be022049d51bd37e5d180de60733f766f439bdca4c6549307367db99e18f0a31b0362dd46b89dd2e8855a19d875c255f1afad3f76e010560657749ea079b8affff6df7f35e71771676bff668a0dbca9b5e2b8cb515edef879fc964efba96bf92667816e12f065d67ef9686c5c9fffd65a1561d0fefc355768a0a98bad24dccb7626ab2891cb0f38c2a644b53ccdef00545475e5d308949e9d38cd18f6406b3f664f69210f9dee41466a87151d0001b314f64a8876e5d7a248dd1a65113c54a3281e7483933b4a7e027536637da80ac74429663d698ee52a8893167e1ec72e295225ad0fc734b36e5e4f1248a294cc360b60404d67aaa74563ca2a4a2703c96058991e52fd8a3b9669d1adb6df7d7b549acea253062efa14dfb65dd3c2ad4f68054c9523a3b9b8af71549fff2018ab3146fc71e0b17fc9c2e3ba6ab9edee4541692e3176ac6e834f9ef778ab8779480b764c7cdf9656ffb64a58017d2a61aeba8b0c29d8ea10f1a1c5e3a5d83287fc2b36fa982ddd8a480428ab3e54ea5fc115e900203448e28ba471859255188b3bc06dabbd472ca8c65770f15b1918efd0c894910fc1a20771965035be2d389a408b029be98d0b45ac08a1ac85dce5c788b9bca2ebfb99b7886961dadd09de1863285e5c670e674adbe949258970f14c615963fe3860e6d5eee0737af147f2f2dd20516d211270e0319b2c5c8ffefdf6fb6e21f9a63cefcbe586310ef976d700067a1e685dc619304b688d145fee7d96d11fec92a39ec25aa748d771c56cf7065f39435ac97f1b380303bb2f5d7fe00c5ec95f08895fd5eebf4dd35205aa9681fe058967139bb600ca10e87674eb0786b31a1212324cd2588b3f66c35fce30e07d825255211679d1ac38760396dc27c10837a86f9b9aad3277a4876476ec98c9db39e95165e5e869a32998e7e52659c2f9e450ad56025a315fb2ce9545ae775fd0a7b4d14c55097efdb529cc87aa4bd03b4c73972f80f1d6b4e862f1fed188c223a443dd13a79b9664d2c5a750a7c14fb6b24fcaf6c7055b9090452e4185a720c5541220f7be24754aebd6e13e66b22eb824f8587d787de0f8ef21e6dc0298aa738a3ca8e350d0cb12faec6f0b82d76cd1b5329e824e1592f4da4b6a338c585c4ad2974b3f88e8c5169da29288f019702e233c17ceaffd8311f23c13b378ecf2019db0ff2dfeac4b2a67a6bd527c2df6423d3d49a25c405bbbd8fd24d4d243bb64b26337573d625699021f29fc209c816bf1fb7f684c5585af17dc4d6f088b37d108f405f1472efe104a802760433369dd3bb76ce21fba130de931b0540f97d9de3a65e98b72f9034fe5c7be64b2a1ec5d3a586cb6f85132f24b4af548f3bb4ededc236f284c6af6bbd9648d5b36659f5f41abbaa6a59da78e16559c20553fd30f00ae3fd7800a5b1c5cec543dc809ef97bcfd5766ac8581cba1c3c0e5855795041cee87f33053031a724f1adb63561999c314e8effe61b481e7dda4fe800058aa28a57bf0e14e5c1752383632e2877303336516464d044d8defe349e79f8954bcf18fa96ca5cc921fe0551743b363334e219f85a89a49b63dfca255902ff1aea0b9450e29b977b03a9d6eeb0971b13ebe64ee2ae31a6ab21eb97aebbec2460427ed3ad9fcb4a1c8f85f939f1ac4443e2d4cb1d93350253631aa7a6dce7f54c8e467507e8c52f3695c5edb0fe42d3e37b35d4499f8b394289b9792d28925c04c6d342ba3532e09e459e4d59244a60960dbed2f0adf9d4726bc66e36e6d2e0b25d82bc7d7e5f06b001cb3d3f2ee47f5cba9c8d3b0e4b4f2fef4aeb14b49168dd22235ff4770915ff8616fe5d3188e041acf975759d64c0404826325f5b9186ac3a91f59dcca8c94b15a7a7c885f8a215db976f869a394999fbc7dd728524032cbd1fcf37572611463623cc1f27b770b30c4640b374eb0dd6ce65ea619b6068647cac465a55e237b29b85c536e2f3c2a7b9c18095ec18a51289207ed4287fce3c0b608d352f905813b53a34721e231d02a6621b834466f4873edf30ab79e3e772dc1022ef9da6259859bf3db1d26046f486d8d82eab62773434e405b246cadfbb40e9f089dbee806c5615fb9847bde5c654d0b62ab3061c83f8fd03aca9344719bcec38216697998af90199217575b8dd66bc2bad50330c65ec15a0c6a7db06f47ac471d86d90d907158f6bd7b4bdf2c5a01f6a739af491a61421fdb7c7e252324b423c49936d6023a042f5c23dd0fe630fe8046cf6c7b9089d69f9906b238801aa8d96edd90d0ab29c1b3b2433f856dc81c8320e2f3f1006408a772a73d0adecd49c085e3727e2992636402db93ef542cc8b52eac829fa178aecd065e3d10fdae3eb48a3e7bb9ff29c1f3aaf62a6bfc281824f0b272a9b10a82847828ea7b11a75add41d9ae4469d3792af3a501c070f55ce7d4c2c374ed1b5f66f9031c3b52739ed719eecb9a4346283985fa034737c6b84026459d94057ccdd43d7a60bf1257bcef5cf999c0215bce5332a0f3a9eaaca96a39f4de70091a87892bd9bcd86261d12132213a56ee14c331f2279f634c49b6487d663371fc931541998363b7d9ea9dfc7f825600325bed10c4907ed9c02fce33d5d59e7eb7a4ec3fcd5cffcc8eaabca34fc2f44a7bb95931d8831d2a761f670caf25fdc143dae1e257ecb2edb9ec012f160b101e3270d31aceff5a6c0b0fccac782280814e196bc895a7d28073a2cc75f069beaa9165349f0ceb79d60ac75d8050fad3789bbbb67219a7d3aa7d164bbe3a1bbda68a7683f53d0ed2bdc4707ada2a64c59d8aad3048304a58696d3ba8f42ecda04ae2be453502c65edcf7568a1a590eb5d92a7cfc7aeb2bc6e4a6eb547b40fdbb4c8ada6800b47f02e35aa60171a566f351b0987609cb3af59b20616da532495abaa529fce6b977ddafc6fc1ed40156274712788c13c5b6fb07dea87c4d534c6583cb4f86f8d9bebb3e89f3c0d3442f72837c56a614ce8a7e15e68d55fb0dcec47e94085e2bbe3575f495fb206e0adb23ea588d79283f68073ccaf5740427f9b7e8501503e13206ccbea1865c68fb522d63f56e35bf77588916f391cffa59eb04c0916280c099238be0678a0f9d27863007f9ab3bd6e37d7099355eec9ea3b68e77c49821adaa5643e6e82aa9117e19e2e14a1f08b15d66c0005b87f549576022fca0d8c83acf5d477b6abfff5ec2dcd08eb03a5c4e313e063f202eda3d4c318bb9f35116589fc5ca05f12a01e170e29bca30a4536b8a30123b4a9048f8c33a0d8f92d1ac344622967f21b6086301c6a0969e2098af73d46be88ce8fc816161c41d58a185b793631782bc9a0d3b5291bf67d0d82a390c552172f2a93b864012e2f75ea72bfd040e8fb2287be7fac26bd88cabde91a6eff73f20b959ad48cf149d5e6bade1885fcd512fbd82d0e29aeaaa9febc6d7a050ab0316c16f92b41eecae5de1840d019edc327b83278765b225dd1e0daf2d956ddf6c9ce36540be3c9d1b5b2d9d9245b96080092ae7dca1f288a508e6d6ad56d855cfab13703a57be8fc0a1166d4dd8196c237c37431226215b71042036aca30d97b7d9e85d3f89fca77cda57554ae1d4137c43e451cd91e387613cd07e2909e49268c048b26d1728f0daa29fdb938e46c9d420e93f063fd977f2c029748f0786508c3fb5a5ac654fbd6d2f504f08c6d50b3d40ed8070c147d8467a47297555265377a635d81ffc615f51ce921dbda99fe0f4b95d1bd65a239739442806c93638021be034b9eef021ea06fda3ecee4cda719a84cf4acf08e488733568f432e316145f557a3117a2c186b900ed4733498343a269102343d365fbdb2f725c8fa98364f7f8da24b4e8d73e8366e08358efea8067b4d49f76e3761e847b1d27097482d1e43cf32d239c31f53e8b881f26c11fd57cea4c9afa43387f1c57d6ef1109ad93dbbb4afbfe0d5aa89c204be91d77ad77519ac44c80075af87c6ce9bc008f6dc5d19081532936e06556ac03a0ee9334f4c84943eb760870636a0458b6a2eb2635009412000c8763a06930a89d2a29283a929d0e81f6aaa349553740e931145464e574c2dcf85ddbc36cbb3d21bed59014a4724fd257541844b2baa8b50d1b6d14ac57f15418f9d99f32a4c7e5fa0c85a4f1ffb543646cdcbc99228ac23a6ac255128422cbb459f5beb30809e7e1fcfaf42f2cc4c8711410cff1fa8661c84cb7aef18e4ca8e4db02fedbed1056ada012f2b132144434d83d71a7be4103d59df22a9b35fb4ad46c475d03961cd0c0771e6e029618e46b69086c6eecc9c506a822decfef4c113d3b0d0966843b763c2bba85f3d216d0de4a4645673d4c81b923339c0b70eec925faabfb5261c7baba0fde9ea02a16ae3d357b15fdc967c2afea01af7715c288b5311f06e7e6559cff0f1ac2788cc5879dd5dae957703fc4d329a4b5d8928d2635fd488e5bacb7b369eeb5fb3b6671b769d1f9368ea126314b6b648e8b39fd2433e7d1d6318c44bbb2e55c52e61c502b21232ebdf9b7e80e794551dc0138bee133504479d758b1dd8dbd9b68fcf6ca984331abe257428b2aa8c2a4ec5c2592b381a3181d3716f85ebcda2033192b0d5e2b3b1c66332503fb6fd3540920a5a4306efa3189b205b06d027d0185d33a7b19b8bbde893830790cb9d1c9c815712625162f9920f828e569144045cada331f51119964234511ef7069871bcfe8e2ddb5213160b7be5c74387cb12c421c2f3226dfb02b9f5cdb4efaa697fea9c985be7c00d839337d6d27b80f11acd8edbbba146be328ac670fcf91d4027b6cc5630de21d82423a96e01540c08e73f59b5396b021bb452db55716398a8bf41c372fa7a0244e7eb25a3482b697681a618f88ec9318468cc501ef275438a2719e856d3bbfcb97daeec7a6039a2fcdde3903948cf4d3df3ff3313d86dcdbe23a236607982e4de936c947f522950065bc7417cbb4957e07549b5889b84a167a2d90979d767d004485ecf36b5c3ced126b4fdc718f002043db9c8a13e230b8823b989111c5075e9652a53df3404168e227a0373bac3fafb1588f75b10a5ed8d17ea3fba7bc794aea6686f45fa697bb3084d41897f219e5ed9a56f376cbd9950c541a7a36aeb525f20a64783e50a67b3c3e22902c873ccb7ebc36c4980b34c9468df92ddbb9a7df2ebb656746870ee06f256a82b7802a7cfcdf33c68c88f168810402491147580f9d11da64599b37619506ffff330fe2b6034c4260ebe672832256f4450c976deff9de93f05d8fe789aee9963f1c8dc721ac94124e7bb8779f1dc4eaff2fa8f5539cbe21a37d5cf8e6847c81ebfbf76e31984ba68dba7c8f3d61784d19ea8d32ddf359cea26b5d2a8a1c32cf67b8ca38ba18ead066510e767a6ae526482c175d764113151c226fa798c2f04aca808f8d437106f80a949ee4eff3e600fed5ed941eca9704a11e9948a87887cc23d8ef6598a3a1cdeded1715bcaea8157d2c9e28e843140c130bf8e36d04b1e30cd9742d495babd3110515d54dc24c925379e2593b8c1e8dd7ea8936911d0b50bd66c2dc2d594c5da3b6e31ed81a118bc2e80de55f586081a90bbee9a2c1eb2826287cfa9dceeaae7e0df9fbc4052b0cf9fb19a00cd3ef175859db95930dcdfdc54527a473bda0ce95ccc50458cdbe1bf1f980a382e63e653a963a6b35f15b6901d8a98b4f7c55a2a2a346217ff6d0644c2243fb38c7f05904b6834e98cb9a16fdf74cdb50ade8c7e165455826fa967c0f582fa5f3de2520e20cfa31dfca56e1cc8ad6f4e4374204fbcb0d528fd42b0dfd666702f2da5c81e7cd91ff74316a744b0a79367f5df3553c9de91625245b9dd465f62a5202c4f02faee1668087090f29509c971bf489d3367d3f121856b599763ee33c078dd9f496c617994589e91cec260e6d82ca704f0bac18437a80513ed5ef9a5fe6529bc9ee707a51da337c4d9f5d63e127e0605b69163716ef0ec00c849539dd42b62ee185850f51b9904e1d9e933695aa371971952aa6c2ed127b5ee6bff43d8f25560ac1b3a3e27a101421a48072eb6ee17a614fe3d32d7bfede7311328f01185e15a96ce90c1e8d0f98e9bd4908fc2b76168f0cae6e11c6eb5870f17a9859c73ded478fe4ce68341c0fef731038453af9d77c1754e54102c086532c314cffe07c0a14875922ea3a6e9233a551fb66ddaaa863a597e0cfbd2b7ee5bbd0f929f68925be34fe536c091f1d9e71c41afb28191b545806d6c8bd8066d4ee8d0e6aff6108ae457b096977294d3ea0fb7748669cca4c116ddd79b9be27355b90025ac92e8daded373844abec084ed0384261d79c6d595bca8bb0d913b5601e9b047335141819f9159c4d68bebd23e4a41cc3785cdcf381ac47a96004ad66a46c6f81555806a91d1cf0f9297bb29048e194ee7bdc3c8a9102aef6aa3f299ce54bd01766756e0254ed9231590720667726e0e65e5689719e42c41c0e1e41dbd1caaf0b8ae22c07c49577a3fda2581b8e5b66466ff03b8c7b597916f68fc09b16087aa4be1ed67618da2127400cb27dadc0bf9c0f288f347d6d0665d6504a04a09b315a0941df1c9a8d164ae4e8f93c26d63f229af28e0146bf006d1c67d2835d2abd0e697b9a0da2335d17e42cc2d264d12c8c49d4fc5c2fd45ad8036b9beea800cc4cae22481c14b5201117af8f03d5dbefcb2edeadbde5cfeb7ff0f7b888fb6c5b63b978b410038ee7d291edf2e419d4494c147883a0d426397aa587388c40bc1a8129b186ddd2439290b2eda3f091385c21d4b7fc76f2ab35ce2ec06ed84402cdbce5f09659570c17d49c6e65539078f338c46e46ccb1ee1895ae9567f29aa0396d077db97b2d006d4581fc61c0d7664717c3afd5f48ca23317764b9807c2877c1f37e09e92c94275b951a48171d385827816574e1ef09b92d394c44b7d8446a51fd182c497d48cfc52a3f934737d61c1b86d85e98864a457b3b0cd64ab0ebd4255d2398a0c5a636558f41644c6fa2fc23c608609faad82df5afc91fe17db590c708f64ea5b1a5bad6f9bfe23ef99d6d25bd19da25fb5ccee036839b8dbc104313fee6c078cb6e0d53220f7ae26a2acdce6557c351ff812be89543b26deab4b0e05c82a03d99a6404b9d19aec39e239301f2f411c1f08e9abf11815263ce89516515ba70dde35dbc78764ebb6641004e2661ecdee8b378c91250a2b796e7e67091a750e1bcfafde79da3523ba9a13c2f14d6906d00c4b0525988b2034574c89deaaf19497b1a06aa5d78038a88db01e58ca9b112f7be53689b2deb964158c1f5d49816514bbac20c822ca5149d0c83d7b87612e96d7ede9cd61c6367b6d2d7808d0790391694ffcd669d347d482a8bf72809a8b642f20c1f7fb046eadd881fc20832e755302a20d7a5d3df1343c4f705715b9bc778e5bf05bb1bb20aa1d59b58ad2e53fde7411e60db7315e5427d3e22bd468192fd95b639219b7be0a77ea00a8448b78a80949bb9372b8a0e028c074d7e622bdacd5bd0a8b1a736ba524c50e100c4ea9b9e092254ebaeaec39c39949f22c423518d1bfc60df4853fc9dec9475912d37223e83b6a95369b367421206db7da3302f0fbef14175fd403b9a92616a14fadfca26562c61df52f707b518ed2134f3c464d74af41dbb3bc5061781db55091987c1207dcbccdb2281482e29f4536dcb134760be1b604e1441ab6c638e60c9fc225324b19f34892bf629f081690d89202e5ef6f696f517f4863187e033579893d8a9e12eaf9274f09ec59ddbbabb01411c2772031b795c06c4b710a849daeccd5a26169a3d0e49ca1ce37495a5762515949221d4b355960851073b9015d37ea0e82f51fa9323eeeb5a4345a83520ddf60629d27461fa2a1b4a6677847373871d733cefda2ed5eb225044933d1e1a268939a290c374ab987e31741c17c7e2ed5bcd77210849bde3e1889c832325c71ef2b0380eabb2f5aaf89f7988558b64e31bde26519c314e5a4c8519228b43734b3b53924799ada315d461abe37adf651753982dab099ad002db7961a2ed4a9ef72e878e16f132ebb5711d78fff9dc4cbd11438ddaaca8f1e22a573ee54a55f0039db101080395e594ff6550a31d9c366191078e2f86efa3611997201640c044b2f946937418d242d50eeb45dcb9d838172037073b5c1f06584ca4669ad5e22dc9190d983dbcb250a8271c47738213758a8c33414c934681f92bcb7f7c3ed9132a04c11d6c01dd71bbd2fd440536198de36355f01f92696217c7d3cbd19ee42359e5aac7dc0c1c1471264ea541554989c1c6ab961088a3647ffe98c9cf2f167b2aee1af91182936acc269925463904ba28005cdb4730357230ebb86b7651cad96d445c18885749b73591f7c579ac3104791b1050abd2eeeeafd5af313ce4a36d3a8841e527c956189c48550d0baeeded00189731446e2bc3e63dd2412b61119a9392ef9615209d465a8bba383b76d6686d1e0364b9b3dc840118c020016c4a70f7a11de9caa6f3a079a51dec708b233d9d073c6f5165b41dae9a408b8154770525b24d39d0517bc5d5ba6765164896e0f30e86d1b91235b43e3e088536dde4f1783a7765c890bb376fac78c55a246943afbc91e97d4e095fccfb4af93c94184159cbb81a31f6ef7de9339a48475e052d99156387388b71d42b546fb45d9818fa19ea877e34f39753188b497b6df8852f18ae2c75b218ff37b2951b24b84e11cf4eaf7ee27655eace9aaeda12757e8539771452c86d8f47090fdbf9ef32d1ffdde28101a5604398875ffac4fae1d59dcc5ac6f7e274b0ca45926b65429b662a33182709f15049317a027826484f5e6124d2e73a473c52c1ceab76e218adf217532903bfed4e0b4c02cddf60acbe511f3f61dac302d4c66b059e7bab9d98c1772bd98697ff292212e970617e1b77d4ae08333e0004c4265658a1711eb6a68d22602908fb9afa157af27903c6235cac01baf66440e0031c76bfc18af71e0958e2bb8dd359f214bb57953d77e6f3f079e91bb5ef902ead30e345e8a9b7218901dd154a5981c2f5e4f64acac15e065d3cdfbfee3a5bf7d11001bda481b50e9656ce1da9e7589bff882e05a54a48d71eb3513f196fe0921c8c78663cc5d71871d172ae61c4822278dcbd199fe3e2715ccb9a9f54cad7119efe029075c275ef056675c76f6e38855efc0e1b2a67296343f8fe56a57f1baa30a8ec817a3e1ac19191402522ff8edb4c153810b9e5ce3ee0c84ee812ea4d3f7a13ff20ee439a2db62a628510106a054a6dd3f1f425b6ada7a84185ea49e290b5f71a297cef71cab6e41237b9268050ea14f314e730c15c7b74a51b2bd7436b1ac8fed871f5125577de5ef12d72ba5e8618592a5ea5b91ad9845acc669659597b9c654d78bdc252c4df3115ef2e81036b56ded098a47e0c93e5b7be8bbc343ff498e55275470f7f8e2c449453f984700e47546a09ba93f926b15a3219fe0620d619436a3ab9ad99452dd633ea0a3fd1d2c817c18b64f40eb5bfa6146df956d19028067d1503e1fa70147f8cfdb012dadb71984d29911c1edee594e20f7452b46772cb86f876f452bbc2e1ad0370ccf9fdf8fdbbb4ccf0ee8b07003679696ce31960a4acd188691571b983a961d747a6989323345b508a13ce6ecb4817497245213cde6039b073b3ac5dda720bab586e8d69250d021f0f8576d8335bcacc3808113b0a6b3cfb96d6778002b995e6629c274a0292adef513914f914a68d2bdf8a5bae3e9a7f4ba328d13a8d5820b383f8aa0590259f0622d40c94910b0c89483cc41ff9272451717f41d20f8b636b29511226b13177c5311f8b0cd4c318a227f5270a03e9e237b9fb4f8a5fd1df94ea5fd429aee3fce1b5aa148a8a67952ec366ff988e7c4674b6eb96f57bf7b78fd58564b069d20b7ee921b81339362cd7502de401e63aa550896ff1da0530958981810525b4c7e6a387166ea7ec044c0dddd2c6ea6dca6ee1ecf3cfd380a29fea28865e6621c01e4536af414488bfc5e3dceb366e9c40f37cc099b9e3b9919591f1f66a85422b72183c7c45257bc4b985e0c3b80746eb1afc00b4b543d15df18a73be894e9ab7896ba353cd422ede3ee760a6b5e25488589eed6ef5390238c9604e8465db33f7c8c333a7dd8308ce1d0fa56cc05a86d949bf3cfcd24382f45aa9d1cf1ccc8cb8ab743fdd93c823f0b64b0c2283a0d9ddf0b3fe9038cff1fe276162fe0da6af1be0a125ca647ef598af3d25c049cc8ad9f6763e422ea70dffcb44a94305c835ac328df0e31afebbf15bc449de17956aafb6ba9b1d29f66e49a140436dfc8db76741c7f8aacc792a0e1a9aa1f12523477fc0152a6bb146f7710101370e1a8706ca0f96452df4909b712fb8bec508e0f0c2a0ab59cc87f33499aadadddd0ff9469b71adda2bea028c036babecec988763191b5b0b00a3a8d5d582ad754e6526c3eb6b78281c04446ae32e6aa5ca4c9790f5d07eb85953a195f5bc100a52880b18c2ab4c70d081d953de55437dbb6b9b031f630b00354893920982a4c8baf7b70646176fe61c7987187524ab199909df803113a1c8316f94fd910a6cc391d8aa61ba9426ac7bc94913f6c3068ae14e1a42ea985d0bad18460299659a593f93d39dd915a6f3eaf64baec1431e30dcf50a7408aa038deb9bbf7d3e1770e3fff28ab3aba55a43cec18f81f35d538a67c4de7cdad9c2514194885bc3d73811c88c74af106842b07517e606d4aa776bb935b518b43aa2321aa495b60bb3512310c092f008a6f40cfaac121cdf5dd8d759374b03e8e815b9589669dce8f8bb4ebf7e568f64196fc680ced655508a6bd2132897a3d4bf4950a96109dc5511ff0211b9919154beac7f72d729d9954327f20500c03515e05b6e6027f1c0745b7da7d484ed64f74fc2bbca99b73db090791e3037124683c190a13572244346fee9c623443d5b83ba1783a9a049d5d323c0ea7c0b798cca1ad42660eac8b017e6c88bcca0228df4b1ab1eaa9f1890a06462167a7ce807a1629e3cf0f9c4abfbb60a308d3e32534db615becb98ef9d77469bfe4cca99de8d1acfab42d42569124af9ae8a47be00fd4630d0bc4082910f598a3ffc5cea3bf2f4b82247af26ff87d35c44335768789ea9500930648888c3bc0aea31c2b94e906e81ca2e2e1f78f477a692663112d1b8025b790e067617a2f7036c090bf2f97b35dec21dd27c25ec68678ef663349209f05cc6bb9d9ce8873d37bf37bd1c4c1080b1065e59461264795d0b0d9a3c1df52012f57cf208610a6c116aef2b3327516ed852bbbcba11d76d62205e079d23af415553e2c6bd7b88b77ad0686485a0dc2f2261ebc6f5a542afc85d5873397f11fff6841982e1e23cacd080911e519810a09835e3f6f42778619fda528acd912b9278e5aa685696486b2d79e9c3e65d3f929fe4eb3a7e820856fe1db7f9c8e76a0faf96fcb49b34383aab0d6599a4bfc35506b7f506751fefcaca8e0a01e684c32a8bdc07943637dfbf1c5c24c637291dc559390fcfe5d4358aaa6486b0ad55fdabb02138dc2ed47bdcfe77dbdbc2cead699e30c7392ba598f1a59f57fcc91fd420d101b83a1f5f62e9e5da64a600dc0a04748b673d447d882a9104d0b31d6b81dfd3e09a3daeeb258083671626fdadae242b4da5424e19dd281f45c4b3d72998d2113c1024a5d75828fb7a028e60bfd6f3cadd74af11f34420614da2f85b4faf244397d5999779dbf787be3e4a3c8c78651836945f8a6674708bdaaf7ba26491cd36da303d51fc4c45117d3f2abd2ab7e1c896ec81f11d899d933448511fd21f45767bd7c32284b591b2a69eaca6bc0afb4aa484d2b3fcc83da90db66a377e624a634a315234db656d118cde9358dd9d2ac1feec8150b9240db5ee6ed85efe2197b8b17eec0bfe3ae28cfc694efbf6691c568aae7b43967ecc742fbe28f45ff5227e22251c43b90a50f37cc5e2ef88708fd5bc95bbc630edcf2a5f79fee9273896e36a291c432705a07c1fe45924ae322c1b48f64facb327c0af7c36207caa2fdc03f472073ab920ad77cab04ad3b6ff704b812a12bc32146f8e5c2a844b881a53e85f84980a5ef4e649b682c39ef0203ead62b5b6296a247a106d1a3876d0c5911e97dae1309359237ea66cfced932386f0c304aca406fe5c8f141dd4fe102de7c1ed4f3be6a42be0993eda2f482608393ee134b4a70d7a9e1b167303513c6fb1066263912092ab6934f6443fa1960ce4e0edfac7dacf5448d69e5608a2ce26759b47589dc968aec8b6e00f9c02bea9319ca2c252daeb5c60c789fbe89dd61aa7bc57850ab90347f395e4d121ef92461460eab542610b4376055c69b99963d2830346f152d4e3f9b741356f28644ff9be69622cada4d5323ff6ad864c919dc0ac4d5c8869d1a031b29c4c1978229e3e5e6e3ae7e7c8ea852225da48a509dc1cef011a0f36ab0b25ca5ddb846bc6c6ec88e4e1e7ade48472d48b203a0c3609089e1fc2665cdd396c7bd5dd99ef59fa3724498a11c75800dd6bb0d21ae38dc7e73bbaa60e302c5f9681dcd2530df02fd1ddea1cccf9783184e82827ac9dee5ce714dc4c97f9a77a1be41fe28aefae7aa21e9841fd3adba72223a50d68e40c099bd1189d2b0ced856c3467a8dc955873df9f48f7cf90bede9310a730fa76d2d18b8195340d5a52c0bf358f2416f7302ffe3e0b4307223f4cf3cf65c95d2aa23dd4d27535acb2d643bf2c04e36757aa3703fd8b5af4e9f244b3cc41b5555093f4dbaad939dd31cd0d7a87ab20b18c944edc41857d1f6940f5ef8099ea496c1291559d8f0858dd5e9b8f5f59fbad1b8ef7cfd4d7c3e2e581c3740945c94d64bd363d47474f9f380e1e02a0edb40fdcc336abfbed5fd69d9b898b04dc20a1618963dc25ac6eb39d8908993ddf280f3fdc16dd1df39841f2c0d6750566bee39777e640ab5edb3bd6e1e8b08e7f4ff2cd29ef3fa0fe897e9cb2cb85ec50ae32007362b34bf62fd9ebab42af65921600de1399e2f0f69028099aee2600ea9a7bbd881d7d7a21bd5e599e2c5b060190f86f97e8117c2abe9456cb36eefc5bfa43fbf75ac0a1b4f34aff4ec1c56460e02ea17e67006238f5a9f16b694b914bbd1a7cbae8c484a9190f5f05600e62a5166d13985e1da6f1353b46911657c9a82d4938deeae0f562377207f68e23199c6ebae6a78adc078aae4104c45a948862b638cab08e8ebc71b1797e615e84af89e7d3e1031b10566de951ed93fe49932e093b11e0f94b850cb00b69a492b081e027af1eb41c388cb193a31570b0c38e829fe907d39a675500a285a3134036620e8b7ff361a140057d79d64871b82d84b73add91f9131fa53e6fd83625176abff2c7e49d0820f69f8010fda70a741a86297b90692170f723263f46afb8dff34c0dbae68b327a609d3453ed94fabcf829f5f34bfbcbccc4f9750392785942cdbfb0b785f92f6913107d8adaf72ffab8573c910f698bbc9d2f8cb3fbc2e150a5140a1d77e00bc445d45a6f602e8fc6d1a9908babd49872c39277d4b3f68cbd6493d5557d95657be2df220fe4e79502f567d59537cf31813edf9772c2a18e5136391e6a943ec54b8c512744e2de3db04280c2007d9ffa3c78b85a5ff58c314188116ee5f52d49e657121b74d03897fd266e142a03288525f9a12c0aee1176fe083b82be7ed8665791bf0e623032f67b91273c895397b8d31c580f68cfc4921014dbb5122594f546af2e18b6211418fd2e8a9b113088a8e5095335b71626722c2067d6f0a0f7939a64580a7653e0a264e498f43c26c4823195c6aac928e089570b9356a57cd687e9156ed305f4c79d2b6c79c554848934c528fdd3ff39166eb7cd038039307441a0b57b7987e95f9224af0c1a35a6d79476b5808585fee51848fbe220f55329fe943e9ad9929a1a2f9c179bda4fa5d121724a7aadbb4062b01a6c0e8f2b7021f4fc64ee5e0cd348d6d09b6c6cbcbf98b40fcf902c8f1972186bcbd52ff67df8bcff27dbd4368e97ab0282d56be3aa421a19cf2dbbf737dee54d8b82c3a88b1e8c109d38322bd1a76132157df3988e93c80b55b36468e549eb8da8c27d5fed6034a2ad3afe4b0e101d506797ba5b04f1c22306139a77027bd08c7a8c419ce0a6ce5723ac0bf9d0c1c14503bf31ec9705177774ef9701b1b8e0d95b88081073dde31dabdab3004e5926769fed436f09708589ed269996fccd49082b3926797940d853706e3d1a15e139a8ad4d2f0dda00b53f9302d782b17b2a47ca26186db666e1f4db060daeb9ca4728d01f289ab1ead795eda170e8795b545477dd8369061d1f55965a44917db4b3f86f11d1e6f28e420451f7c3656d7de96c6346f7c8892d6928a7cdbe3695734d2093506621e3888580c99e29143232fe6766e22394e87e0c8092adfc0c8639c29ffb6d084d8a37b2fea5b4ce5ab0ee137c91b4552b6f89eeb850158b803095bb4fd9d4882fcb4a5370a2d495b7fb4d137007934e20e38508b3a7972b34c7101f3fb2d039e96c090ca7c7dd9af2cf25628c4689523478f3865cd0321bbfda37dc9e2bda44134d57fbc90c5cb0d615ea1a57d5ce0dfe64195f8fd4e4f2a0c58240d08652faeaabfb9f3e25b2db9097d6772c6973ccd1beafe879c738a535c2ff22dca1f5f73c73480e74274a732c919082247ead899fa5c582546efc81cb80580c702f6a046ae7e16d4a2948a682ad73997bd39adf9cbfcf9068defdee5022402c568fc8016b1d596f24673b1a045fef23bd4674adfdc57dce6711d13acdce99e6523e07a201ab6f298e12843faafff8fa94c67d8de6b4ce73d9d2af76fa7b21ea8e3b442c2583809b120deea8a6f5c4fd280ccf0de88482ad3757efe8cdd0346ee191a578a1dd5e2487e57b16e72f990c82c643b6a63ebb9442ca735327c79586b9d9cc3a75cc43ecf8017812a5e865ef5420e4b1341deb5a6ac395c1a2f0090505d030c367aff270439f55ea912bf32995c308ae48ddb1ec8178f7051583f18a1fc1fef98ab087c738d0c48b4b5d6dbd857bae273e3572d6ea1469c7b291e60bc6fc4d46c6a052a380d11d7853cb17fe04f4fa941106dfd346859396446289c52cf3567e1a00988f4a78a625b6552b5c0baef02f445a28d16749bce44fd58ae52d3536f8b850c5f86011b2d0893ca57f4af3911b11474e9f370efd127d6a5a9a49a1d8628e9bc47d1e25c06ae8f562651dc335eca7a6bc242803ebd7748330b86540ef3582334e8418a68316e1c495df52d0a34d8c959b5b33b57ce4d24cbcf96df22419092af359b5081b8c25ae1002fc42ca1e42c271472bb73e77bccd7dbf1c4cfd7bd38e3e77c56994e173c0ea1ae8ec68b221b64952ba7d87a5385301367860fc630725f3d55060ccc6ea87ed228e33ea54c5409cfe91304b8336c4f6f187e8cd5ca45cab7b9148fa717b4d59a7dab3405b1024a107a9da33c7c4545252f7644da808a52c7ddcafa4623188a1f044987d49852a77b21d1a7edd48447af88bcc7f683d2bff0a36b18d7e33891ccc350a3050992219a78253f0e0195e6ac79136d4a27ffd29018d1c37a2272e47c8f3dd91b83f28def6a23db5e5b3fa7d64db5d821737fe7e264902176cf64a5df98942143489e5a7afd6b9b1096949c98f0bb903c2cb0eb439f29e57645dbfbef89a21828ba8379b8455ed3c6302a9431cb41567a7bd6ac3f8e0e2230c6db8de61cc3c7288bcf0aaaa9dc7ddc30ad1ebc67b500ff768f0cc9344f32565f113b171df471267a49fe691b8209886b600ad1a407d6f352c4d8804e683ef80ed696e62c11ba1f2dfc0c39d88354d6c175b41200aa887062e6403570114b833292d4cdb3f87d74f3a41e1bc7a48cc0c77959770c862c84ea013418bd327cb8ffa16ceb6bb971ae00507ae2c06beb66dd1efbb4fcdde16acd43cbf57f88d0c9ff2c98379deb7a46e25a441b4a1e4ce19a4b7e7d4a4ff26977d3a21c1e5a7a7c7919db9a30e1b7dbb3476488319e02f0b6294bdf83e6fd4ce1f71f6b8e81987a34b7aa567f6e40e99bd20d99daf8ab1db757830ae398a07a5f4e37b52648eda75a212a8734afc9147a2468f2998b80bf506ff301f801f863c1d38118e448cbc4f5370cc2c6e026f98b23c4de0eb3fdf9e3507d7bc1cfe75c79bdb07f307b5c04547e8ae158da4cd93cd5e3510efcd4a0039bc73398fb9b39ad26e4168b47a3d07112ab9954ff23ec099327fff4ca11e21a7b329f2fefb2dad9a4371f2e3dc7c45735d9da484a62d33d783f66488a3b53f1ffa17d86f8e488786bf881b69f66d962612a81ed3125f4b8842ca34bbcdc93c9cdd368fba4bd1ed5b1dbd3368bf3a2ed25295c9e1ffd2b0ce2a17d6de8a6ef447973918ba2a21e7fc9b0023f29067310ea6214667e1804490ae5c5eea28e4d04c156aa39d04c55c334b9c5267b5f803605ce2e23623460df2a24465a9c72eeb2366099cf90b3f82532b0d8ffa8a9acb46b211a6c9a33f359cee4857c65d3ddbc59353e3f16f08e9ab534cb2d4c6c71d391fccabc59c62bc4c287853951ec841eab0eda22ba3da065a870909773c2905b0c9ba12562b32d82c3c318a2cbbf5aff4221c29f4ee63d18c0ddec6b6d5d9a634d0d6152eb92fa252e225ff3459bd7c432f738a431dd14f7037e5c46ef01aaaec2eac3d06fba7878f59dfa07b218487a3462012a649b870e5ebd6bcb6ccdfcd56ad82fbe9fd3a2c5846881eb506b40e9495cd409a600d5d6835fb81f35b604b00287c1d7a81717ab9231e49bdebe514bb6163fd5d08f41c9af566fa2463a2b2db311baac3f92ab9062a9f8544f786085acf515eb38e6eb9dadf89203c6a60d5a261fa2f7912064d56911e7f86b44858a80f7fd7e9b72982dda04fe8e18138929667f4eab94dd4732fcbb3b3a06f05dac804d54c8bb8cc504fef3bb70b0dc524a52b0d6bddc741f281a8fe5877444814d6458040bc8af8310eba29bf5c34cffacc1de3ba0d4767e109c3add39f36af35b761cbec9e89af4e92e28ba381347f036813dde9381a5f2c5fa14ed96996371c4a7ba4337aac3f843afa527e0370c4f6a02129636a03aa272f165f0f11b68a7cf98af840667f45f98aca3af3ccd2a7bdc0154fc2cde34d3c75738a8d119e0bcc2610d080fff5e0be8287ee6598150c7ff930977ca7a8eca8374749a0232da1dd3f5b4f1393ad377a012659e466ec6791e1268098b04ae044dd304b5482d1309cd41664f1c5186a05e107e7e2149edbe452265719f0e1d43bd4513b97a9cca4b3f1e49126fba608e9c8731a2ffc29ff2cb38d392ca8fbd21a83fa03ba7765a41bd3f646150360682f234adec539cfb8c90f322cc710189dd3e94c2f0b5ae7ec30314973924d6d1c2ab53b20bb4783a50289a46b998bbfc453aeaaa806c29f3a443b1af4c2d752909bbf148432e268b5f6a09bc36699a325408c03f7dde4bf37de0aa517ca8293929da4e3b573ec2d5e6346f55015a6dd363a09b2abad9aa35d3e10e232ed5693a2ec537f2cfec51c5c4dcfcd9ed1fc77b9e363a10719eda4a8fa7fa3c37d1f0fcc5e26bfba1bd3dc194b1ad341aab963da65ccebe1c307e08d37bbf403a8ce4c55f9af933f1117f9a030878fab05fc00a496b8b38b1e6c7e50acd59c0109309cb3961481664bb3590742e66ecdda07db4cdabcba084e6f223f101ddd73db6ab26636b41013c20df9695e76c14b59320a6f4fc133a0dd4fe65dcdf078620961b4b80a3cc98c562bd2f9f3454f6e268dacdd048dc78fc1f952c6409376586edeabf0910b9b075510a786b3f28d4484749c58eaa914ee7c3b3756e9badee5ff300f3268b5f5ab244127e2a7df1519aa5de71eba6f52a29eecef403b04aead58d53050657991d8b53af5bd1bd6290d954bb5bedf4a65248950b55277201deb9cfd6c1d2a877e0ce70d00f32d6ac198a6d30425c2a10239c802daef291f3f97105bb939e45ff0f9293be6b5a6023d3e0a1ef4d92e28c3888d76832cb5ac14ab950274113f6310f277c04732344f27b664b07fb554f71eb2a9cbb69f64894dbc6d4ba467c026d1a429f384962a88acdecf68afb8b46415df00e837de1b202e1b6181656cae9dbfcf349fa407b45599c3402ed1a74c92429a15d61c8f802a45dcb8fb6eea8d1a841dc0d4a317bee1b2f8e7394d7562334717693cddb9b6702c87602931fcef02b7d8690318173d29c345d18d004e4d53da4d5804f8719406b4d6d2a1f70071475565e5cb3fb41c4610a7d3602e51317c8bf0dca4de3f9849b7a610d658f70a1a117cfa55a083fe7e4732b762675dca98fd97805f0893ecc1fbe8be802cd0f8376ce56b73b55373d6c6fcdaa74d0d15ff74f48737654863edaa51050c5aeee94b8de4c79b5e055c2599362495ff3422bc77edeb6ac78a78e26142205afcb779f8850dbeff54c7196fcbccf753221926b045af92cbdea11b8a1bd33c3705ea6b0f0b1e4f10c2e4ef340162db25afa87f4b4103e67c610408ebc4a823eb7dfd1f04f25c569570564c6b9cbab6acb95c7abfc89a92e133b62a7ffc6cdb65aece8e2f5e305ea263d6ef62a33fc3318fce524937aeb84cc983940de08054d69f9f56d25cdcd8ac0f8865a2c8bf4902ec5b49c20597849cfe3190ba3b4c4289e712f39f1db00c1648676566f7d5355c50d940e0bb83e76656a6e21dfc2d3b8e7064eec17e17bfe994d097a4b5747f2e078865364189ff658ee719999b3a12e188f86975dc40432b1ef82ecbff3538d8cf1e3cf4808040d58a63b7db38662cb51a330851daa81d1f0c7628588623d60a510d1060bc896fee4b9479a55e904a2f14b38fd17c840edae0c181562b5b21856bf9b987eb183d19be71b6610cb4812529e9c4caf173e24db8b9b440c71d8b1d1b994b7122e2238ce5b093d37676879366c23f927f7d9898ea5656ab2168e6cdf62a5a2d90c513bf2ef08aca206145f050ff0934dd30450ef33ea32baadee6225a32c56627439d7495d3597224dd1514c84a035e70e545266deb996887e5047a83c2c6a372d44454ba19512a00c93532d8ea5891db569ffbc12fd911c2121170d3fed054315d0c9e0aa833dd33d0b6514277e5fe88351261910499594d9117ddf7df6fe2ca089e28e486992a5fdb133863d56295a2a8717d11025e9ecb04423a7c0e1e19bfd7789dcbcb9e12a754d34e9613b67eddb4d12da025f2f57a31f81a74f801e8596121c4a39fc1f2222d8d5b085bfc97773424c50371b5c69ddb3624d06921e63406d1605639b5e82cde7828918af522336c4929adced3b9e3d90ecaf092982e8e5fd6bccba2c459631b07191976b05782c2132886149c6e07f2c3b6e2527a9c1d6f237bf72c19a4d1a21fc207467d73f96f1e5babdc2e0416660bf7c5a082a78c1ce8cb9f1c6e05f8008be329912d2579af9d1412b46151a7ce85e81d01c14cd470cf5629cd9593a6a7ddc99aef9afe16e45352f083e33c0db8432461a118bb6fbddb85698a133ab29ea51ff769b391b2a9992eac810ad523969904251abbe9fb42562c696826aa5545fd996d88d2356d7e6a9f544f0fad1268c3f00351134bda7ddaa5e4c72507185f26426da3e3b756d701ed8bf3bff00114f7a9785f37e1a1b4fc68bbeb331c279dcffb369a820e006a10340287167246c5c0d398a0a53c2403087047ccf6b459f2fbce305151d65ac4c75f9c244690f56ca1d938038f65958f075ca06054c08c58d9d2d1ecaa5390abfa7210238c1772307796a4b1987c992f500a20870849b9eac9b464cc011a2f627f3112172e514da01bb6b8f9e9d4506d25ad42a5706dc03b6fcbfb297777436a63afb652e41b83ed875ec83fd359d68aa67e556aefe5e7413641bf24cc87aa0490caa967317ff7bad0221bb14ce3fcfed5f962d3617a29bdcf66127d808c6937e915cd1cc69552887e3a9781547166df6672005b457295fa6e86c82a71d6c487304a2fdfa4019cf2e777192d66136cff0324a384d8f3a46756a1189ce9cc89a58e33f94c754b5b5eb98ab0249278d01bd41c7ae0b620198bef7ffddb20170c8ae964fa42bd3282fca2f986a963c93d51ce589b0af97953ca463615aebb73f8c593d3c24f984d4dc6e0749ed71728da88dc5bbb5215df4fe2ac51c3f540bf6fab5f7dd98e7b132b3ecfda6b6de70e2fc0787f54e0fa3cffedbd3dc26ac4d3c69c96418851f6e40253779703cc0b508ff59a5e5426f08426e70f28c67a97297d08625fea0654e383a217d4bd714b602b37c04f87e0d7af4b42d6ca78b1431326e063c4c93029689ccc1e06b6e15ab9e80659d2d030dc06148780749e4203f95362e44a81366a75954404c9c710ee4911911cca88fd0d0b9d9c66f7cc31b29ccaf9e15a0a78a3af7c69de26d5c0d60a252092c0e1a2634369585f3c413c0334a9a55ceb403ea63714397ad4cc433887783fa95844a56052a4d2176bb549db4ea2caa53fb26e58f519b2de3be25fa88914f33a55978dbc5b7c991687d0b45ee0e34acc6f9b65b34a74e2152fbfdedb68d5a09dbf6b8db4f5ab3686af97ba7fd21a6049fdc645ece9db123f91fd6ea209c9c64777c12b700d6afcb6388a5c6e204f1728e7052e1e252d5479973e7c96e6e2fa214f252df4b6a4b0b08ba95db2b391ba7b0bffe31c17521f516a36b2bc5845cedf9273b2739b9f74ae3d3fb37874bd65adddbce57ed5c20a38f914bcd036b775261a56c91210f0410ea4b7c8e9d59aac1f2d8885bde5c12fef36093d6ff139c415bb5b97540bce996ae26b2bc50281d17674d611b4053989c9b97b13607f054674ef83b8b70da1af553b77144bfe12bf9b274beaa10a1e2bb795eaf7aeb7d5cc07abef1ee713766c5350f4f869012707814da381e905dc01e3074cabd0d2d1fc92875b3d7880d6982c0cc5fb7c9b69cc9da9f8eed221877b94ac6a55b3079ed842da88fcbba7bfff5829e5ec934a7290ecd78cf5877fe62bf74c0feb5f62aa16a1467afaae1171a77ed70ec5f6ec1d5ef1aa5140db83b900343462bfa256556aac8e4a620b943d96fd8a3569630ab5ab0b0ad9474ca318bfdb1ce00dab2006ccc096a0dcc8a44409a9faa7296c626a8360e7743de53bba773eff613722365908e2debe66349b49e8a1d357414a59715bd3a4050924ed800a953dcec4437889dcf008315ff3de7742d45c81d295c1f06000de978bc8c3a6f9d49f90d4b3fda303d703811e292b6cbe04814221d3b875bb61f5616d4760fef7731db52e72f4e9718c79c0e328190fe4630b49c450f9f4e17fef531ebaffc6d16086aeb7ff3fb41e908ad9e8e82f4712be67e2e2d8722909a2f4f9264906c7630a264dcb64902b93aa30f60c95352dba30e7159131b2673b8ebcbcaba22c77ec1ffcfe97a0c86ec0f26c54d76af506899fc264afa3ea2e3105bc6ed782e55b97ee1d2028dcd2ed05a34cd0b3bc0639fe39b15fffc6f147e35ae96c7f5f1bd0a5de9286f75a3d9be1350de62b289bdfb950ea5b4f9066368f302fe6925daecd5ecb0ac8dd501b20c3f6bd5002a012a509db8cc8a7580296481c054d9445d22557622d7c1f4264ec2c354dbcc595c061575779230dc42cfa83787ec37a644aa8fa63af08a3b90dbda8ea519836dd860afceaa31ff4664d382237267ac3b2106e41280fea88f2dd7c7158a0721a8671372c9856a03ec1ed0ee44d5d10d3b1d4e5649f995b108a81bf3f0409078d8ad3df65d2535d20daad3a91329421bed86da5108eeac33deffacc7d81c8e8ca2c8a1b243e650f6ac4b085cd8d075850dafbb971c2d731b1b3c0dfaea2ac449f9c7ac0cc66b8a60a87765c496576f5eed70373dae8d754a6df1b024c1c26dc13b3620aae34bf28212a09754c9c866338eff13a3411988e4ef639d51c42b237cbf4b26f10e1a9ee1871a9fdc8dcd1d21339c7e7843753f53d982b4ef73a5300a64fcdf9d078f07ab087c058ddfb2a6b6f4b4de3211ae5e524a2413b42f87292a6d5640477e8b1854807919153e00baa543ace78b25a093f1e73b540c7b8d6f75103f51ca6d85f51d1be3436dda6737abf3f2f6a3f74378f33e9de5101d840d545eccf4def9534529e80d21af0e0fef9bdee85821fd813eda0cb07700a84cdd618ae23a38af25dc60c73e09f38b9fa26b51da145a77efa340488ce3b3148fcdbf9338e4a1caaa52de5db6d44028d728dbb2e4aa022cfafdc5418026be66820514865a09f48998a0a940d9be26ef25f65dc56dde3c6919f145a0abf1034b952342a0f5b13842ae52d9bcf80b9913034860a0da94f763ab96788b140186abdc19e70c2b63ed174012aafd2791f4b2d54e4502ac160289fc804581d3aa4381fc7c8080b94cdfe59ebf3c51e40e62dcbc6736e58a492ffe548b6a28bfb587c381dddef88c0f93dcd556645111f25e2419e47aa6ea6c665b408bd994f5f3272a91a4abcecab26b0360a9372711850cdd77cc4d9df757c6bfaa71b355fbb0e036f9a15dcf0b4172f126f938b8e9914ba5c097960b82aceefaff3d307e800b51420cc528fbce0ebe0d0b115922ca3189a1cef3fd0fa070310d7e50f74dedc0ea8cba3de75f2dc294bdda0b50a5fbdeaa3e8d94adef2d7287e6f3e1fd4b3a400e483cb30d6d9040dba986926b2b0cb40a421e5dcf761ab40a685ae71bc6aed7f92cb27a421fad107aaa6440cc46140537f7a76376b34f7decfd99e8182fd94962a677c3c7c749943472cfe994148a54da87aab7a9bd9ebb7ac2597fff1e86fb456e8205ad7b7abd3edbe2af8c9058e2ee6bea308775b57acc96d3e0215fe6cd3517593e7225358cbd1f1b3df1e8959e3363e9660d661d5ffedb31b6f4decb97d5d325fa858508bdcf3ffa3beb3596e0675e090556e897db18849ee3f1ccff069d7193afbf39d0e178c499a1b8a09aea1dcc19953aa802c92f52eb75058b9f04c0e36cd454d84b2f02771a27c58b262cae3550ba1f95b64dc7ad558c5f0b857f339e9778013d796d29f90348bf91408713e594af32a30564077bf321e4a7faed4ad3faa9b341c4cd973a6da7cfa119dc410e87ccda3ee6097fc2eca69b1cb5fb0b1ebae00070bafe032acc36c2392b4bc276a9a1decc57a94d13722fb60d63ab94d2575d76bcbc6cf75f91d5d424a638b54efc153cc8300f7ecb2d439bcd89f244757ae0c387314b4a3e08696761a262eadc1f8fdef7712b394a60bc8e2479b4af25bc6ae5931166e5ca06763557bffff0093d15fbd3aa34e0bf4721440d6fdd4a65b7c0af33218b00c9d2a1bb1c647b22d2ca5dab2a10f5c40ae21dcd26eccf4f17b19a117eeff04c3b99dc7f9552cad899bedaa2df8129a88f03e7a22f6e911ce9f9e78e69a1b98709f74be4ac983ac007e6fa4b089a35ea33b1453f8f4bbd94f0edf26cf66b811d8adce34181eb29c2add8bdffe5b3dbe2b35ec3bf0dd963128642640501285f4514cfdeb894fa25bd51e64a05368d09280a60e16e74e0f1c484ed504bb0e61f7ba2768375942c7b7e2ee6528de72ee78c4306dc2370ec7c37e9cfee372acd786c4b5304afc4a284c5614cfa7e34eef749b66fea6e856b15f0456bb63da741e322d98a22fe2008105877fa20350b6dbeecbcfdabb4302e42411fde48e5043fb7728c0e7045d489da4a0118b875356bab995350397c1bb486e827632990838004e53877bf965235ec7fcdee1b19bf2c1a68258c3b7138a96b1567f559e1946f0b3a383527262845ae0def3af29d3542c57b785cbb99909cf023429ede0ac4d585d043e15a67af4db00bfe60e699dbb4ffb79db698fa437780c290dc0659f6c90b76f3eb88c4707a5407e796c616f0ac12b576ad6195f6c2446dda39d76859986fab4bebcde68b09db1345f634d4f0bac51076cab9f7568ca90e7231a6364e3451c3bf733046473e82f859a47936b46cc87a59b4b9f8b5316df3d3faf634da7c71d0818a704e155549ca151cdc79ed50f32ca347631e4819ea491dffcd70a377ec63f7ae1989e1c03f83a39ab748e7629a405440dd852e0a169612cccbbb00bfeb50b57b4ec26a3da88264f93f70aa298c5133b02dac5e587ac2c26a3d5fd1fd447daccaffe5e0df10721cf3e95ea44398bfc374a12ca2791710d5d4c8a55ca2d9afb5ee6e5d9bfdb3a446a855801254816603631b6094a6d999667fcf0197aa449a9e4b81029ea499f14c8baa9f2c99e6fb2bb1f725ab20c5c2d24ecef10ae1faaa04a4ad758d7f0ded98c934eda9b12789d07343ef1268955756575611e98d0e2ab620ba2a7fdac842423141bf26457b8829c9a68a44af30ade99d205a4eddcc0225da6611f99b86fa7bb8ed756f862938534f60bef578d1d0ea7cd29045bf25a0098b6dac0087d247da87defe5f92a2cbb5d2852a375aa01b61fa06148e4571f01a38804f00b70ace1ff22a140bace5e7ad156e822806f692ae0708d40565589eabb50c1744ae1b60e52d3d39547dcd7ae4f5e66732756ba7acff00358c73deebffb3e3583828317e7b72584b68c990272af0de0d9ed5e759f42b3e107c46fdcf1ed0f72939ec585c1b6af281618ecbcefe2147bdbaf94be92952a29d5dfc6bc0f9b0a0ab0702e4c16a6e9b10a3094750621ca0862cc7371d5f9df533a6903081f833ed56d0dd2f9b91c1dd568ad806bcefa0786f4bb1f712e08468f3625c4f73c7e6295b104cd6c735cceb138adf6fcb4c07b586793682eab14d950f8ca36099e0fab8c08344e91ad2c0a6a0e061ff2bc0329bc349e9b07d1bbbc68a2c8450f8d8323526848f96348f9efb7cb421fe0677015d9343531da36151a0e6211eddeedc017a8f2666f03013a843c7a8a0afb1844c0e71baa393b5ec635dc569639985e8acb40dff5769185befdde14211882726e4d4b24b7b899cc7dee599fe5cd4c8d32319077ce6c832493358fbe03ed72e603bbe5baf69ee1fb612b5a78aa429b0f99030df98ec042c85a88c0a0c1bb9168f67ad4df384b09b33407d14498b0524fc7cd75ddd95ec6e977e5faa8845cd0d18d32fba12b056526b433e1032329fe06c5af2d72d1a4bc96694de4b214375bc764e3da73d74a0eb3ec83595384439fba8e4e78d0dfb029217361463ff83fad3ae9303fc2344b5ce1f776b694e95f511438f28e72016dce46b6f1929df5c931dafc7bd8ffc119376a6adf0eda01679c08f1d7bb31f8dbe552f8777f4682454912b09e3ea83c8f776813a4639bc6bed9b28f185c084656462eaddce47779140231e4f20be934f8dfc9265efbce8374a1ec4df1b76d85ca2a6362dec7a3263577bb04ad0ea6d9fbedeb063fc0bb80b7df61d3695a845ebf221828f0041e76e2a018358ce9f0039b9e53e236944770f2f5fdbc66dc8854c1c3efc49310a3948d4851fe2268eeb744f31512f39b1b8af3754ebef60ec7643aa44adfd73cf46442e1dc9bd7a7ba11633b0cf2cf98801e3a57cd055995f1ba3facc774385197824a588a0a45e6ee197741572ab9f83977ae75a6356643d6ce747a5a2055fdfa21c5365e0d17977d28263ed71d243424f9d185497450872d6647b42a540a1ac1ed021a542d84e76950552dae2a0d9308a38aecd2a58b4f3f09164eaf824c2f82596057e3d6d14efedaa9b6c893f31cbfc1370ec67bc684dbdb54d7d401128e7f56e4e6e8842156ccb7e1dfd39effefed34c86748c9f8834817a7cc0b19046f3cf086ed7308854dfdd2455a8e503b21887972201c75f918e2a767f83e1a26ba866cfeaa3530517fff249cacccbd3c5eda1255c5ee431b27d8b750d4353761b9a42827b284444bd20ae4c748f91ae5b44281992b578c7437d04ce8e809b2e993945abc38d6ff773ee078116f84527b08947e25143da1ed65c54c4f44344b336d8607f17648c706cf65ba9df057ed4814686d2688cc57ad4195001406d128997893174f9017cb3fd152e5bce66f8aa08c2eb53ac4e7e341bf341e1043ac28713db4d6c5012cb4644277a2cacf5d972281010b03ae0f5cba7cfbab280b66cb1b5f82ad4ccc5927b2a5687d1e5a0908628d02a62bcf53acb915e2fcb6d9065951c86842f12af7a07e1dd9eaf8c2b271299024b1fecf84f35f0d2a69f82f0b1aabce6efd4fbde4f45c9e3f4209115bea72e6614cc405b2d5bba70572fa7700e64c43c5b47143c32cd84c19bec5adf810ca1d1dd39887a254f8b16dc7013bb4828800ccddf1ef6580adb342637a46bc2f7b04b1073511853658af2e1af7012bdc574029cd1087f14d863c68645c0f1e4a05e809845774c672f5459d0bd8daff71866fa364bf53d22526c7b1bcc64a835a0ee121051568a874a84c0ce17154986295409b9ff9e5b99841c7198f1b3d9bbe42838c6626a2bfb539cfd1f11e5860f44c96ed4d1457e9d774f2e3eb4d319bb9be796fb5cdee53372f3ef704705628c600846e9338c32582122c97251b3ed8aa0d8f27606b71bb30849af592f5ee8fd873d07cd92e942c9ebecf1b087e4aaf5343ed6a06233e29a3351829d920c6097bba76b0ccad1f8bc04a8937f579f21236f47370e2612ea03509225466fc4039d3a1c4e5e3ad1b105e190e9c48e28f7b590986d70e8f82063c6427a69a09e24ce8a9991c53da695306e461f3c3289f9fe92750ff0f250ba25cbe2bdd558ceb06f9acd2bebab65cf6be5c3d486799137a2b659db3a1d9358cd93695cd33bdf329fa5921afbe739b522538e06bbfa3f144610dea7c5307bb8aa728c09bed4f0cfdd293e5da589729ffc6e28fa3639fd87fe213f245032242a5ce1d79f26a472d573fdfd87cf4bedfa6c021d7b1057b624584a8d2b31f768d88a9f439a9a474c8d61f40356a1aa658564b8741848300c25f4a53bea668cdc44914ece950dd6ba911e70bad4a543dd22c5228b37df8f0684fcdf1da2a45b27f8752ba4cc32f6773feb1c9c623f9082d8b6668d06a58beec040facee02d1ea5834281c5c35d75ebd7b3de2f5004de9e17ed7a7744a1f33a55512a6893b1b7d43559208f9b9b28b02e6e4974dae98b699d3f6d8825571593d704e4482eb3d31335f60fd992cd673702636f9ecf238c9e1871f63e777fc44b5ac39762f4c68e08c22204b56546f70c01f4d1bda33e25b060b5780fa82705729ac05a30fd709d28e31a5f5a04a70adc160c39f769b4d838d416b70eb627444bb0d45abb02ae959e7a03bac62aec2d34c94ca6a909b0c8d3c4cfb3a85131950857c16f2f509a606c5ed049112dac51ee04175fe53965d4f3fd3aa17793d5ba473c57e70001d6092a47bd824aa13a8a99eae2ae8e94d754e972cf18f608cb2f1ecf923add9ea62e19a645777e196876b166637b5820cb47004f8a016096ab2c8100be8305dfab5df0b4dc27ece73fbbfab046c0c6d539180b107ddc824df8050f7292aeaca31733b3dcf2651628f091dd73170692bb87196f7ca2234474f99d8a122518c8c360ff3803d4e439c5fd177a8da1edd99148a36e953804616592056be07178bfa3932c24ac5adf73fc8ccb8e7c9a4b6ac0304a88aba13b6bf7f901dbb19ebd233480ac73876b1126b87a5e5cc6f1e82c9704a2aa70d5e66303d8561920f958d1e532a6d8a51ea14518b467f1a6ac46c2275e8c76ca2a712bbb79c9d19f8309c715341ac02b6a52026321800027b8fe13c7d4d8ba73a7ba0243f184dc7605026026c6da11e0f2991664653f2ff1b3ddb4e01080058daa4d4e98550d97cce7ec59951a38398eca0e81f61a68d5737f50dc2debfde2f79e29c7ddbb7c00f92e3a61f4c52cd14719bc46e8dd318e41ef732ac8d816495b8fc01e6efa6ae5ec70deeb0635b7a8f933ff122b304641a4236c2dbe22ad9303fd05efd619d1571fd509d7c6e74286ff447542049f4954e2307f72b75da3857ab43d5e235227154a0100d817d7d15e2d0b8796581e94c5917d40f15f2be7d03007b150736f9c64077fb22611df2334400731b4f48fcf1472258c03d7a44214517bc1d27f206aa04a584967763dbd13abea391cec1050b204909a34159ce44536baaa65d9e58a4a90a1c090d68b9f602105a27fcc327d4ee17fe3f8d8ee921c547882541c572a48a3b4320cf918fe02aff323e52d29d7cd39e4ebca1539e4824d8c323b6020054d23c7b4899666b2952ef90a97611813d2115b5d2a53e8ac3acff3447578de9d16db1717a42de53f8ae1df335e91a909afe5749316af899180a4b8084e81804a8be9ca82c582c5b935cd50e05507f79461a52bf9d4aa598915b118db9ceef3e73d3de13c38351587367b59a4fbc8044378f31f0b0e017a337892ea51716d57841725e73d1d1021b0150f323d48c7ae57710eabd8c36dd794727ced425f51d4876ea860e85175ae5b6ab1601aff14747e9d21b17ed6063a60ea2667b182d054aaa8f3eb258f62023a16eee90b9a281ada25483c54a62a00b03787239174242b1f13b3359d9c132b7cadde2d8244b5bda8b4e974cc1e4364dd23b55bb378e7092f30419885b3041b6a7ebe76e437c0ceacc75e2e4220fac44af489e4ddba2d729d6156135806ad92ca6f309daee2631a654385ff24f89bc96d03dbfb55237268ee2a9adaa797b05c3ab52cf5091af37878391a487ecdf5c9afda8350f4c0e6fb9831817fcd6e4ad1d6df1e082ad1a43cce4e1bd4bb32753a2512e617f20080e7d1796168fbd68f0d0be7929f77a4aaed904be218eea9806c67f6add23ba9db4b4e146a3e91ff0ff9042915146fef4150acb7239fc537aac15b3aa984f0aabbeca7ab282711b2705dca975a6c0db26c414a44acb2969c13b2dd1e999dd70c5777cce4ddcaefceb6a5f0f3a19ffb032f169a96be8330af8ffdde427ce9e87570d52c527eceb9d801eab8748c2fb7ef887eb5953b418f6c3547eda43d133e20303328a163278e5e54f50061a127381245a9ef02289894eae1685fea855a4d6fca85400217d0b238947279aef9f6bc434d120709dce50cf1ab05fdd2b2ad44e49bd0323b291f0812f1fb18387317bc2741a02f3563b078163b1da6903832cb0018f0516a79b32aaefa3da05276f677261f0e54dff932ae0cc17b3758cdcab24419f5ae464cb44a78d6f6d71fe2f7c87d6998cd1d7e18a0a76202194e373886538418bef6cd2db77378c934fecd9704a6466b0aebe22b8dac95e4f7a0d32c51f8cb61efc893e5bc7cb60b2be2183be9863cb234f5eb653d2775978ffd583d45c33d3cef0764e2e39d069e14d6173cf9fb6f3254c88c0384831ba23bb9e279345c159df4ff7245464f809073be652ffa2c741881f748e4f46b591ee45f0772418994de213a8db0b45977fc2ccd79c4b06e5c7a7f30843a9ad584413dbafb3605d018a65272bbb24520da7d8d03898bbe1f82f4aab051e21bd20f410ad84203a759e8f70d811d25b1ef105bd6bd5db7d24d38d2db42f554bfb3161b7f08d7e0204670a7227391409b12edd285ff40dbdf2fb882eeddd970fe8bc6962343bb1b805d0cb463e132fdc0ea7efe0f66b35bb0a62db087e1363976f5d22c778f69f909e72d4f2ab82a117c7af5d2880a19008812ea3a0287b749d663a6f6afa77ff65dc451addd862ab0e13796165cc5cbcf6a731ee10b9a4535746adcfec03c8d025a8ecd143b03c3860ac6fe5f97b15f68431ffb2fbaf50b80c9914efd44bc07e7f2d66095517ea3eb3ce984f1cc45bc67629706e9b82093dfce6219606f847e0f67fdecc779a53c114748543acc796886dd4398648019b336b11c2ebf25a082e15f0e34949e060964df70b8f02c077b520141f13d73da8ff89e32545eea6629834b9f463201f9ac24cbe69699517398635355f1ac0170f123f7d15c678d9e59c2a421521d6e01833973f8ca2c701b5523318bd2e898a76cebb1c703c7c9aeabde4a014f9119710e27f85acad34f1126884b66f634ef86b440d3960055292e9138e20258228d684f9e3761d2706a31d7a271b877ab314426cf130938573f55b83045f9f1fc2966dce2e4cd516dc4804853dd211f38ee0764840e3f09701e03ec2947bf10db9394488f39985af01e6a0237d02a6fbb7865008e86adb841da3420454e2a324ba6cf9bfd2d63c3fd57fbd599dc7574fafe16275d16484879f00e5ef702f4a90078244f524f981e600039765953be5e3e35d39c29582bc75f954769d9f0e3833f269a9f925a4b9831e7ea730ce34b3f2303bea7a173e9a2666078273b8a1d178c35de23e76281204682b4158b442a3ae7450eb99527325a2b56925d3b46e32044197d5a988a73bdda7b04aa2e05b00e37d1bc2b30ac91830435f123cf715b2d98dedde79feac544ee1dc4db9258f76d124739246ed51bef37a446cc8fdacd01fc61716d77723464a8bddb7c33a608adc1335683c6af2fa1192c20700cec1d128cf0ee92615799f1886a5417dcee7af25f051d73b8030e82b4f1034fb21b5673079afcaca4896d54e63b7fb041bcaafe7b298c0a445b4c53c32f007d24f38006a52299c6db637a67f338db25a019e28c9ff5368933541f45e6a4d76177edc8af72b2b5589b2b14efc5bef4a1fdff4ec34537d4c3a89366982abd79db9430117fb66c047e00acc8705cc8e67925675e6b1d47d57141d9b46ab50073cbe414384c91e434c98083c9aa74fd5adb087dc828cecb2d98c0b904352a6bf07902d6cb5d622b1aa2e690fb837a1580c389178d2edd8cff3200f5deb02ac444eb3104c2b3298e0c7ad9f792cf548fd52bbd6ce24318142ef7c5fb46ff50798fb3e9c6f649336523c39d2d2f5f39f543d3da45f9e7806166986f1fe7e4db821276f9a165f7f495aad0780be7c762a54ece809cb0f60907736c3984aecfb62f94bb85371824f2bd5c9293297beed5fa0535349b184b4866a98229d9877b0c425548512c45eeb54509f629e133fe62513a167df8657cfcc3d52916024637248c8cabf1a273ce0450b97b99667d20cc9a92c5be97d3cb138010e31690a618ecedd5204a505b40c44f37798f3e875311e0c87d1d4eb2b3825ea1030e1468d950ff0c7fdc7158879f166cbb310dd54c27e400d278c96f8b319be6af09a1afba2fb934fb095ed0a7c36615284965ca6bf00837528a30c456b848466c65fd97c3cd655ee921d8ffbe09b7039aab9f23795f2b1505f3ad81dfbfeb84e58985937de4e88b96669e0359a08787ba90fa8c3d8bb3ab18265509c55e8b7c0d4d31316b7ecb94b6b882ab69e9fe560b0c0732fdf3f0f1e4322e73abc9702f90c237ed4fa268a523e19c38d2414a50edc0a2201730534b72e5645d2370f870a19920a06b6a999515b15453ea47e0dd3cb8894efc301d522b4b6c3d2b263da8558469908063ae75ed87fd4406fc00e6ff4ad811d06824701ed07881f573fbc97b4ec9168c45e33e6f95af7acf6779e891f3f2dd88402e75b1f5aa338bd6dac72d33a7ec316bdaa1084e6312ea6ddd4598aa0cd7b0f2ecc9ead11f6cc585741eb62fef92bbe41403b257da26fe078b895cdb269f00e79ac90c0398289c66a31c4f9f23af832f8c7fa8eadac4b3d890421b30ed5b9863187d60185a7da1533d5b0517c1d7b7b774f804de8424304ceab3589aea972ef9bd5db6a654aa54f9d6f405dc71ba75c6ac918daebb910c73f21c68e31cb657ae41f388a510c8ff1d7c632c7a5de774df29b1448f2f3166adbbfd44f55618519fcf71470b972e303c36cb8805da7e52985002b5b2f92e79a56335b767023cd823966a7d3b1f7541cae19044288716d8913b03ff9f7e2997b58c6730e1c0ec8ebeb50e9337a8706ef87fe149cd7238e233270a4cfd9b3b9218e561dafd428a0c0d8f8a93f6d7a9f1e487db114b0079f4b358393a57e49354e13804eb5c7d3ac8a2c79f4de6f45c753d84bf783b70d88454fcd763bc9b0437d188f56b6a0087ee68b70c643e5c67cb6e642f1e90cd278adad1a3a81f2ef928beccebaadbf8308d2582331bcae00d0761e7edf50336ac3b82d45506db8135e42b7da30020facd9c66ed01b701544c95e2007b928887f8ecf452b8e7d218af5b99d4a2c5543eacaeb0638156e7e28f8bdbf50261c6d95eb0eeb3b12ba738d4efbfa5016efcd4aefbc89cd56bf7c83333af47a7fb7a9d4adb84cfcab8e9a23f3014476c3deefb0018f2c9318589463b0fded8b6dd4ec8d090ff42e8a662a452ba36f8871dcd994cd4325a3ea39458b0a7c345c64e83346a6b4bdbcd28bcabf62df4e99fa0061a57ae6c1633aed3cdcb3280ac5b404b5dd1bdf3b173ff54633ea02f66a227e0b3ff4919709b2e159bb02c7700a77ce18054db319d5c909a8c00aedefeb44fc3758ddb443c445a4b18ae7720ea6714f483d9e09680234921769135f7d8520ab2e60b0cffac89e50664c712b69fc8d73b1470825280a178275401715fe9e88682344545b4249ec6d870d9f4e8972511d5a75543d278c517885769feb1e7eddc1bcc8e15dc9769285bcb0d0ee8250497bfe609f32a57617548158f52a197a105d6e3e8666960e99f78efb73fc57565385119e92dd9f87fdeba9eb08056483ae02e1d67516e6b1a3519203d2253b4e7e20541290af88b21a716659015d154bb9a2fbff958b1e4c80b9e3126503981382ed8fb1d1ca2909e7819b48f3c581a7d44815a53f43def4889dd68e320bd87e2c5c502b94756bc34a8224b580c02633ada2b1d708b55f0d317c4759691bc427a76a224d1dbdf0f3ba2a5d81caecc734ed2289bc6f45d6cca48ea2717e44443974989698775e93f0a6c8218142e280192b080694a4854661e700b6349cb1cfa70878d44a6d32e9f12b4688544c045081ff1b25471aa4cd63af6974d94a6ca97d76ea2f4706ad2ec8220b3758ab9caa08815d6bdea9ad9893b2e46f212e6960907013039568a71cc16d17082180177a6703f87418793443a864ceb662b32559841b43dabc801786866f3d96227d1c58541a5bc290d92aa2416f1029fe4255dffb7539eeba2a8b5877b72105dc9161c65e36f6b95bd4f3533962c6bc9bb43e496cf56fe298cd68705cb2dd9ab56c1b3489fc2fa84dfa2b6d6678b5898e1dd16a7bfb69267474a120872c621d41fc4e51708b2263ec5b86d6a70452da099cc3f321738ec4c9782d677ac2c9a8b2c17a8c2e481b812399af85fed93378e9b84dfcf538454ad6d85e4641716976a88057f1bcd7ea84890fc57a0368d109094472b1ff7fdf5ee495064d77ddede03fb3f3d28b666fcae1ab779affc982d7dc98b88a1a3c62d662d62f65686cf029a29b6ae046f19f782863ccc0ff2ca90559c4564c247bc654bae51b6d28456aff9ce35a135bdc5885bab0aa959d300560b3fb2be11a9d1f18499fab682f4b59daf4ec21a17bd31cc946fbb2a0a7f75ab711aec2cc4d4c40aebe49549fa81a695381ff72eeb434e5447ca2d70fdbf3029da6e82ed8cafe7b96e7584778a61ba2751991fdc5207535f870152f261cbce7a2b1a8015d94f8ac2f31f9a11359c7c247ff717eebe4bdc0ecd0818c64b8a61431329c2a85233c29e5ccd9a79ddf548ea39a3b1ebe07e26402d52c51e926927992cdde352dadf71cddf5fb9426c24c0f314d026625dfadcb96791cedaeac8421f1024c962e4275919c02121d9b8e316950efe8882855ab852388e2b814f87f4845499547c1ce33c4630a33c31d4f7dd8435e62099f3663a3da757c5875239e883f9b7452edc771eec26972e363152922d398d0b315f22be3160d623eddd709c6c441434f4ead9521a0ff3dab0436f97ff9b234eed4f580879eb38100d81891170f73936dba7d2a1749211772b82910eb6465f4a0cdc28194a88b6acd063adb7b49b32e04b7b06f6b4e2eda99f92f0057b4072f0d8ee19276d902cbd7d3ec9e7ebc91af29e57c1474815b2c58f8c2fb6069d09aa8dbfb7db60ead948e00178bcd982ccde625609789cbd478345624a24a4825bffc0a10cd345cdf519d8e20e34586c8f9d2ee67ed5ff049d5703004f94f9379226fa50da309e5ea774374802792095752d9ca584f454a66d6957771b997aedd2225a62182134d1dc62075bd88527baf8feb516fa06b481ee1a64c51707acc8c742c9e66daf984e41d6ad42febad90a0749ac52657b89bd452a98c502ec37ed0dac62e37ff441a665fca18d5e256121feea80fad1913993437115ecc678f7d3a7d0229c7918a6bfe5538c780d2053c81b9a88a23bc6172bc61e7348d197aa4968a688918ed9db3cc859fc0b905e9b411a9841b547e5cad23d6a5c21b748768d2cac806c12c6c6c28941e04861b0f476a7a9d880cda30d75c7fd9ca04cd3d8dfcdea2bb732a54c730c914a2f2f12ce0092eba2b90e178b008cbc8a0a7c11b3669709ef0b891ecfa5a2dc48e55ef05f1ab581a576f6d9b7ff3442b2575371993ebb3d6faa399c804889718bdff46c8ffba4a87430a918fbeefdd286dd1e6f66e5c2fadc646ceaa35f081972c23ca0a3493364696441ef182c02ae97087299518c6d29c650afb31cbab25d7908b57f90bd5e4c79aff02aaffafebeb6539a91535eaeeba8cc2722a89e115b830ed2b8b9fc09f86852802d941556bed0d26b3c3addb8da7c121f6119e7f82e68e530dd3e1deb6a5263dc74a06d2e14f1179d4a0979e9a70077a3b2887a38d6d9f3dd40c5c0e1d5f20a152cd131f27e089fa970ed6678e7d923e3e34d5b3605af14a83bcb0d7bfe8841b1c577d52a36781a5d748eb8ffbab2fe322c82a1f8d0655d59839d310860fb6f95f7b974259206318996b1bd36ff9d03198bdb96554f5eea5eb162c076e5e98dfd199530cf0a0313a609669e5d2c631c60331c533a0fe92e877a6ed4e013a6301a516b12561c9855b0968876a366d161464dce661784a27c1c577c02c807e2333ef9a0844895902276cf0bdfe9ece0d0db70889e36945d137e3abd5c034d3da9708fc04dcef455e5f179f334f36b1764fcd590f14840b38bea4531d7efa78bcd1e4a55770934162ba576588ceb77b29bf703f2aecf67abba4529cd9df2c58bc31eb413c34688a10bb38a27584420d35608335be326bb9e448939b44b9052a6bbb524afd36c2dc17ebd7bb123d252db257ce3599aaf4cc0a51de7a16d9849457c22f413cff966a738b97e4f3c6c3b6e59a66ed8a09f317b56f46a873705db2de949f3c1a68ea2ec751678b4f7cc95b03b00d1f502bae3f5fd64b1d431df10d1865d40ee833451b51e57c63b6e9a3ff2d44d250ed5a8f012f98a8e11e865055de6bdd6b4687ab97a7aa1871a102e5a09d1ed533e99d2cfa98147d1709062ba7a1e07af366cacf85540230fd51be60e23754544677628b076bc2efc41e8e5cf2bf39456999e67e2fa2408b82c7b603046ba6e358d93f11ea01f9585a0e1f2c57b59c9f9d5dd5c2cf9a190fa1ea97e4513935c2eb7bad81eef78a49df89c379ae66e90d2175ff40620c16acb39012719b679e8e1a49ff60c06a7e7b1bbd125fa8fed05387bc0bba633f9a293c344716fcade34bc3ae8c1cc0e592b0786c0b7c7580b11d1702d2a28099ce77158006679747fe84d98a0c4ef9095de2d4cf4bb7367e72aadc4a18e618f5b88b860801f5a5fb3ae4f5aae71d060a552cde06e7c30425a9888e19aa20c08e591e1c2d2381af57f0a4a33975f8514450ce732521cbdd161ebeed8e66e50ebb34746dbd6d95a5457329bcb19d0003a81babbe5e56e3f77fe99ded47ef68d048338f59fd2937b5accdb1963900f01bf0ddb48ead97670a025758506c1b0f617ceba9e345628bf0746eee915102f9de5ec70ade59e4461b36c47d3ee0eb746d2b948406dc28efa35b3af839be509243a8cea2d4568d86c9a885e1173b7226bd145e1466508e6919588cfd4083b2abeff319b5a3fd6184315e0",
    isRememberEnabled: true,
    rememberDurationInDays: 7,
    staticryptSaltUniqueVariableName: "65d04238902f8cd8da8c503075b294a7",
  };

// you can edit these values to customize some of the behavior of StatiCrypt
const templateConfig = {
  rememberExpirationKey: "staticrypt_expiration",
  rememberPassphraseKey: "staticrypt_passphrase",
  replaceHtmlCallback: null,
  clearLocalStorageCallback: null,
};

// init the staticrypt engine
const staticrypt = staticryptInitiator.init(staticryptConfig, templateConfig);

// try to automatically decrypt on load if there is a saved password
window.onload = async function () {
  const { isSuccessful } = await staticrypt.handleDecryptOnLoad();

  // if we didn't decrypt anything on load, show the password prompt. Otherwise the content has already been
  // replaced, no need to do anything
  if (!isSuccessful) {
    // hide loading screen
    document.getElementById("staticrypt_loading").classList.add("hidden");
    document.getElementById("staticrypt_content").classList.remove("hidden");
  }
};

// handle password form submission
document
  .getElementById("staticrypt-form")
  .addEventListener("submit", async function (e) {
    e.preventDefault();

    const password = document.getElementById("staticrypt-password").value;

    const { isSuccessful } = await staticrypt.handleDecryptionOfPage(password);

    if (!isSuccessful) {
      document
        .getElementById("staticrypt-failed-login")
        .classList.remove("hidden");
      document.getElementById("staticrypt-password").value = "";
    }
  });
