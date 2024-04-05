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
      "f53865ada2c4f4fd65a263bdb50a3f18b8669dd0dfb727673cf8bad417848e330ee49a90c46fc663eb8f7f01ef1d8f92566cd9891aad16c0d77c57059f375bca59be6186aea218d61961a48c709d986893d054354e2577d83f2351a68c7b5493389167efba069b4becbe843dcad4fd394994468e447b3815e32d243afde3ff5c7f1fee7ede7f6dbe765d2b63504c7abb85c086b8afd35ad92ad3a1ba84e4891dc717d9ecea99759a0677ddb0f401da7f5f707e1cc1b74c6c0b0fcd1fcd1685fd8e88b9b3aa7dfa856bb815f0fd8f0faa06171bef5de0a26bcd0b348636ae22877d421b4c16449327cdc5610af996e9c21507f9aa797ae54adc3d5f4985fdb3934a2e163f4ab5344d2bcdebc966e422892cc3b752d96dd01830afc1c94aa8d28ee23decd4233ed7f0407c2701b38623190338c919751106ecd3ec68f51bb61d66b22c9a15a4ee2c623c41c972ed825f864002d144dbcb13329422582027a8e2c6147dfd4263e11699df064b2d4af87c1b587c616f5fa3e947299d5e6636b805674dfcfb68bf7ccce955982adcd0484c1eb1d01ee07fa47588bb55865799ea7932d7a361986cd6ba53cbf595980ab5139ee53f83a734bb45a7d4b70d7d0de6c719bb431000e1149cba70b28330fcb040bd643a0a88b447933122eeb9a0f71defbc8b6d9f51f57e7316e97d1c9fb43c44da88c2126730e8df17d497eaa5221c4c97aab46a6951e14eb55030c49941878b8372051637ed8517c8c5628cee649a94ec3d92c1bf1f118806044a333605f61ac58a956c6763e7ab3cbe51ba259fb2ecd6fc1189293d01264e9636de953f6290ca22ce9f7ed482954830026ad8ac95af68115d553961b222cd613473d5ccbeafbb0ce4084ce3669b7240301e24e3d2b8264c6eb3cd3133999b921d2510c7dfda57ff5ce4d0f26feb013f1365f37801b05ae3193a3dfda13e15bd0784c13c51b298728deadb42e2d31a855b489dae9dd52a0f1265a1a93b76eef8631ca00779c692eafd92034ddea1242c48a887021c71b2bc134a6666509ae8dcc6dd837da2679df1fcb9e4e9bc1f042729064d04b014ea2e7ee8e83187214bf9301bfe571d0803ebfb40e34de2d8b34bcb70dd1e5cc80291d08577880f3a04a0d17553313877a3a9ffe5c6a1c6d77e081269a66cead03a402123aeccd4a5f3f9e5e467f03c9b924cbed86ff2f3c08a314ad0a75f09c7cc0fbe9812c053184a509490e3617212bf1d632688fae75b8f541e76405708571b3048ce229076befceb399a7d286f1adfde948a47d1af2d69cb3dff6a4ae12ff2e3c2230c614aab1c0be8d97b442c766fc7536cec81a35f5bde9fa8cd993ca90a0d39d60edafd91a9c217dc4ab6d3b2ded1212ebc07517c4fdc28340efdfd6ec8acda42eab674d7269d48e1dad3d1799c00794525a9dc8c6396cf719e7f7f59ae44b44040d2a9406e93998f5b0155d6f8ccd91e553b11de3be14e904e16c57429c9e3e20861e730546fe90aba627ea478f62e0518c3819287324b1fc1733b0c0f7b8fb9785bf5ec51c0c7c54b13a6f94ec57fb4a73f47e551a800a65740300e5e2f415611c4b3a18b7a709336b83e6e54cb6a7e078ae71c9bbf5a87f34a78613f5038b4d8358a32a8911308d3f58ad3bab9b9f0495a29aed5e22afa4cfae648b309a8271174a1a8f67e899df710499cb9a2b9842c8e283adc7593d2d66a7586168bb1b5237aec060723ff101fd87a9cae4e4a74715bbbf4ba7b9d7379912baf54134ecea63f155fe4780e817bfba8d91d21fab1586b4723d503ae11c80f3440aac4908f5a8c8a9522eee766e5b16301964fdf5f4dd7767a98cdcf6942100b79041b4b2748c1ef682ee1b30f52b71b39cb9f75a16715e02361e2ebf8d115109b56df4f2f25bd8d2c0c9c7e22125add2109b637258a6ac87c05a28e5f0d2fe67e9bd6233ac431cf3e4ce828e0a847bb6c34b6f10e54ceda61f5c08e338a49d6cf48c624108d3981ec8d1ecf9f9673123b6df67331626344a020c78b0e3765d155a297dd2780942840c5f5f00be7813e2a5e24b5860604ad7983bc4e922c2b4dd41eefdcecb1e6f8b198a1e20fec5a36c370be2225680a80c7bc9e1550743878489f93e39408455e31efcd27079c9c5b4c1d726e933996f083387806fd2a41b9772e0312edb2abc168ea1f99e90fcb25427b733e9c671f927a8d586fb64076ac8c49276a23568b4276132acf1115c3555afdbc2faac6c485d972968904997b636cfca84241d60482faaea401616616feb7d3ec24ef1773593293c8c26ac7ce19ce798ff4d5336dd7506ab363dca441863963acc5ed0f453da4fc841047db9fb725a1657ed5adba000c08cf9d522ecc419628ebea1c74f68ef0519dbdcf10cf2f919be38e774a7bb7aac94a326ce08f6da09785c385230f2991e800450a8805397f472d358b9a246a018ab1164468a902484414653776c988272ffd84600bf1475a9ed7575dc1434740addf0096334d89a77ab4177483c36644b6844abe99ba6b9cda162f1f926b5fb7ad14178550c2f03a2aeaa7af9555708f1432872dbf0bec48ac87edba21d1b0377e7df14b23c858c82d6836d922c6d0a79ef8cd74353bdf5c5ad0537a789195f5d6712bc62c158eb0f3a4a500738891fec784adb565f0658ce0dbe35eb481bc8323387ac50a74d5d0ae5627e92b4d97ab90b4b80ea159d600ecb188ad688ff1b3ca9b5a15114a2c75e9bcd35201d5b2e581634b226439895300ace073e65d1e38544fce32c1a475f7d02ae7e75c6177a46498672f7fd79e50bca534a5f59fabf771941ba8f966c94f7b0c0f60205abc539136f68b27e5b183007a5bd0fd226c2bca7e10723b657f4bda67bd50164349af52b9ad879beb0062a371b374a4ad699e861f1d23234bfaab2f71e5a2a010892338842cc71e4d72cb23bd5a216fddc12720dcfb6a4e9092c65779f58baf050d860bdf3178b5918ab3e3ffba1c9af3af57e47ac199e6d57863fdcfc159aa68f802146b509a18e9b233db7a9d131213e827ba287aecb7f06ad96a9e088a599534a35a20d74a6d2638d0a68a2cb0c5d6ce1d7e7a27acf8d2a5f4c5ef2faaaeac4f40877d9f47550ad1e3c5db5f9a936291ad5bb1e1a39ccce200affc7c0ab335407caa32a8a4cdebf0d4094e1a46337c29290ffcc1eab61f332d1138ecc24b5bcadea14d0f46887f3e70b43d38ef827c35f13c4c8fea7c20c57c61e58e41aa1371bfa688ea45351e97984c07b3f466861c834a9e0cc914147dbb7be64257339b29652b63f40fdf38b8a8e41c2dba4f8799fa8bb2041f4a0d1f85ce683aff176fed3c87c0be69101166f61f4edc6ead905c8e9d573f71cc9bde78036d78a8e3c1a2cbcc77f9cebe29210e8e5ac2f4da21e553bda55cf300c7d52c73801ad2673da77fa956893cc03fd6836b254b8d98a7d4791cfa3a93ed642831a00e9a11f37982f93dc5408f59c2f7acd0a2ab0f26ee5c21370f28d5f3600a93366338760d00d26097eb39cc29dc8feffd3d4b7612c13648e6a928362154c164f00eecde72c80affbf406e6fddc62c0e31a9906ad7e2f6d087e8308fbbcc8ff0c2251d7f896f307e492c093fcefe5794e0659fc30ea86b3fc26488107f9231ee2514885d8a5d8c5b1b0a92714ce0dc68eb8656f08d86cb9ba822b9b3d90bc8c940a34a17df5d61a95a979c653ae1ccc48da8d3376a813d208ef3aa47741ecf61576466e66e0dfb0b6fad25d0682b7de917e3829cecf7e8419aad9973aae5340a4d42b3dd802a25084bda1b91e09a408828b6629535a7f86ba68ceba27d46e345623f4f4d0b2ca8d187903b282a0f25f8f7ad08a0baf5bf88df93226cfe391d81e85910a63303d7e877afe15ac2e1c9b8f4ef35ca8a53febe411d5158cf0c88c6d8aa0465f199a4d4b0537a62f8f3a857ac1a0096b8c20142578936f411e69c6b8abbacd3597a078323ab378a12298330154ae3b519d9869df26b7e84031f50fdb3245ae1623bbb4df39f507bc232cdd6b63771fce23275cad15bb2cb65d26a848b33d7c80dc6438a285858ca215cb691b4a523324dd77152fb44016d0464dd323275ad58f760e86c77a6abb4635d2926b5829e70efd1280e9e653797cdfa5412ffc3c2879d50e98bcd276687857bbee4766fc81a0f5cca249eb12edb4d0b857c26a590c91d254d98c53f586a63621f9235ebf89f7fe1c042f0a4923c413c1715f34b0bb40dfc213c294fe36c81fa478e73bd7fffa6a5e7b431e5e0bc0ea829590753ba655e5a3aceef32f6898a56b6d5e992885081eb01a96565487358253623e8464e4df957e24a57fe41fc41330e798b9cee765e736241b0d1526b7489b4f56c352fd5870dc5b24e0dca7efa8e67d6561229ec6478381007b7aa8910ded0de6b99a8a91cec2d92067b44ceed226a44c989c6f603c49eefcd227160000cd9b109a50febbf7fb71a8ac8a284153f98973b62afc3a829606df7798fb1e9b94bf325c1eca0063ca61bbcc40dacd5b22bf57c1eea9585bcdebf79f4374af15c663714b145a9de524a7cc940429584a79b9c73ffbcf22ec096bc7d61ace57dd036281614d78c0a6fe582f69a31a074d30a1afb5989fa92a1df183d604e5f994a93a1ebeccde3fc8ea96336b62a1f9aa369690026c76ff3b32694a263ba484d09a9553dde07ac09360ba4aede5c292d439835b4b190317f2990f180109e72c4cd83bcd86df0176c3101df74c9d4f012c64b394c6cf81e42ccd2419a11f17857b74fdfbbb98592b9408422c00fa68604c0e93278f15382dc506296a4b413f3faacac0167d7f77d95d11fb2475cd254c3db5a8223f61537844a99dfef2f9025f76a75bd027686d7bf0fe71d2554e8ce224867ecc1c7c6aabbe2304045e393f54577949798087ad96685ee13b67d23dd62303348802ec29fa3f182667c44952e2ea4b55bbe82a29afaaf495181dcecfdbcb37123b09d42643daf55fcd75c71f7ceaea0f928312d6209cb1ec09fb8fa0021d56b26b65fd6d64cdb1b88100e333ce3c174994c489ea1a93d0f7b0cf6a8bd839c06becc4c4f5f0e5a1f98995a5b063c06b5144a8e6b9f6ba90f9d8eef9c15eb1df6c2d97d8426d6a66910ffe063011ca413c1c27492f91d2437442407d108a431550295941a20370b47036d4151d3d5a6f088c1eec5458c965ce00607a5c1a60d081a3792a0570aa0499cfa6d29f00d678d0961b27cb24358abf19e45f7828ba1b197826e36888c96449e346670c5ac24fc4a0091fc4ad529115e41377983a3a848d365fe4d1d4576c8b44eb1dd1f9a7cb89363f3b07324d0f4b01d8d383450af3d0e32862f7f16f1c9410d10bdacd726de462d002d7f5f43c541c7fd93db750577f16b6f2e1c248050e7cb519f9df4b941a0159ac1b819dd03cd605ee39c1bcd35543e79f8e6bd54c0012ac0b35ecbd67340ebed31bafc5d3524c62e1dc54bc1950850843e2456fd96f8fcd5d6cc926508fd84de0dff0148a8fcd8ee5073296373db3f452492b3e4da01fdec04c858f33c79525a0af759694da77124c6c83db8af7530e86fa38e7effd2a3eda0c1f49288c2d3c7f5307277eeead32730216079c9c724665f3af5f84d5a99f67d8b16e3a879c7a45fc9b6ea26bf7cfab6ef7c60ecba050d261b01a318e7d385536adf9921843156480bc13e8543ed46b31ef7999204e3d440f4473100edb2657196979b98f04deac576927cf55a0e6c6248fa535dd805b37abab7eb8056b0f675ab1520ea1d477efcd486ec3caa8e8a6ffb9119a92fbdad3d75b74e0164ed827bfc9068413ce22b3a0ec5ee56c25ee4ae77cc27835a3bed17d2e019e36d9d7cf3fdc1c685c72b174b455e85a6034c2a8438821309800ad0d03d5094e38dc60476295e94e032c9c91b10c4929c11b519382dbc4353392eb6e47c098e06cebb38ab69e71468c9a40166470041119e21e60c8a8b6857dc9fabeab59a20fb0530b2111cb5c5b1ec705cfa83da465c0813ac18808d5e842de8ef5d069ccea8a3e320d681e6ec418f0c5803a5d6dcf395cd1af3ddea4513ccb102b5fdc8c350f9aed3b249cef924466996996318c2c085431119d64024561f9f23425e5f43aab0b3d16891b7043abb1ad5c4decdaa27d2181ab93f33f7679609f479edd873fee4d67b53305b27982349dd318f0794395d5657b6dad95645d54204c85c20204b0d60968b865e2a1fc9290272cc56513a5da9ac05b7b35146b67a35765039bbce8e680d66e1bf063592b8f7945319e80de319581a20e62e5405247980788f3db78f83c52f1311af93d7316d4c15f30717cdb43c0b3fa4b28b92ac5e3d3714da0b08d62218b4606f5d8f40064c6543b1d23ea943abeeeb5314e63eee94901952cd2107238e01c4f40ab9ce8f74e17b229d735f0d672795e89f2a8c89b7a5dd330ca92ad3e2b15bdb29ca68c7e778fdf6f10fd09e08512eeb6f2611c0a0675c058d6ff7bf36bc9561fef9a3a9498444bfe545c44ed1c789d381ac13529df0400c5918164d8f519cda09736ba1a4e8fabbadc6488a7ae01f488a6fc75e2a06ae58aa1fccea9673b9d86049168d6149d8e9ed3aea189d46e840aa44db3d239f57bc5a364b9b09573709183bf9286a5f600ad13adf90503e3a33c53508af15641f67f5f0f8edaf4294f6885fee8a60903f7bfbbcf7bd3f29f49c4ade1ea743671ae4946313374f2ec63839cc928b27f5450242e626c9dc0ff3d200a54040cc7379ff706877be801558d0de5085be7d03f76f07769e20c32a5cd79753673da8b5be2ff30b81c0780d6996eb75f1979b54dba7135dd721ddfc685701ae0fa1077bef16299f727d1dd2b3e139468496f31dde9c02556e8c88c258f072a98f135303ad6e175458d5029bbd2957523186672d6eb260d028b1f20e44b2ea7ec81143f367fc135c4294d34c107d5a911e19ff6136e39e0702d2702f159eeff9593666592a6843349b753559937725eca666a54eb3eb5b9d3f2940f8329a767472e814344a7a35e18ae03e72b512949e9e80f32abe369dd7700f63cfe27089ad7d42dca7c3f8fb27e66fbf35769143b7288baa3d7c80b2623abfe15c2ee10ea203efe1d8d256de6b961d7027ccb9031c0dd650aa92a0174fb8664ef208ccbc07669a6d222bc891f85978abe624515adf37d3e94bf0564bdd367d42cfe30a31b42b15c7b75bae07319c87953f244b087f6bd609ac2f215a28eddc6b93794736b47a3b69827852fbe99a37dd5e91048db04d644fd3f65a6fdf6bfa1cffa51ea683d32ceebf9d5bd9e38472b42b87d47c1f04ec267de0048b8993f6264378b73e103b390416120ca9de50bfe2925c7ce6d23ea30a68a6c031ff43baf36f6c8daae4c468c5fa0702be2acdc051436151d06850be067398ee1669cbe3c3144db4192aa424bd93fd61f24142048bd2d6e04fc366a62eac5195db05ec5e0214e5dfc96ab57042168f6c8d37f2fa9860011405ee05cc6062685e815df334c1bc88b102d34ed7b838d68058b6575536845e558db5832fcceac3d04439a9c746d2e8acf709733e6e28a1bf6bbc039177f3d2d1d54cb74c3a0a134828dc05a0170c5bc1cb2fe5422ef3ef5b33edfa390084b0a8f0142c902f9e1d25bb5cb732660fca58ed3c3fb6820a3fcc163f2f4b70b7c18fdf586e123420a70da5f1bd9f49ab35f8407a6593caa4cc6d0fda981ec7a636d49bc7f1eea53012a2394bf7cebd15b2c548576c20f4015f12a3446cd5f4f6e67c46e92a44ec75a9ee25ebb29f36cb380f2cff232cb8e812b4e64a144bc7815c2de3af306853bc0585db367a38c286e275dce13f4a5c7e9ac55ffa6b593c34ff24946a5982e70970adaefcf776127127af867474801f6a75d571049379e9d0ccae2ea07ed6a8cac19b8ea08f26cf740a6b4fb038f7978ccbbd504e25a38d71cb19feacccc97a74c9e9a5cedc0aad3cbe6bfbc7e74a364a8b141a1aa1e1dc8c7912e444be34d680893be50735a76f88a8189037d451e4f26faff80e865472786c81c10de7c64fab812c655bdcde72b6d2f78b314cf1a4cbc4e060d44f012756d141702dd57784507171cfed40d4cf24feca20c06d4ddbeec1f7226176f76a77fed463714d1319b49e120e5a067b92e123171dcc88fc37c96a16fd384206ef3cebb7aab57b8255e4c91d5bce8f346c6ed66f62c30edda8cc29aaf6d73b5f50bce4ccce5b9de5befe2ddd5a994894728c01a0127e66eb74faa935f014ea090a70a8ff7aabd0838b6bb7885f8bb4507d30761ffeb459dd26d36d1ad8db7a73e267389f35b00603b7ad2d38fed583c4a03f433e6011f99ab3935bef6ffe505928fef7a3ccf439870119328735447b25a2ee3ae21e86e592cbc0d395a358d710e901a5b50b2a0500998e7969748841c01cb6dee72794edcb1cc3d4d7bd6c1d5d9d73c8bc8da3eaca59e9d4cf59f8b2efab69d0251d45246466722c6688fc8783a0de742e55717dd85aa7b0aba8935c7b50df7729d9e311e8be5063c461f8143ddaeec98a3b2a252ed828614f174b75d2dda7abfdb44de85288d448ac839bcccf53d8b1f5ce10e04b4ded55a278222946e9f1e3c4ba0eb6f581d31230bd6be8ca16d33c0ac4a9e2417b73a1158fe6ad54b74d96dbb11c59671165f5a292447bf8a0c62a43f5b538d2c0644298812b911ee35a799543c3998221e829cf5cd1ecc94153397b23d77aa86def8de9715fc3f26bd644c08904b836a758aee2516155f6332fba4d3dbe182a9602e3f41748e93ad68365f283303d07db9c029c04f15611710d02d74d15b0b6be7f61c1e21959f031574f3046ed306d908d7fa60e07030b4790e0971bf9290616c56b9072ca7cb12760bb2a413571cd4d2352385a38a3b54d7dda6d36887b140d58e30c51878d6afd24649c8d77d21c4a14955077dc84607accb53cdc461a4c4cec938572b1a192f556cac3aa5db0f524da2821c656103e6a666d55cc702bcddb602dbfcbd140ca92e1914ede809d846a4efac33db045b922bf076978ffceaf7004845d4bc6883c172e9f70a655693fe492b38df725cd1523c710a6a9823647a16623adaa49f8b69948dce7c36d9f73ee492612cf64d23ee0bdfd9bbec57e59b565d3954e754a42d674656a2c12a6acf0c282ebc177aed0297a9ccc91c6f449f213917bbdb9a96d9932bc0434cb28cd12c3726e88958e3e0d27148596ffdd54b459e5f49ae74adc2369210c35ea93cbecf843be01a4438cac1b49db6db1ea35b6f6d52248c4519e5ace7a738ce52c067d6bfb9767a49882a9edf4c6f13d5a4a3c4754b532b58924bd3698421e3104adaabb9edbedae7a0d4f99fc9ef29ae3121d674a53df4db1fd086a3ee3fce47d894c805bdb53ab6d87afed991cc56d209d96bcd1cd7f3fe2ce6c186d67f342a7100d75262505f84c135e45c57d1eb52332ef0ef40a4fd4c41d57012d5a56e8fd180829508e9e1957890dd29410cc4cb3d8d76d352ac1d2cafce9d1e904f59d0399eedaaf8826e018fdc8bf8ee4ab9337e513c9e1b2e6fa06452f455907167f466e9e82461e28e6c00abdf4463c34ff68f7ceb310cd0d9695c60c4714a39f27393c11166c79c04d586067a8c00748dd6f606982ac39264f6a255161937a96a2e888a98bca09dcdbd8263561faf62455dcd34877387e3c04bbe64dcb1e32cf9e076e4cf95f3952e594a476a57999a50b789fbbd99b9789dfdec90aa93b7719edf6a293af7dfb031a69f34f9767a44ac70ab6238e60d7c6378e180b7f821d6d05baf46ed8f9f76f692aaeefe2b721d4c76c6eb70d08e33f4040504f8c2579f7233387cd80d667a743f437a8cd9854a1c05fe2d11585147b58d1d73b50b62ecda405a0a0aa3e065c48e1632a35a8901c27bdb9109036faa1fb9e73d4da70589809fc2ebfdcd509686f3508711f99a188b2777dec7fbdd715aafdc3f2ae79ba9170885ccfe7e9552b0a1694a4fcc031b22d3df9439ac7627154694fe9148d30e9d494e79133c8ce5bb8dbbefb89376dbb45c63e14326e9a9764d948893a72a270577100b0b7e3cd04c471fff8bd2e76e636a6aaff3d980d69b7bae9cd51de2e9b1e93bda5189f0c481c26ef2ea61a3409161bd159c6254f546dff5595a2e71a465ca68aca91cc6fd93463ce9085a41a2af75df626a0d665bc4dd4c50c5af40b8f7953d05e89a52a77b9cb7d916a61909bc8d26aecfe6fa5d956ec84b86feeacd863fd7b7378d9faa7437c91d12b9b806ef3bd3db167e331e0660c42184358cd91eb79ab8369270c867fd9a6f2064e44fa148db1c7e106ef3ae841656806eedfccf4ac8fb54b68b5381bb278fd56b351f4b2a9845f315b99191cdd4d3ee6b311378fe8ec16e4d25787f44036d6eecc6fb0032301566aa9d6af06e94535fafc9d4d4ea7cf26b59d43821283090b9051c776ff2d147ae25855cf6c0d49cebbdf73056270e52d7203a93f03b61e18061368e30676686f0918c7da75e7877cc44347d91730c0cf7786f9ec5fd13536352daf8aadfc70fe44f0eeb5270b41b7e7261c97ad367998def670fac935ec72a3e0f873ee85f0ae441055d13c7f06ce9644e420f7381e4636febfa07fb2b31b3dc061d3e4d3d2eadf42b812c05e9382a0b233c2206e15a78a90726514e973df20892e7b75379c1cc3adb5944e390a5927cabdb2e5a481e57b2bb7edd2f634027b963ee1d2270763d5907a34bb049bf6d8a5be85a96eb2e5ee33838b5c44ae0a36c57eb90152a0774eba05d2cabb84404ea37744460d8d22d8c8ce2cb10afed7dd0b8a47bcc074fe826cc6c736df47421fbc014cd76544bdbe377db8856a9e7e10ff1ab7bfd6dde0fb9f2a2fbd3cec12a63ef3dd1dad702d1e76cedc6f53f90d259728af4bbdaffca3bd5350e534fb62d51946599a0c375047fcfde072b2936b31c80f049ea9743178be7ea4ed62114854f6cba1bd5467a82c345d85782ed4bb3eade6f5931d2c9de48e3d0472434ac6a6d4ab1670adff5e82e88dbce92a9aa5dfc0970483541f70ffb2d69fdec3cd4ae6ca4685874dd479522e3090eb608a7b5524bfad37f7ee63af4fa8783b051a3965b4d8af54aec54f5674173f1a00c06477f5b9ff1c84395885984d33438689b4fc2e27c8689d13a176ef278eb760ab37ae7509084b9fc4f23d95a89802b5a10fbcd98c08eb37f393efd96e6e9d6c9830d9651f1dcea421dcf48d96df272a89a5d88586c4114ff6576ba162e0935c1b19c7ae260d2101390cfa6258160138a02a427773d883de75437b1e2c8fb6a9955f47193bdc50fe85ab877dbe398c69af6820f7d9a7b2876676a00c8aee957fef04a0a5ebad3e80e2fae80595602a6244331de93faad31bff75ea90da0bfdef0709a36a3ec5e54c2a27fef9c2c989dfa448f08afe7733fbfa2cd697102cf342e026d595e70bb41c4ec397927c0b8d9a2d29d0f61a6df7cd1897c183b8a7077d8bffc5709169949af5193141589f048d24bc2321a229cb65548e7294a9b5f255e00baaaecea156bde2da8d944dc7dbabc893815757be8e3e6b0ad0e60ec3dafc600fac94a1a7c50c2f85bd935c1b5ee20d9d8b172899caee69be83aff69963a562b95a56ac51c8b5c77f97f38035581f89958031eba111c33f92ba19efbd4374ae2450d727f4d22e58cdd5aee27945e87688a6952af20eb88d946dc3bab8e6d54b3f29c9382ab537f53904f49983bef4990d44460e40d99b60314edffb36f4d8924fccb0f7a540d2ab70e3487fc35271473dccc978cab4d6506d4fdc1a06619049aad23ce7d25b69074f34e55745ee97f17d7af0b99b88ae72c08bf8515729a01cfb47ec238f2687bf041201b1d583f25e07a531a67f03852993eb07bcda70499123f2939c64c58b56e1bff64c3dadd643ad777ba99bbf5799e6a0ebf9d7c2c6efc0b177383016c9379e5bf89b0381a44003606ef0b1e4ab6fbfd2365549445bdbf7153fc72957fb1da23e4ff1570285bad5e6773549b16c511e03685b9c4e35f6fef72082725bc378bb097207d82d73aac42bd4c45354ac0cb04988bc04c639af9af710fa0979026512b1b133aa20607320dbb16266ed633affad10a7c7e4e551b0fc889590761eadb9d557dcf86ebc46365b9655c494bdc7594aabc5094d0ce71e18a3647fdfd4edc1a2ffd44049d00029daae2aa51931db29c0e3a14b3c88d24f3d5d01427efc369ce65317399f730eba85a9fbf141c651d8da904ff68e4ff79d8a3e2801cbafcd726a38cc7de54f077118361dacb72f665beb2bd1ec06ec2a11ade1f60c875829e8d414e633afd53f2429769e275b04346c8a4ce7d8e58122f74689740b912a3339f074f49771a63c4f615bc5789e4be776ab7f1566d564a122c0d6361d40a79b951713e14c8fdec18f267076d4bd5d0bc48dad8a401d1735695c054cfedd5572d5a475ce286caffd7764c2b979fffe14a87b19004300807779314afe2cdbecfb50be990ca28d49c60280246a60b48a8c6b3ac955e6f61f3cf2fe9f798f37a387c7f2e200c11385d44ecbf6409f1ba1adc626af0efddc876d286f4164c61ab5cf91eff7860700939fc11da18aea7d06146eed4aca14377454ffab2479412678034b5b9a0ee5b3a998f6d7920fc86425d0ba3c0399c7e57bec9952e3f828188751146487a5c797d2fba725c0b53fffceccf255f3a5f40752e25ab3b6ef40600a00276f469fba543c3ad3cfe95d34c64bc50ce821ef445637d380a4f8487088b5a681d00e51ce4bb8e49aa3c0f1ce67a7a618edc92b9841a4d2e32ed9c81d78b2a93d9718c781626f5612b025d45cfe640b35f108800861dcb6ffbdde79f8e5452d7140238561de00d44290709c5f3bbf4963fbac26d1e01764b8f2d4075fb471ed1acb714b99c51b238931e1df892e0da7b1f9a100ef545e8ccf6be51ca203b4c7a046472d04ba752315d3c579a590dbf495e419eeb9e129743942e1a24b21a7007ce00a100e17e1bc61e2c4c2d0018641c439c67035fa379e0ab78f1ea35e0897e2495131ff539442982423749ee7c0543cc4259140da2468001ec9169352c1ab26cf15f4c30c6336b87fd96103a8c7052fa032afc18b942d254844f1f7680a49f70fd97655b9ab4e727f4e7c1c3fcef6fde213a0b80475d2e36015dfa4d9d9871d3c3ad3697ba84154d4c2d7195d8e8dc4ef0dfb0b8599dbbc32a2e3bcb09ca155b38d0f0906ae45f5f8af2c9dee1876904ca2735d11ee1a420fdf06c4a514ec5414b2118c72588652f822f02f94685886baf60c6c82ade993a1f02e6cd7b9a3ef295b413c8b118791ab241a70cc407c82bb7c4449671d9a71bc12c5be0db9b8458dc75a6dc252fb47765a7ea1d15d71ebdb54839d1bbe1e4fe442af84d92a0af946df3f6a986a0c7343b2eb3ffbf760d46e228c67fd36eb63b50906246722d281c163b4f74946263777139a5105c16d5a5b1159d74fca4877ffd9a309578c69628dc14f26e155a66f294fa67da3bddf51d873ab493bc4c06a5b835f056f435609e2a58bc3c08c9d246a6d82c2b42ec07075e4bff424abef46ad49eae2f34ee56933a31eb58bd68bf44064f2720d0bec668b6c1baaed335eb8d03bd9c4ac0941f1a3d99f4af9f52f110be1ddf3cbb0e5b14b9746aec37c23823216741eb780703b8b12fec69e64ccf94509cc036c5e5baaf793ac7c30e790d61e2e19f68ffb0286d929a17f58890e4bbaa2023bf08a56c193e81057a505d21ece3b1872011b997ffae10b57712097ee062bbf688e2806f64a2ee1d0ba20460dd3b5949e9819dfcef8adcccec8263cac55cc89ef5519c485fc90ff1fdb6a253141b41c383ab5d53d717dc8d85c5442142ce09baaa352511ef977096eec4a9594f9e5a9ccc896c0df65d06e2d1b7320bf95f5b6584c1bb673fa334e94827aa6f7f776143bf39ebbb3c5b07594a484d0c0ce6e37061ff7e1ed7cd232c140726a8cee52f51d8ff58799ffadf0bc4574ce9f3bb1397eca67d8410e9a96daf6d186577d673d23d5a36ed9722a622b6d69f5865e9a3e9627445052a488ac486201c004fed9cd51a04e070d57e95d9547d5e4d9238ab841625f40b472a19f180938e42f5cd460a108bd0988ea6d8ff65ae2e5ade40b97f06e489766b30cd36b6044a2e9cd19447295660ca40bd3dbcd1d60a76011c91a5a809013bbeb838d6cba98a5a80aa045ed1220198792cd799e54b52b329e61e6c3132345d59957be816286af67d57487d5606d10868b7fd07c0243f0bff40584b365ff5be3764fbc729b502f4f3157dc96d94a6c4de26079f53bd37e7a6b906d7a66ae1799d0fa180a5aa6aa3fde8cf01669429c52c7ee3f9759fe7014f53d69c0b5ab0da76fbcbab9422f234661a99b19c24e97c4770fd62f9ea72bf5a073b263a344f8763ac0d630cd29e877fa324ec7e2683e97bdc0a33bb066846432f4ff5feb56389cd5266ded9e78b064f16307d23d83f98757b1e44b991c76896f9163d0f6b1459229f021d63238cd741ff0361c1029ebfb02a5d74b42e77acd338595f725be82959ddb313da5adfa9baf4c16acd6a8faf985eb2ea854c92237cab98da7cdb32655e5929bba4009b1a7d54f4eec5b1ff06bef6a42b537bc241959ef52b678690521ca984467a3cba2ed429b7dad65b7eadc7acb8291e225a383e811e0640f6dbca3577cfabbb021736f64f85008e0d3f29abf90afa3304d93811231f55de489060f1969c952ccfaf9f29e0854c2853bb9965f9d7a3a4ea8350528de56a431d9fd2947209e7e05fb45808395aadd31c31dbdbfd988d329695c5815eb57dc183d525ee22e050f72a2315bec88295e88d00c842ecfdb2a1decf5f949bb455efd85bd34c55060c236458128cacabb3dc02a8b4672be2427c29cd6d89ddbf08bfb74ff0baee81b612873676ef95f3b9345f088e48be2f3d8c34c93bd6cbe6d7edf2b404300912691dbae3d2ef3d31f29bf4051ecc1db9af1613c09f0e2b565b7b43a6d7b4dbe55cee2d803c097b184340e0f822bcb1f76e44c49ccb28e227e39783d0c62042d1366392611ff91b7f2b7487be45acebfb3594505afb9fd0321c22fb7d82e669d357c73c4563a042ccf4e50999e0475f9433ad5511a09a7e06579c3ad36b1e3781c7d7099d4eabc03404a2721ed9675a4bf29a340fed32bacbafc9781a17402877e5beecbbd1a265cb62aa86194f141a883cbcfad0b08a2e01b737f16d978849a48572b99f24dcbd718cde99f9f7edd8d9a7cabfcd7e0a7c014102cf78f068ef6d619a9a685fb9e9b68b36df6eb7401c6d72b847b7d12440229668144e048d6af3873aca808f2df23aa5b0262c02d603ab668e60c7cae1334f79e09c1e174dc89c9c1486af05816d5553619fc956de0ae80f0cca738241b85f4c289ee08f9947d095637d1c890da32354bf06a1abd461793ee5558163513b5473e8cef064539c08f67d019f5ea9ff0f8db26bbab0419baa984f5e1c179935100cb103f43b2d880d066024a2170c37e15691b66351fc5888cb36eca090895487a3f8f438723ef90b31ee9e1d18a327172efa7f4fccdbf7390fe7ad763cb003bb7d71f1f127568b9a97d60ce2e1e3e9339e8c2e293ad0f3dc2988e38a8e0db4d84cd7730ae6044d2154d98330b9a43a9dd2c13e51f3730987e4705e310fbbc3af634b4af71b50f4b15f1d8ed165c807a3003e3dd73d433462bb8fe75500a8129c0845029ce617326b80792cc2c3a92cca996ce9c4c49c1595ac3993538c8b8aef5886024858d08cd514b5b7e8ee532aa3dcbe4bd3db974ac02c3242baad0e230e32bf0d3ca63eeeb4a8367469aa657d3ef2b355484bf4191270b5c0d8cd13a87790b980fed8c6e775a609cd40483da0e11dd9f882f42c1ce5b53ae7183600048ca4a27471f275c059b6bf5c20ba4c9d64174737acc93e35a60f9f9e940e5bb25243ae6467b648d31076c8b9105646124fa8a9e49e06dbb2bbd052af7e32409c22b0ebfd53b39b49d2b9dd0cbab7b5731d90d0af7d93767fdbe1c194cbb0d25af4ff57057d0b5b0f5499811087b3c8629ca734d5be8b32504494fa07e158de3e2ea8272f1f06d7bee78375db21ab74ba1a6f91631797607e866687e86102a3b0e79bc7f66663f86a242144f52b5c172d9f392cb9447438f529c123add6cf258c514d40cd5a96f5d48bf10ae60dce7070f88e5911d5b3068e8c8a4ebdc822bb0cc991accb1fa80858a446ff3139b55bc15b0eabbde127a06b96992afc306ae915db73bf244ab2e4f651087fa9070ee90ab26fefb67bedc43de193a274c280bb6fb5848ac0460b86d6669be773a67006404e1a73c30ec6f2558ab9025d0a32a763ff2f683c831bc0a753071368bf868ecb520d89be028b43018c7f48bb32eb7376cf5710a1ee9066d324cf7e4caef04bace440def729028e95a7bfd85baf24b9aa23ba122d90ca792225891574a0c899c2cf48fde700e2663b67fc27db80d86d7a206c435345331ac44bb74288597c8b3fd9225b51d40b243f88b7723ee2af598c5dda1a48af3af4ea7e24aa11305a9d6a92348141e715fb4b7e23402e5dfc74da136b39c0118023ec5921bac16d347a1a91c48cbcc391b2d10f3c3eed71e134436a521b7b593db7d6c565c595652965358f138698a263d648c629715555129da1371ebd031f42b4b3c8b65c19ba4d24061e37174b0690eacfc5dbffdfc1b70e6078d7c630ee079edf2bb4157a9db0ebf81aead6c393035c59ac5c6385713c927028c15f4c1e34341975492a587213a7e668e6f27f8a96aa08931396dc09a02f3e913394ac48d42dbe5a4505984402f2f60bddf0c5d40b7c76213604c88b84df493a8eea66f669a04090dabb9f4fa46eedb853a08cf5692c28111af5ce869e5036bb1ef7ed65610ee412e24c412363c8f22dc492585f2ad8727ecffe4f930df7d2426271418a770f328a2bc3e1cda0b7c1709d782c47157b2114330257f06f189594399a30800a81eb331093aea783b028df6b4f4389255910a0639689f0f3b6f07ebf9a3da37d1034f1f8ab38ec8c6d26340404598c918510343579053ad02ef5dd8ca032cd269a655ce1422bde15e7e9018da47cb945861e1ab678588d6060172c5570f5eef386d83bcf41ec1edf1b40ce464122b000549831bed8b8318c01edbb7d36c013d683b87aae232d275d887c07ed46a3770d9bdb0480d348f6bb88afefe4dc903b2ee2a1d33beef23d6849e44d8a642336389928e06c79e8a6bf18035a4415c3604c9dd5ebf234b19639f728e1346421e3698e7f80f82b8686ccf486a54aa1a8634cd4334e75780f88034126827c886fae0769eee039e72b2271967039aea77db62d44eff4f47477053aee4ba6f3abe3350371d59298fbdc6a2d694147883edcb69464f770db621efa4ca6cf5673448c54eba5a3155b6d98c9a963460653cdf7b40b1ac514956f6654845253c69211af594f1f5c1a05f047d560a3c7e942dc7594e9784833a24b5ec6b50d9e862556adebbf23c9627f226bfa23ba880aeeae93f4d0170c16c7a7534c9af54c73b330b377f8c3c56b3b1c0a3989bd186d120aaa0441d77e1c143332fbf78f13664fb618189ed4d6b5ac48bfe039a3e6b1e99aea60a7fe16e80809dc1ecead2f2d1551653330da2f54824af09ab4ec1090f0dc9db5b4315db44315f17ff0394c1e9c6c34af77a8cbf759c077951739378bda18df72482b3aa3bdc31d384a582cc290b918a90690aacfefdaf8d57b45dbf780b2f054ce1a6028f472ac93d8b8e9793f9e99654052551e2de3ed7ce94ac0391bc8c2439aa39a0106b2950c24a882336cdcf638f78f8aa71622d0a52867f9942abb94c1d7b904fe62558698d9b7d89d118b70ff2b5d35bd00a16bff600a6267e4b8d008effaa7e0d0a5cf36b3b0ff376f8a9ae1a40867bbca606ceed3b48b42c6db2bab7c3f42528cf9115a013bc6b36e7f5c78055c961e270d30618c7a10fc378fdcd7c2a7df896d70a66b17e072cbd7ef89c68cfd4515463af8c24dd3b35c4913216cd276e9421be80661ed1673aabef7cfedcdb0ab08b64acacc65766503bd17b782541b6f1f4061a8d3e3afdb5391dd12c8563e244fbb6cf3c987dacf8530b3f925c6fcc84a54eb6149d112aa29e12ffb7526c2098ead403f4d3e99563a5791a78b57fc456fa527d7364598da7082b9d1e43b8bbda6779c07d4a2dbc301a4fa6c855734fa658b7515ba08c6919c7486b9bda4fe9c5b8b53b2e8d7f0a032333fd94873415c0c9bc1317f1ef003ce310edb523f283008845e75ad9a9128c4f7cb8505de37f1c411cfd57338e0843ba0e8140f420334bf8c6bfdc5f857a84330a7830cde2ae94433914ce1be5d95f24e92fd52c68afd10e5b254c6c509594dd718398ac10c4c983047bf7278edb5dffd7a7a8b82ea65a5df67b5a0dedbfdac9b5e1d77eae5f6d214e64b36a6b22c93200ed6ac4eb38cf004fcf2818ce099a44ea0ed8842d5ea34bc82d4fe06f605888c1885068e575e2419892f11e3f6b9717f1023a2b320753135c6b771199ee532ebaa0a8b9ef0f058d9cc031ff5c1f823670cfe86d1513049bb2f79329004aad342b71e3b530cfa4dac85a79dd9773a1667cc2844697e1f299ea4ada8d9b811b1c0960d78ea257b36dfc4cf1266263474eff78b09a1b129b2986543ea05181c4302ce6f3edd59e3c2eff21bc01d1cf12551fe00ee52db93ab2927c61c979fb394b462fa09a7fbd24cbffa8a77547006263f8add0d8bb0c6223884cbd73da3aec07cb2610abcd437cf699be28c8182776452d92e93ed09b50630de4d15c34a1aac3ee649208ccde95ca1182565f7e13f3c28ee0134530a3829a2493a4694c7d6f3fb28fb2222bd8e0746dd99da78bcd6fea328295f08e0085d1300dd30fbe892bc8322169a82dac19fef35b3d0487317cb4a36da3c9fe9b7678dfc839766b78b23007d99b3bfb5245fd94ece657d753f7ad48ab1a3508f309a1d418f3700124b768c44c69290df703d8b9178f2983755bcce25f87b77929072bd2cf1001f12de3882336415945b6ee72800c9772e32b91ab5ed0f079f51541a992413d0ab60fa445d8059153528d28809e3b2200883cda616b36fb8cafbe07dbb32b5f42d78dc1d7f4144505abceb77f141077b30110a44f4227c4c7d72d9b19291064c51bb5c9e271f3f5dd44cae88d424fc88a60b01541c3ca40e5d9e30f1f18c691531aeb71d5c28a5ba9f64241fe050c7e4aebd270ec50b481a30a605fbb798ec4067b4395f654bb354e27cb323ec881d8822fe8cdd8be24d8181423553da788f54241a3c083d30f17c9138f8e6be804c35841ed965808943dbd8a7de589c30a6fc03fcce9ea28e5ccdaa664a1e78ad79683bb5de9b0fe632315e7e38eca59f4afcf5ed9bbd2a5ffc0fc48f548fbdffbbc04b22544bbf0907c1a20e3c3257b0042693a50ccd9a5b863671a78a1faa90efa41510728480729a75147e5107222b7b2f4fc509a6a3787b9431c47f5b407f8a1bf40d0bb911050ec33ff840623b6a0eff595e76c07cb6d3ed6b3b4d7cb3a5f7eb435e1f0afc7c8b3bb01028a7102bb8d970394f2bcea61d9a2ebeecad9d766f679a4d33033e28ca91314a17b0fbc93d3c3d6f3e3aecd8afbc8dba57cdc7423a4c9f3d8ff8be00501d0c86d5e0f54eb247350a74c1b146aebe8afbfd804297e2be289354d4a0be267c6fc908110138594aa888243dc712a93bdd50b9b67d6b80ada42cc83b9c9ba55de4e307cba6a8351bee435494c7ab15a6344fd7ef2e91c18281cb2390d0570a60d5b73b81643b1f8ec77fb44835339d4514702d83a292fc2ca997e7d144a182105eda93ddf7a87e90e103530b4cba2bda129a711f9b4c36b8540344d01ce421ce45f66fb181d3157c094d39a2f4eb420d35ef78cbce685adfe276e7803666503ec14901e076cddcf93f8754a56c8da10c130d5d8c42d4ca9adf9e1606d61f4e9cf720e5162c8ccb88868201042e7359667700fc17071bd9030ed429c17ffc61a8d1780a3e807025c91465e7fce655e472e0428de1f455aafcc6ecf01429a8ff133419fd865d6a37da878d8106ec3cb7f9da08d612d76c8fe15ed750f3149f0aaedb8754db49e63395464410c81ba7b0ddd99b36c3da1971b79677539eca90b36e1a0e839d84d907dde93ab75b0989422a2f331996dc3008ab33a6c9981bc35009c52c517503f7ed31d308579151ed413569d3d5c3e544f17189da3062f11263e57be50e1cc6361be54f1f8f3126e73587bce8bd8cdb043963f83c9be2bb2e294dcaa7e08af129c2a588158b94624aa0690f2e12762d0eb30c816b6194988c7815106481d529aefe212afe8f0b44b3bcc8edb3a5ce6d1a36474cd1c1c9ddfd0bb85a2bf2cce22d4fd785d0df3824921643b5e185618a1eb867057f4995be7f1aedf492a2fbfa31484c724d3e9120b9dce12ca5189956a7967ca762f4de5b0f37a4f365bf4aa544ed2ba68c8c4b6332e5960924f32e3b5f821a3a11f7359d986aafeaee68dd5757d7ca97db9fb7e6e7ae23133e2be91db9b23571bad0a0aadc266311d8a312aebbef9553673039af607d782d90787e1e2a84a2ff4a6511101b0e39feaa09adc457d51d8fa32099e42bf651b325bb096a55472acafe374416b94b13c8ab47ddf15cc2d7c6b6f8dd69dbfd70a3eb97be5d0e95c5936df0f47d52f2a4daf07decf651725eda5060e551dd801a0af3cb6fcf828e2c0a8898cb189a15faf623f668445eec8a05ae98000e4a52ac7fed1c71397c6053e510c3a2bbef692fd16d58cb7432812c77ea3083c38d284614efac96702cce02ff62d6357a2e3107d49200b181fce7af4f1e158d5c6ca9227f817e3aae89f05aa1d94cf86900c7b75cb09fe9678e7d16d9ea5cfc2954ed504f1b7068916054e464de171e20e7b4897070931f9388e1f6f2fc9bed5ae3339d33431c211a00708a9afb11aaf546c9d60036d94a41f198da92a4d7fa49b227b72b7c128af099386b1e7548c818d3be72c1678a8693f15d210a0f04e1dd49df724734725f7c06e9df343cdbfb1b5d34ca18f3f7243569ec9658902e8f15ad9380f62b8145db3b188d34e4e9ee81a8b77710f6c494ee5c4833ee2cf7940e977491354ea0b2cd4d224cad2f3c38afbd73dd5a9fc6bb75f1e605d2c94b430984eafbdf0541799442d3bf57e7e3a274c8143e22c2fb2c1f119740c6eb17af07c04e54c21675225026a63b61e8fdbcd172042dc5dcc6a1fcb83826744b7b9fcdc1e31185e7224619bcfc6b18a97e4691fefca6741f54d21ac1e248508cb9e72ae9e0649ffbef07bcd355b4863bcb0b35180027ada5f8c855866e78024c58d3c35c2b2b64c3cc22355c47ac9f5cc276acd17973b7540bd37fb487e8107e43f51b19679b3752fc4da0d04f874b2342f15eecc3b994923e5f2d7f538ce1727c0dfd9a567bfd2316d5b5d1ef54674552507a8879e7cda68885f34a86731c034de81ddee01aa15fbf24c10a5fd3305641d6131e9739e7ea25d49d09b770dadb0d70a6964e1bc894ba25629a3946e7f307cd2bd64c81dfe9709959c20c0e525f84a079ee1924700e12b9490c5ce2fb99a4b9ffe358bd592ead1b31d62939d96721869025d72244f955bf4b7729aa069a6d7fd03e5d8d700601c11d7a2db3300f744dbf210cc328ded2f1c3926314d468248812f1b3ecc22afc4752c5559a3dd43f652ff276a2a1de24491d2430233cbf99888021b416e31ce473abc4e46d32caf4c77a1e4b35c66d93c5ebc7adda538c5c4979cafc06d54ad2b244927293a6a008a17be8cebcf76505cdff2c701185a092d78a48e7dd739de58f92d314870c5a4d5998e32e92d46410deea9c28cef21860710482f961523d6a1623b1fa2d880146266bd4bf734dde7a2f2e79c71bdef7bf5ca5d7e39f01580e3bd2aa02a0205b27d454b948750aab68a49d4d9df6b92cf0c21c19014140173e1e39f97318da338a91ff756c59bd83933f9de4fe0150b44d1c94194f629ecaa5674f134d2fa4ce196f3988a0360d26960a189a16aa2551ebbbe8b42c53ac6d280cf7c08a9c52caadbec88f1f60d853637611ecb39aec8a9ddd56db9b7002d3d4c23a83df595ad19920b355c30ce148b12928568217f9784f575429825af78456fe2ee205d3b2ced8cae4eec46233be33248e84f0866baa0500470130bb1536f172cee85be27bd0df0a307d50c21148024f0647a9ebb837225cfbe943b7a58c6e995713943125402f3425c09e18021ae99c0ffe6b215837c69b4ee3d2970ec0a1cde36fd4bea2abe90d0f79dd071cc80d493d017748aabffde71f3e560716e58be6b61b1f57b18eeb697e65ed39af0641fbe5eabb7bb1a2e19a6fca03bfea7cc26b10c416ce8f606420ec30dfedb4c8327b017431ec67f806800d31d89cdf8239f65fa0a67c41f43a84ebad7d2fb653555694554d2f190e12c1ce94e98560c6ac80b534f5bbfd4f9aa3edb3b601e7d21d65e64752650306df7591d595cc62bcd61620ae2285c58a79ed1fea62d851f5cac2c400971d53ae0e64476f5ee91f47ee0be7c7111729c7f2808182ac0365d302e6ed3c9b455be917fb72a539045be4452cd86358183c02806b2418f80eb24ded382b594b2d3e4a5443b72bf4dcccabbcf987ae66e1bf7750dc52cfc2ca1f24b7fb1b475181d902715814b05df6741f1e21e772e2d8db775277a943d95e0eba9a79334ce09b82250509d088cf3644e226f6109439b347c7f29c787ecf734c38cea9f41279d57ef5e80cbefc3a91d6335ddda947dca41be6cc3a8c28ffb0716b0f73b677c654c6ba9b9e1696182d95976416a5176ab45cb7b44cdda51fe438ab2d088ca3de99bff3a6d85f8e9edb6a43e53332917ad8b393000c712b79ff7436d7da25544abd0f6d862f75ae49b39a0d538b04453c82e3fc6adc2317d08de6bda62509ebee1336dfc3499271a3b900d333e1adf1f506ec7ed642b8e8afdf1ae893f90a869c559f2c87c6cff50397b6814b56851694913e0d3cde6f16af5b2d161a4c42178d8783bcc988c1f7d1f1334a1978e8cc13b1804beeeaa1abbfb37a2e1d33205771f60fed1311809ec494658c7a0adb47869407e3412e19aa4f2ecd412372fed541f0f3560b23c7a8ff3fb50b13233d084d5df504dde1aebcb572935d3e05f3f44086220340f72497719dec6d2ea419f92de4d888f676257bbc121e2c3097e98897b581e69e00d73df43987e0a8907db4b1ea76ddbdc08d3683f0c22125c912ba2998da18679ac4805f631f2d5929634c4a3d7c582f683f28f66c423afdb367fe87c5d5051807cee3cce82b81505eae5af03564a6e5ce3503173538c87310d66b7758d7f008f3925010b992230663498ab23072b3e7b9d82c582c3fcfe52126bb9f9590ff5611397db499cc51ac2328e00e492a25fafd0c7e36b9bcd051fb739e2fb6e769a8adb8cebaa5d1b8446541a32fc415329d9fbce9f075fedd7b4b7dfb0a7cc02e6fc3cf8efb38568f654013303015408cc9fb62e68b61e5d831d13f60f67da163bbf3ad1af40dbf6717fa88ce214ddb5c7b8beaf33bbeeff8c7861c7a1ae1117890169fe7553d154bda53f3aeef0a4841f94d18a2bc3ddd9dbc8d8873e7043aaf849c4058639015e59962231431d53ba804edc6d8599290cb18faa0f2f0e0c19bb14e2ed8d79b4210603a16ad5e19c34552054f8692ccc4b30df57ab7444514e794a158d473f80d4738b3d39fcb0183755cee47b11766dec115378c2940b34669a3679f78fea6cd02b6ba62071a7ef53c3fe351e87bd1601d72fe25fcf888c073f887b33b6a1a4916e93624c2b0533267c6fa8651e50d44100e78d9a0450e1c8546b646b25135beabeb4e52057b1413e66f798b20755f1f2fce9d0d363b6d3f824a2df13c61a3753e46665799370443c494d7d775af14fe7f95d71e5ca1b6c27970ca9644f20a1777fc395681831c7969de43839957cee200382d282329afe13a0fd1a6bb4101fd1079cbb847c71377ab1562d2cbe7d50904f394b5bd69635c93db7bdf103dd489e44e864c286ad639be1f2ee48d4f7acad42ad94990c68669c2293b8f63b9f3330133f82b65bbd9c381c59dc0f01ba1efb93c40e3336b08ed668876f4634d0fab9bcc45f8bc7a6b07e3b8e9440affd12fe9bbf00afcf44ee23d900481c5cca745683748304a4d730083d4497b1b9a06e87b6e0bca3c0796aa9e3d1de3371e8f9d9b5c472dece3d6f3f08fae19d20e8dec48021e6bc11b73193f9d7678e30977da3da64d1ee7da6df5595a369c5f7032e155f89b567c99e226ac8775df0b38aceb6dd64654231f27b1fadcb72b0532cdb541036a503fb26db5a922f9a101997b66aa992f353501ea6773b3c96299551693499ef292843098b88095c9e68d287b8c78a0de191e5d469c5686166e9e3664e1833194556de06b55c479ec1f207b1f3792f5fcdf14013211687c8a1a96400c3f78b5b381acd3b2ae42483fcaabeb0a393335d82308fad2592fce26110af75ffdbe6808ea4c9a16e9254d2c444bce8cf05a79c89ce1efafa43d8a076b7e903a4d564e2c647dc9060093f17d156bc204d30dba74affdeb59fc34f59eb660704dd9852f8abc031bd0339ba9829b6941e21224ec1971dad719e0c667c5c268ed26dfad743955c030f920c7ca01a47c04b2992a964b84eabd375e6740c00257d27caa9d6e7bbeff5aa131edfbab331f5996a283f8a36168954d2ecfe2e0de2ea2a695a7fa686bdd1f042b24f9093868fad61c4236f822a27df1e664b424860bf6d3f6ce73179936963249975faa271ea0b999082302d141d74aa1e6906dc364cc9349a360277b5a8e3828387038411641249c28c81082dd0be9a7d1960ae2ee5f245eb58a2d596baf40fa7bcceb6008778f1fd83d79a6541217ce56de18d6136f33e108ee824c9b372aa41168575a74917e89d25a275d52990ce88a24adcf715c14a91602eaa8b46063b719c43875cae2a75abeda8f3d48925f42836abe68ffc9c9ea166665e0e9258305a1935d4b77ef30fe341411b9a84cb62667b129a9d1d846090902d35b5febe111c9dbfe0780b5f958aa90e174a5db627b726e87bcb9bd353aedb3e07745a2a2edf0b220110440051e7edcb622ecc3fc85609f058761d999aa6d22f2c7ea9cc996c7c40f2507936d2546532a0291163899600ff35e224e41df62559774669cb157fe97c5e7ac7ad9b902975caf80cc0401fe046b3a4347c712a78bfb65070fd427454c527c806135be1557a0eecf0a551e9854ddddfb6a492f95d65f3461cc68be90527e3113da5f0af80dfd0252d04a49c018e06002ca7c4f6a75732246f1ee76cbb44b3bc3d3b603d57685a3f91a644317b3a380de89b68159cd4f634afde89bf1635fd1c4e8d49be161ec341a9e422d30d47e5f9002528e6061e49575eadb7876dc8912982539eb811e94fe38e8bacd2998d755ebca1c6022b9f6df56660e6baa4807b781064ae1fd7ef947a1c2a2bb7a7ae29f761f34d2aab4bf448dbb6db31b517e4ba4d06ea79d8cf8f3eeed8d0c23e04623cb79076d18b3ae365e1af6ec93e863c1e487e07664581387379afd18c0767c770832d32a6c745bbbc4f6be2739d7b63a9540a9f7b5f520800bec9a17b9bf6a64156b44a6ae62dbebb6b9a868c6e4b6c0eabf280c06344491ef5c6993eb76dc9df7f1344dc342b7ece7f53571c156f4243b7ac8ee600c309e84a7c05ce4b78525294abf3e8471b10bac7d9fb540480c59637e1dc63a1c3691e3a0f1b0fa025fe3bee2611e12ec2a69f51011ddfb87c5d19e3f030ab0be4d8af3f512389a9fd35cf642e40b3689df40c8c84c3ec77eac4b9994a0542fc9f00205a36f5dd2e254ce688b45fe375f4abad83e9e2bbaf92fe2f2bacfaa67445e219e92a7a3640eaae941661c3ec5af3ba6942c46c1296a9b3298ca1c81dc98e681d1ec078db6723b818855c006c65f6f7b02695be2c045b3c22ca7e1d894f2480bbfc9921c2d14d7e12adb62b72f6c6681c3616ed276e00120435a5947691195b0a82b45625bb6c56e7f56cf4f2d3ac38edd3cfdd10196026ef14d7cd3272e492c1fa41ab28c80af2cc3295cb8cdc62037b759227705681b801046892ac824870b4898e3804e1174bec366150b884aca9afdf10b4a11c5af72fc881facde2056d4b0d5ce93c52f6d3de95f4a77c88e12650f3217a7443e7710a49d4c91fbccf2201f06090676f7b74dd9e9d60d88617cff0be60a1f0109e0fb227395c02a3b5e67eb04d95b9726c7ef8322712704daadc237622498d931ca8b1f1a8e179b5845a219b94af5301323f2e3c6fc266f69dfcf29c7f53a8711bc4d2817d562f2424531be1735ce72982574e10410630cbe8079e5b935d815c6637d5bc1cfbdbaa9336aea2e4aaec99f1e62209235f3cf44b5e2ecc4de95b25067a18d168d4ee7419e75fd859c2528469b6d2f508353a5158c159175d635ad1d33403a265b5db4e225d356cebe00c9c5815b03621b5900e411da1589d9e0d3a08c31c99222591008a001e8fcd5c0b9e4d9618a5d7e99678f3eba631d95a17d710d864b79209ce13880eecc70109e2bf7840e997da4b0d687ec6e97f4bfe2970daa2cb758280c5ecef288ad941a9d993b620f220fb102dd361f6de6b06cb0825e01498f1dc561d04062fd56ef581bdefad706fea3596e373380764f749ea01276d3ab1821e36919147ebec5d731181ec584944b5ce1aae5a1c5d177c20f74908678b337e178740a1f5a59df050c3304344dae034db5fb178045ac958d19b4f7602f8257d7460c79259a5ac461a819e28afbe2d36b1c9ecf8ead97f95c237f8e0bc068741e4c0153ae47f4b4d531d15c7f5e1ebdae8c73361deaec5e2cce8c7bae627c9eacb0efa693ea4b111270437eaef54a0b63389899b7ba3c3632e953ca61d7c990855680074adcb770d93d3f894da92c3c0c5a87ca8aea897c5573c224843bed8c6c7e0d40575e28d0e8bda93411502c54b2df9791b2d1e26b13df789ed2369105e8dc293cd8a1bb12ce186a16a60968e9c7be69bed7e3f0e3632617efacb4c223d9335ef9b4b025ce537691a3bcaa24507975199360639cbfcc82844ac9796cbadcdc57684c1c05e6df4a79bfc1de2d05767416310ce6f5595e2e7d622026c455b533dc2c03dffecc7ac18f7cadb4067d4df5ea36a23fc2f33aebce8fc3740cd06da081a8173431f89984b45bb4b319e616be994a80818815cef33f77b777d3867b392d450ccf364d0a63656102d756596a2b354be32f96324460e62f55546b2a32bc490f9e965125734487703e83347fecea2958275c65383c1b65b5f2bd5a8f567311300a85ede154b1498c224da3e543700ccbe9fa2e043c458e18749b58322abd9f9dc5689c22f43aa39ecf257425ad5f06906c6720570741eee9ce6b0b64da332a289cc69315a645fa1ae48a9061bfae03709bd6fdd2eb86b1eeb0c53a29007be528f8aa11e52ccc5f53db9b5ebc1d68f8e52ee8d41c51391025a6c7cb1ce39ba28b0a218bb6e07fe2a6091e67fd277a724be3b05831401f9efea0ef16102a12ac271fa2897ac7c202fa5c2baffda90e5bb9a036957836b8d29326221e47212eb885304b77eec5e8e30087f620f53b4a18371c6b79fa38b4b82a5bd34eaf7baf0181621598da95e202a2796c6761d41d7f5d31020fe02f81b0045b6b3b973a1388a493ab7fb4727f5da18b9268087ccc4e48abd59b542a5d6dcec474fec93ba67863ff05c09877d0855d08ce8fb919afc5540ca6acf3ca145da15bdaacc4e01e9db1c77356f02a3d4e1ba7e48dbbbbc7eda22cc95df8d106afec21fd3a724f0165d8f45e79911883867e016136f2b721ced79698e257e1faa0fc879a672dfd5ae23c6d8f16507051f530697b4e55acc3441bb40f84561496a631601dfd65cf87e46b12318242e62367bfa46b3e99d74d867350e5a14b2b03822c8a0047ab493903b44450f50232a7298e4368571492f35d47d9bc2a05b08d4b6e127402c847f2d048e1b672f88b0a67ccb38808e24f90a7d5e538aa031216b6e96b5b9238ebed37920cfa7f69213d4479072b257b46bbb0dbdf35c27076ab69d9b530b2af7f21632d478e796d7a7c76a1f75ade8871f2f944bcb0c228eefef1c2346b409384db58f4f8a5a9f0cf7ef616bebab718464bc6fbd829970a28fe8499fd8fcacd40c50bdd32c2dd86f50c8d6d218c22ac48657463bc191295134c90fc8ae0e02dcaf5066fef748ba492bd4203cf85b978e5757aa82155836d05af8c0364e2196f8b9e0083b76a1ee10e1f9556de368b3476e0b8fcf7ec6b31dfb591a4d50fac78cde29af5795956baf6ab1fb5eed3af0ca72a59725ddc3558118aaae3f1c8af8e92563d5627559b48cd1d618fe5768f09345a994e66f9d3815ed8811dd09f72e5c427c9761d892bb9fe6d3927194d631d34be5cd73bebaec27e08f5111284314cb10564da78d6d0eec03f4a382677a9e410ee510fddf045e93a51c4089614ab76587bf1a9702bd10fd65e5b2e3e847e0d2616b0e129a52dc8c9dba7e19a6a9085cf42c6b46658cc2593dee71b9283fb90b94c01c3dc82d6efc9b651985e8a32513621e6a82a762479d78cb4c2fa974acd302f5a4a2d8228a778b7435bf142a5eabe8dcec117d66a7a9b382d45dd20d4d06fe044d1d13b7bc1e4640313ab236ec0f419637945190b3646f63c3ebd67c25f34748617e869089610be8b2dc934419634b0586dd7bbc98e2d6e4807c8407497b0409e0e62d5b140589a3fb696aa39bd0fb23b3db152c9f08c4eee818226ad124b9ac3f2e8fb62d9f821d297912ae31198337aa66846f58500a8772a72a376f02d11f288fc950bf07cee12e76ad059b278c2fcaf04a54b92bfa2bdcd6166322bcb829a4b6daf14001618d33eb8eab380fc05c2266e28fb9a2fb86ccce2d743d9459f941452a30281e5e1bc8dd12cf37d1febdc7909fa0aa71cf7c575a804aa4280ab2dd6deb158ac1c120da0282c71570732a3ccdc235314ec03519a8ac8ca9c470daf9686fd9d0c7817f8d0239300212e29ed9e3473aeb19be079e72a710a4c80e37363b6cf5d85c0534652946c076cca460c56001f83309be7be0bdb9cecfae840a103b4c54b60c4b8e8c4d82cb9a97a9dea86cc1522f7fcbc62a7430984060163a78bc2b901ad47291f27b46bd45f2d3546accb7cfdd4c908afc496690ddd87ea76c6b4d9bf5014ca9ac231d32e7e2c316b78db23e99eaf13bdaf11784f501b9d6379ed85061b96d92217619c4b887ded7fab329e46c5adb2a11d077f7b56f500d424c1b2f5198bd9f58dee1f13f3c959a056c3c3c53b9284bac053b7edf6c990b578f53dabc4a3da73cc723a5e0fa50c92ea1f1f20a023ef3541aefff7520a9a87924d44ad99916eb66652d0f88cf3dfff56e68c6c018fccac7f594648f9988e1c535c847a676f739954fb1f20dafddcdcd42fa0f19e455d085c527c6b13f7da412f788aa14061f770d48b8568a24a37ad86f4aa7aa8c5242f78adb8c0bd7c215039e9a4a178029583862a1c891459000c8dcc2bb8ad07e3aa36a10a7ec524b8aa32e781170b91288da82d009108ea426e1c026548f42dbcc0494b270d0d47313a6895a92472b94c39ecf1305d56a428da2d5f95defba3efbd9b32cec2540fd9024106d15e8371c5d2cf36ab0e4ea01c94569ae6db8eb4fd0fafb18623a479ebea079e8404989f408831dde94c85f8a84333f782e5b38f2cfc7643d313d9960cb10941905af06525279e9538937c2e5bc7745bbbf9f0209a16c1378db06e031c6cd60d6e0849a8126299bac25e42abb01e374f4d7838bdc3355f442957e650bbdde23b26c400b240a32b9e828126004c3321342fc9256a6af3281de9a75677f73fbf9deedd6d35be377c7d72449c7b7f44644bd1372559a2ccc9d961bb5b709403167a73923308f5d5553098cc475361e70247267e7586adb2ebdb2cbfa67de9e8c1723d563815775b71cd889547545bebd765280b6b086a68a3b12db2096c91c0aa24a4e56dd77b612d190fd8e29b1f0ce9fa0aaf9148a643e8454432275ecc870eee2d60d777a00078c0dd3d310fb5f1bf696442790af55b922fa318f139e8d627e43d6426e3e81c993e45e3cdc581ccaa4a4235df201abe6839573b68c7d79551a52b6688c713272526f559b98dbfa7690ca7ccb589346b180eefc092cd518298203b00568ebeea4ef6412593b0cdfbedb34e9c89a2886194b840239992a9bfcc4a30aa34d392ae296d6073b6eb1e9f9386e32a3aaf103e198569fa061be6758df2a7c1a32f187e338e3749ec882f6b952ab0a52e72fea8cbcd0801397e5e3aba72ee3adcd4a87ebe3107898a08a5fbff6bfb290f508126c9f6d403ffa3b3ff6ac8ea30af5646e756fc361d85d92fd20a2cabc1b2c547e77d7a0850daf9ea7f692ec2d66e9bba82c951fb0a48e88f0d359a7e2e379aba31ca433a2edb85187c59f54d1310967463bc7c1dd02fb26e18cde98e578a6041f510831f022b9326193c6d00a46b2febcb19a38aee0a592fe93401a78d3cf8643db154d08ec2a5fa5846df3d45d90c91751748851d4bf6023d2dc614353a1504abdae6522d83da84b736d49320a4c0748538402fc5ee57d0417e22bd0b328eb63d208c0d69de5f637e0aa9494e70cb899b8ad9b3580adb8e49077e3620c598567da843db7cb361fb1369f43e9bf5ac821b7637c24c98221a6d0f1732f32b61694e4435245b493b83fa412b830296203e90059bd9b55fdcd8db526a940cf5f4aba1cd55980050bd285a0ad6c591407b12a8857933f4b68cf80e2a4d6725645eddb7cd54c2fa0b3a387f6421d6a4f19f80b2d34134cdecc8beb93648593a44f16279482c9c1e9485a18ddecb4d70938fdc8c337c068701933f775285595fe9d11a90ec9942ea06aefd0b2e413df885ec64cacd918a0962b875ac1a2ff23dbbc276e0fab2b106834d3dfe0850ddeb48d6f3fe579186d55764ce35fc45db084d2c5e67129fa639b8b074941221f71e2652cdb232ae7a1ef2a7e4ae154c4b13d44fec1242bffc55ed2f00ac4fb561b5e5a6c060363d53e3062dcaaba2211c56e51204883e59ec83981dcf4c4a9c34c3355dc47f9a9f40e0047ae1469e53f404ee0b5368c51c1b7833d2f03740ef61087ca5f97f721f3367adc74f262f264248bd50fe9f512e3d7af7ec986e2bf1aa49c35bf98cb9d165eba572321f72cedc666e904aa6aae67db3379eb4f1d67e6d3626557c1647aea2bbd1903925bad7390552d8948b137f989d2fd240c2911195b19e58a1808928d4a0decd8550ef7fc40e01bf8a6b47686b8bb38b8c05d9d7b3c576de1b67bfafae6792443890fd9daf2d5e6f07cb9b121ed7935883aba7dbe8511e05d4a457b425bb55152faddfe8232b35197d9c765dc631fa5e3f9b6d8469ae0b6dfaa51780596ad0b4789e86a1a9884cd83922c62d1b7227fb5bc938710927be64c3d81b38f59187dcfa1a34ef775d7a0b8d6ef38c03232dce219c508308f0093572d7d3a8fb95cbf2df38255d5209184efcd3196615b4cf59694e20e2d03ccbb0c73d752ce41458fa6bd24644c868323f86cc0df64a0c5787725ae8535cabbef72886e7c2e872dc394da91fea153a41427b984046da3e5090d6359bb904f9220f7ff6ffc570fb743227424fddc21ba9314bf1ecf0caba5f79a42021822ec7756cbe94c86e22bdee0fdd4b4e24220b699c8eebd48b3138c8467168055024a9d86d04bfdd8497dfcc63f70f1305f5ddab06f6356f5e46b20c31642378acf63dd68289a80d3e388c8b02222c5e4d9d98ad07169a3f02ddb05e76f90437b8345ee8adb5ca1221290a97887e6715677d9f0b4518b06e1eb62910918bdae89904ed84e21832e0f8e6df3d85917f00c60b9bbae212cce22ba57f59294ddd6c43a03ac5e2e2d99d267b8d4c89309c55f1db26340896aec52f751a386890c72096628e3cde7b1a84cc367f017c737d66c443a46b74b8810521970fcc26cbe39aedd2e6cd28e8d3de7f3f0055271796b2c0d564c2e855822604c71aa45b1f90151c768803e785bdc77b19d94e6a1eb493de493391db28b5a21aaac551d7dd18639a1d1e08ec16f851794991438c5ce71871adcfaddbce1de28996bf253a4067cea6644832e36c730764b211f0b5e3c334364fb959531b5b451b45700f5fd99dfe4554065dbf8ed640f4998471cb5ec3d5105cd05fc21d6e249e5fe3385a5bfed9a9b0b56eec0e6b60267612f1a0e767883c057d32182928d0a557e0b94f77225d72a04c2f210840f4310f41a49c24fd9e7e1d8dc1c86f2df8de94f6979f5eef2e99bee076824ca0d2f3ba5a83680f6e81021db81c0e4a13c67dea1d49738410b4120c055e3fe8b35265f14b0f5b58325d508a07caac84ce154ac719e530c02a64282a08cc089edbd93726285ab7ec15ba9c7a32267ce574b86a2c9200a96a3c4e591c4d12f1373d8dd899d9a5989908272e42704325de39e000533a211820e3dbcc08694f3e4176ecf5fe799aee358a0b4ee2fcff9fbc39667c314c660c564969d5bcf61b787d816f1e684bf407a041178e1d0c53f4417843a9f5f55af8d8c924cec1cdc9278bffb0e4800d2d806ca80d1f991d42dd803f559978259c8489148b846b669bc5b881c7bcb751b6968076f874538518c80672ff2726b0b5049d43111fc474ab5a585ff5b9ea5ac2502a0b4b0c2c99b416e9a25117456232d12c81367914f6954b20034c45cadf20e59843d1475d841bd21406f3e45ce1e49888601769d190f73e457593294cf850020c41f713c545f913e3c098d200ced6b57ff10889ebf48128f0642aaf295222aebb75b56d5d895709593a9abb1d77d1bb1eae802bfa8ccdb319b2c49dd13193f53db67ab3a9ef941e6183d220aa114c924b33ced2482967d6c82857e85471b883860fe2d24f177c895e47240024274603e79ca28a324e87e715f093a99789f1f992f0c6e67188e575dd2346c7ccf7c56ae759317feb1ed91f1768ab6ab1f2620fe51ae537f114fe1b799b7d7c12d7fd87d9cce66aeb3df5e232d40fc1f7b9d8231f81cc12725df52b85373ea1097273c11963cb0402ab6dcf6c4c7676d7b075a6a23438293528cadcfe188c9dfadf2b76b8b60af8281ce161ae8d48f919fb6c648854ba26c5dd2cd65564a8f0f007cc7b630dfb496bc82a35f25cdf227afbb9de147d99dac612f9565f216bd989184e48cb823a52a9e3e76af479346db49fde5465948bdd269babcf944d01e8d34a0eba2e0412666329be024182ee9ff10a7f9217872d9bcb38a4e9af9b95e46e5aeae25209036d6ee3a60362c6d673c63d75f2eaffb254580d41029b129e0bfb42c01a11a0e8fc8883c9399bd2aab129bf03923cc6f02a8d732e78502aa52332ef1983f29935acad21e5d74b7cf148c9aeca5e64623df5b8c3afda51ea80bd352d2b2b133849bcd97d95b9aa9ea8037a9687f16f51f58a406ad8b00bf6f53567897038b69b2559d1f5ce5d0c98555f27ee6fa5baaf1a984c08db21c21925c3e249bdd371e6154314f47dbff996bd7b032c33a9d7f4216e9f8c98b3c981f57bc191a814350db10eb0367d6d9c05094b917d38b3c85d1836e2022871a2fa4725bfe2ddf9adbb75cd219a0a567e6150a8fb5aac57cdf67becf97c71229ce624206520ea38671bf545f24ede783ba788b4ef1879fa217857b9b16731af0c2320ebd22c7913a66cd2ded98d1e5994b06bb5eb2275e3eab65be7a51a8580db8a066b3b842b0370cd020539115d229c912721e525c979b44192e7fa9844325e01f01126681a2c527ba9eb90698f46b490a248bb4bf36243e3b4e834028a8aef02142835b2480992872983f214eae5a79b2384d4b3b5e8d2667e35c236ac5756b466d1dcc64b64e1f5385a46f1a50deb25eabf1803911e4302c87995b3670ab42a2f43d35b3fd2c1102c4f11c2733ead575e69a1a845f74ca941a5e47322a9071dcf20922ead63367feba58787b8f8a5acb320f55d8562810e36d5d1d5b80b89ace0363550b3a0e643195be5c3c1bec43094fdee8efb55359bac679b1d8c8cb233626cd5280d7c2401bb850f9a312b8d2df2313fce3cbf036f502eda81ef841c88dacd93784a2f282eac12ca411d4d68b58fe8b813c52b7879ecc13abd2b271370b03beac1ab4f5e859855de41e3e53ee98c58ef99711efaee1a183b6da8e334d826485a361638da570a72e4cea2d2dc3d8df7da0438b76a2c51881a5fa8e67d86c880777bf066d8543e4e8db186a51f8ec6e79633af87672d974f85ca8ed6d9f559462b1e2777ff2a6aca4a58d68a1358f978f9d08c67548c390ebe9a2ad85f5d560bfd36adc0f8480fb5f437665c1f717cda147e1c241513abe19e7028176beb35ddfd304a4407d0b5efc36b726d95b44c619c51549dc88717357afcbfb5fd82834a8f543f472525311c383bb70e93052b9118563485d79a4066e02787a8a6c7346d818845afb2b6dfadda2f1e199145372eb0c291f12f9d33101e07a3fa7ae946bce6d6118e3031a10daf955ee80710dab2adf7a5d10a4cfa7acae5b598d935afa93b692dacd23b4628d724a7f7ace3034992b3ab4ed805e641d835fe627087e423e9b3c1267d5fdfc4fe6d0a4f34596fc0f4c25b079f9a4151c853c5855edc00b104751e6af89ee6a932233b869a1dfdba47b4cfbd4f5cd80af84768a9c90e23834dbbcc30bf0f71e93bb316185a292bd1c4e161f64a6bbc27a5215211e7317f0e0d01e0d613a5fd53d42b2ac0a335ec8bbec2d39abc481abd1177923389e768d50eb105499cdb37a3addf66382f36f325f324dc62fb2cc23e244f5f7e3c6b567ab110886e7fbc4ff45af2ebee5a94cf23e92fc01534dcf75356aaf5004435a712db7239887264eeb233ad368b5b2109e1617925df7a720d0558a422794f9ca66d99a9379a768a0939d49a5096d2e73bd8330c8b419b2d27bd875aa0173fb3ea89e21d152c3aca23921d7b7f3895356deeef54cb0aeabc7487a02aa9984b15a661393d272b4a903bb6deeaf81ed424abbc4cb293d0ca49e2a75ae80f559175b45301d4b6f106616a91ebd7f9acae309a8fb3b99889142955da3b84971f57d04e1e046b4b64b33cc2ea6f3460a3ed9e7432d063e42477fb458ff17a9c007903bcd264b0995b7ad2df8688ddec745c122817013ae2fbbe4bf3467f6cd2ea1902a694dea1ef43239feaa6487cbd07bfd895230d0f7fc85e797d9f36360678d75b6c58c508003962df57d4f921adf809fdefec0e71cfcb2eefa9c076a388d545229089f4c9f7870db3e7bcbb19581788b91a33418e72d716a8a89133419307ef326e711a42a9bd9cc37d3b434066af29e3296195f082629ce4a34be916f745bcf4d911401475d20eacc262bef6abe1bb089b8dd5d9677aa44924a82e3ff94455296fb93485322f0731ebda905b13e1db95ba5531bebb0edaba9cbad497c0aecd2a3e078b4cf26c5091e523661f6fe2f13db15d74d890e6ab330cdaee6a6416f9bd5428e80a408315915e37c37a609ee65656eebbe9cde24802a8cb2bddd459d3543dc83a8007d92197615f29305e5d765f544d4d1fc920fd43d9e537bbfa654a2aa12b21e7b48934152a9c009b272a8a46f6a1c4acf253b37bb99b763d08322911a525d55190eaef0d9d674e32ea7e16b7529a9626ed15c26887aab89f4780a16474e9572479a8f40da99b2cf8bd3a3e36a3a28d0a39c36a354a9303e0ac0966089f04ee88e2f0b47e9672d1c886c1d8dfc5674cae7f4bd30f10ca6ea8e1aa26e26126cd2f03171a6f689189e4d914e844b73a010db091b83a5d81a485b4aff69c52beb98e27b211dde43f18ae0045aaa6394f8ff19a2fab7670fc0a09a4513b2b0ca9a2885ba34294118f189049700e90835abb2a36e6a8b163696a0737c3fc9ed5eee26430a229614fe714861c7540c0a5976f446a3d902d83c1c08d923730678c2a76c3fbc25f8f2957fe65f801cec5f07826cfb701123a6bfdbea2ec85db5a6aefafbb5024a2ebd5c7b2a12e2a64949cb7631899378ac32bbf6e3e92bc60f5c898016062bae089b2cd4711bc9f9957ef3c48679a512dd5309982ceb01e87ccda23b49c092b176a28b97147652e139cf92f211f103e0dae340c509aff6749a2f56959af7704bfc9dd39debfd2d3bdf75f1a8070d32c6f85d14b52291bbccadd17cd125de22a389caf43c7283921d0b2f4fe8ef54b606726660ff56e64a5a212499c3b66210d08c180c5492ad28a45d904174952e6df4e8c0680fa96ae33cafa3ca436b23ad9ebd945b36314f6807cb023047d48ac55b8097962f5e25772454de1231abe3595e79f2695630b9836f22423270d38de9e0fa778d4fc60204d4e934fba79e89f1cc54631eec8c72be789a9222cf7e29653532870bd4b878f1135889ba5a0491ed8f2c98d2826a1b36c68621007e8e6bc967980372193287933b4f9e65cf2e2f4a450ca7e259a61abe7225702233a06594f7df91b7c5ff4e2a13d1cdb024873f1d99199aac4977d181a9923ad190c533618f9e971852216d96b9772a84329d15195d658202cb8884c48ec3998512c11317952f5bdc507e5eb9146de5e4ff36379cc7d8580c179272dc67f55834a9b29c0a90176ada1de720ec17696e6c2124506a16401537a33872297cb705b48accdc82027c7c68722adb7562b8ab4f1c2455daed276c38eb12cb1fe4b414e46fc1881b5e85c5502e9329ebf913654b3316be0ebd6ebea270f9c9c603c191078141f48f18e5f712556c8c94a294e9e0f919af8602b65195a45db8b5fc28a65c544329004570ac912f55214c776a915d0cdf01b559f23da95d2cbe030bb0e7f22a61249573546d0278159f84fee291430760eabf3269458794ebed0c1f224c196d442c621d4270c6db989615bb0b9fc1eb11e80dce070bbb9cf64ea18da8f67cbbb47e1bba76d6829e4f4057342247b695a8801b74d84331d730a14b7ded6f92e3d54b84b032666faeb92fd69a712b43b9a2bec9836432c1e0c77832a47a935c65899b8682fd0f5186b7e7761e610a8dd92776f519c650be2c76417dc0d44862ecdd1c51928e63f3eb9c1c3f3c5c9a8f1e906cc08ed1310c05d1157dad85fa83db273be0f55fc02208acc7cf6c5db2e0e402b8b79850c8a57704777259aa729f4f06c8898fd80eaaa614fb2810afd7789ff2e64ada46b7d115252a1394fac955df9db07add976aea396bab464f1b13e80311238eef97f80d12b531719be39a11a8e883588c30f23b2067b6b3fdac75b5d095e813d1ef1cd3e25191f54147cfa331746f9546c8a357b9ec31702fee15b94dc1733bcd5090ce5a6c1604a645b1f55cd1890004284fd94ca8b433ac553574772dde1f77b3172c68dfc61cc3e22381c1e1294100ebbabfa3c03b2c4238232fbcf26131b3bba89714be7487b33088a8807650b0cb35c2bb6bf36e61ec47b482d468b0bca9cbfb077e04319f65643603823c4fd4041985f233c3c76cd917f889c3df0f0c7fe695f335e0354b1391cee6284a7c127969f4f952249ec081181af8453fcf88f464eb53f0dc11c8fb27f8957aaf755624c09618bd2d623078b9d6d77a322ebdc0dbc06b9f2ccc2f29fa2a9aef8ae0bfdd8235605d221af3b6e92cac5157ee715513fbca305670e06cd0af701182f341039d3c33cb0451390fb7442880f656317cbd7aa23d1d36ad17d124e7bd021d58f60766da788466290f3092e6855a09afe28d8f994e8e34f2a3315bbff45e4cfcb79e7d601ad9a8a00bc2e356fab6280d8620795272f845c4a3b2924d1a8b7db6691d3f7d577c86ddb8735afb1eecc8cf78191d71556d29229f0c22dd2fff163fdc41031aab5edc4d3b0a841f6c79bad9caa6300ea41d9eb22f4df7c7eaa7a7620754f7de4b0538cc1b0764e93b8781c6ccef519ed009a1d7c1842f351864092ad1bc7f8b0a41edd88669f2b50f01383f17a47f206e07fe33443b01390beed350450ab31b99b9e5741741c785a6f823c7c0d39487582823ff5b37f8f79f589f66b23702c43295ecb7b36b9508fe7681bf28c7d526d41e3c9827840a7621ae3953517f5b7444fb7e809b2b5d798a524d9546288cb0e12fb0e6856787cbbef55d5288aa8c81faee8cf2e16891ff1ea032b4479355642198ab8403490594426196ed7598e26cc33a0f7165551337967b2db84231fb98060fe8ce14ec39c0dabfba7693a931755653274e986bf936631c3c4640f2b8df8d42b0cdae367b632fb6b1587a5342a6463135977e0245ab786a34b5780bbd2efba2236580163eab79093d4c9ba12e1f4c08d54cbac7c4cf4fa26968214002cc48e36c3538ea06589e05daa38988bf8f720785e2bf2e856762d8eae6eb363a3aa32bb67b326aacb83ef3b239369c1b09b3f56d880d3743c4410b1cee4f8589966169ad2585d721fc0d9435352e2fd8131d79d443ea8037427677f04e7273ab5d417ac14342a698382437bfdaf5b868f1627adb74c50f60ee9b451883f24249c4f72f41297fd80ff4d880edf604107663b6eeac27bcdb29a7bd19ca5e7551780ef49a7790fed47b536a0088efe891bfe56772a69ce271c7418a8d5d9604bad1a3ff86c6c290ed1509b03bc730b77592f99f78e6550c93807f020d513e2999a0f820317f592908b60bd44c622888fae0c631662b88c963c51d4d1c23d67f73f4f39513d03cc520b70029fa6873dfef9318f234c4c4c63c7a1837a88ae4672748feae1f0953a7261d80bc95593dadae78c370ae4af4a0a55c90d6a04149c8e4cb92f5a5121754e4733ff92639522d2151ea8fcb4d461a4070c746423c8858631cb53ad6b5b07fb64c38fb5a6a7065243f7398131c1bc415575bedf8753af5e47bd2d4cf381a78ad9ac2c36d7629df9dc89029584f4be5fbfc165f785563c092747181053a06174a2af089f7ac05d8c2a8a75a041a169ee6c40de4d6589268b6a7f772d16dbf578fe8a39de2112a6e19b930e8bc776b66bfea5c0782e37a0b28aec4a94460b39456a6dd9912371680a8bca65ffe1517a14639629bfab79bb473d9ae6ce12128c3dbfb7f58e2412569342d0c197e6a13fe85e5be152931c751a61a784d0edaaf2771817cf6b735198a48164922fd92e4014503e80a45ddd2cb34b85072c881ff253f9748da086ed077e3df5f8fa3d03bc2a4e681bffdd793abbbc836378deb7d5ae6cbbd77986a747ce1d265d2cee72d16e79c63d4d9cc39e8e00685ce901f0e5ca6b454476d3ce24d555da35a3191e6a75dd010d986f2bc9dd40369ef409c2baab6fd7a360758398a9ab579a1eb514511c58864685bf8ef471f6f3cd190f7743c6ef642a834e3558e0cd14bae3d37a80c9dcfdcc51a8e65b4546805116b53395e686d4349e5523cacfdb87d87adc4da9ce6919c3e12cb7414a30de375d3adfafb4dc5715ec8e201c3532ff420d9f93f0666833feff166d27a95109a92cb8be3d52f34e502db2184a175c5583b2c15d6d49c518b21a5a93e82a43fbc000a68c2635561216b148d0361902cbafcdd51700e6deecd4aea34c626e82b3451cee9c227581223c0e15a872a9421b79cfe833cf52df42c3720840f669083ce9ecd0361094e5b16625edf5fbb1238c9871f8bb3ae5ef6edc9770d6f6716782903b011156cbbd4649c0a05342c2fdbe2a89b9a3bced188abd145790eda6672595659f4a6c66582ab4498f1dd009512e71803a064f03af097b26020e243747ede89d1aad3669ea711c8da36c1eabc174ce2226ecc96fd96ae8c16a6ae79b4885ad0a7739e12ee17689c4e90b486a5f4476539bfb681bb489a44cf127cb544911a4ee3cb355dec4cddf5338025e5b92a21d83862721d2ce6240c90fb71bdaa9c8a2d4d4b6753381e19c29c3a2a7810758570bd1807b872bc23a74617763e2d3f4389ee32b37579ab5d66e8b33b76641ecca579f031258bc5f83e9d206831eb57dbefb3a512e8e98fe61fe32434ba58cb23f37aed78cdc54b9d44e5e52295c50c4c105ea438462879c707f31be2898018083ade87fd5061e703e1f84fdb51ef8bf00e735d36132c2e76d32f6bf6048573f23960dbbe300c68e6fb7e981d6a5a9aae2bffe49e0397dd21e07da64d30b24843dc84ccb2c026a42e89382ffb522a8604f0b842412c6f080297423df81dcd18fee89c55ced60bd8b9f415249d812a3969b54d48eea0203d385a00609c545e3b8a50199364c1fb8af6d6f88fe60c42b0a88a6cdc9928913794fc1a732f58c0f55843a281fd0a749507e82e9d3508166a60d495e1b728bc5d95645090072e78428247209acba2818d40b6421426c4949b10af1c336a4688f18e6927fff2357e6d29d7878fb4e8f982efa86cf5334909fe9174b6f0db184e15133d10ee42e5834a9b6eae54845f99c15533caa636b7d6ff770c192afb78847ec335bfebdd8a8b02ed427f380743bb869470458bf00d2265da946b1443f29d1d8c1e27bca4b709885ee0a5ef641f2dbd48e778c6b991ad5ecb284e474e6adc47575ddb5c22941c2fac47df75b4d4c8a37143c8032b3f457ce3d6bbbb5e67e63fe7ab1a47f96cef966317a9decd3c77fbea94174ea3cbc833a40b4e893ec3ef32e293df210f310b1409da5b1500f36a9416c8bea53ed3e362012362f604761628cd571075a3e8216ffe59e95ed3b87e48e8b74b9c870b0854598e3cf79edb8c6b291e64533e88496892d38326601d2567f0a464fc3410e9103074b55bb90cc7a3496263a7fc298cd54607d4e92497fd0a1a1971503bf6d6cdaae7da79910709b295154a527009331f334a148b26dd69ed4407e29d3f95d12f9016e74264ec0ca37ef1158bf1a5a5ede081c153dfa5f14ef9d0bc32449d3bc34aa1483ab7737e581b1ff14a4db4e4ae5ef1ec84b7fc0ad90721b23ba2a5062dd1850f52a354544fef930194021a60f6475336445511a59854f58853e8f402482ad25d035dbcfc6ab8bd88c89e1dac4ab8118ea9b6150a5e0b52242ccb2235e66291aabd7ea5baccd43e611d6fad1e2679f0ce22b23e8c3b03507e009b9440fa4d4c0314c3b233f06753f17644a10eae374073a2b8daa0a3d98080731c0bf23da231cf3ca4b2e71f04bb530d003dec8b99343e177988a58d85c02eb365e651437a811256c4af44ceec986ea18f73224431f93d524e8cdb51e460e4e65f99ecb70030a3c948d3a9ed4b5dc980ce471af87c11da6566cdf02249a97cdb907767863879591647ba26b3d254cb4c58358d9f1e4a6272f4835c4f190c9d6e6d1a286dcf14a4b7dba9aa5a9071cc335695cf34e1f338d40cdcc773e23cf3757a0d324c4fb29f2fac9568d2b8145fbf566664d9a6277c2e518b142f1df43072f86d0d23ab8510e0baf4c06252d4f2d4add02ddf91544f33f342b507a081428e42e90554f53ba4671dccb4180aa2d5da6ee97c7e357cb46b0d2a4577722e5b4c8f47aac39264c68c4cd2ea92279726ed70094cd793bd62374b93444f8172a309b959b96a947d2bcde70992e6f593c14760b4dc4ba5872b9f2e5f6a8c537a66dcfcce178a7db3932cb2be764427ae5db6e3fcc39957d11a1e45e27eebf5c30db621c680b1f2e046f4cce87d76172b52aac013d4446a91431dd7a25ffb939d780bac699919734cae62894421d6c7fc9a174007258c81ed7bc985e7746d39fde9525a799e2a1cce0340f88d36ec528cc4b9b20008b27609f9b61aa729fc3039c72b3ae8b70f8c3d2c79cee743f375b291e10b5ae1f8844d6cd4559158481061348ab2c0e10e0422101693bded0a91e612d2f933e2dc6b52e4881b62acdd47e9cbfaf65c716129b675ca3d536edad618898e4a21596a6d0bddfdcb0d987035433530504f03b5b28aad25999430729359b04cf616a921b0d6704f00e11a6a59cfb5243c7cfd6e1744300b52f6547e1cef60d086c6dd98fa478bc74f8c578269af21cd8381f6d8474e1a97a159ff72341ae30674076d8e6420c71b9be380af398719939951e7e65c1fe17f5555f9e707c8f717090847cb08ddb7516711c80fcb58e43d1d1d1a6b8755451d7b924b5a47a7aae21707ab2f751940cd42513b0999bda7ba5cca237226b8c69ae1cc8a6ba7905a40e793e34d40c40359a93e869ea309990ddedb8b19a4b685a39b8c35969184088d3c72aba7126fcba7e37b59c4f3f2bc05fd24643a06e0c5f16aeda299c4189e771cebe387adb2acaa13b09fb8bd10d8e329940c84a5af64ab4baa4e1b58a696420c4c87d53adc1e6567452a4b67f5af8a3d214ea49ec4a87cd889780ddd55c3cb512fb8c71634d3ae7a14bdda7d4ba569599096ab355ae921c075958dc65f2cb856859e78811c06bb62fdd475eda503ccfd419c419426e331650881b659442e57a33b4a4034a453aaceee7d1cc021551b190a5aeb53beb3b29d8c7d80cd0811eba8c30552effa9ac28026a1bce8f1fce872fe18921b883d06188be7a6577823259d58013bad02dda44284a6999ab173fabe53cef89dfb11bb03649c6a6d22e32ef7ba7f28eb784c3d21d384f4143d9d1c728890c88a1a42c92218ef1305d83ab0b4346ab262f14befdf2e9c25b7226b9f0473795ce376a64a4ba4ff8c32c3d42a3e3e0d3164ae6686409019a2dbd1a9fb2b3eacd448dad9decfbdb5beeeb6bf0b0d5b271c015361ae65bef6e407e9044573ed5d7b295a1345c9719b8cb9f27df40d770bbe06b318f4b6528f391bf63a6bb49b0348258c2823c982e5c27cf50d8a27c0534eb5a239d338cf90cc0c277d8fe37d766c857785c3cee8bb52ddbeef65f208ae7380743029a8e2299d44cc8d8048aa67d08cb43d91a13a4bb9b207b3d3c635a43d293fa59d0af187c1d0b34042bfa5290f1ab6408ae28ea033ac5d6f476de3c106b76446198e9f1f47af71bcc383fdb123b372edbd211f9ae64287a7fe0b94a12d5c4aa1fdb129313f352a63da9ed6b314da087e9afa6cc4bfa3d05b58624baf67aa22c45eeec85e07dc48ab8e3f573a9e1ada121f95d2880643f31656d515212402c7483e42fc919ba5518c4a82bc5b46590573c9aa4fcf2f039e7dc7e838cd89a368c428cf4d3bf38602c6af8b8819575e5a8d282f4c0c8c65c53d931e695d373fdc55272b97fe1818592f7775f42cbdfe1ad64142e7e2f1cda8060454ee5a542727661ac851743492e20da355033cbab4745aa67e412b9556a414da1602258350d4a90f8caa65b449210b50517d8203ce1d05e1258a8fb647f33f352c4c25eda0ab4afa650816d7738f3b3c1835d4b1927422ee6066585955b15b102e1479adaba98ea54b0f485f43a79c7c23e54f662ac5de2d5a2208ecc691a7b4e7dc236a667f2e031c7115ae5b7be7f1eaef2e31dfb05c2d9225cd9c91e7b40178082836fd1b685221490ca8ad6dc8612627bd458aea331249a80bc4e34500261ff11938f7dcbcade3f8649c46c69cf17932fd058b72a50b9ea681aebf23a2ae18d90f9d42342f39cf859c180a8f9205cc093a89e59c84c8bcfd9d959a01888de89e72a0952b3d60bb8d6a510ef2191e4d8236859faa6f52186bb706c504542065e1a7e8dfdffb97631d591b652862e6dee3896f96de51d9acbaf13ced7b97c9541e2f15dfbf127be3f81c694a665c8a047608d8643a2034921d4872c8dd4293370811293b647dccab4fcba14889ae1db11b650d5bc519eef651caf1b5b8e71f31754fedf3137170a72e19f3a369a4906c06dbd88d9e5efc16cf57689ad76c4e06d95332bc5bfebb481d3af9a24f54c57cfaac37ad2312558c99993cffa15dfc8b86621bb7b6caba358206f1bd9b27cefeb9e22ccfdd49edcccf58b30c6bae4e21b7fcd11b617407ee5c4a8ae004baf2bc315d4a848b9983c15d4f069af2c8ebea0aa50d48993934c2b37c44f21295921b24c2c0bea0086f404c17d9ad59b6e7ccb1299d7260968f40c2f720cf8e4aed720aa3cd34582939092e1bb76cffeecf57e07866eeb25e2c93a3e599d692ff40ec935237e895359a6b82b53eaa7be505bd40e388c952d4d2abc6d8d7a4e3e4bf8142cde8024a8dfda096e47713879feab1af3d6cd44758f293c3aad8e89b470cee7f9bea7fae45a873a347f07cea05afed99c0312fd3f53b69b95be9a4612942569039525e7dc7e94cc5f1b0e89424e23e1bcec3787289c316ef55d2d55952a9c6b8a81c619d68316dd036da33bf639f05687370dfea631a2c0cbedb0275f9f14da4a250163f50762d86152f76591a7078e88a55f193940e147a726a3c48ff22cf90bfbcbf3594d3db7473cf42305ace56737ec5f2001d37738e3f66988e58f013522bd6581cda1d8f7682fb4195bb883f9674384bd5181216241fdf120704757d53e9fe7c52e926bc389fa2e361e16d67730a0e71b261967b88ed32eebac406cfc8e7c2f64e319428eb5550cb22f779f22398045e0319eb5f8bf988c53b82a5d4b8a33e982e45a8d8dc31fa671d2d35a3bdfaedc624db2344fa6d78c31cd71f6c3ee4ebc7fd1d317e197746100a4aa492314f4ca3524822265d6713fd7bf3b5fed9a51cccb6427ee28a2c28c047a20f3a7ea5064056ec265bbc87e3ba4d529cbeb56ec2f55af5574c92246cb1e2b9448e21cfcacff30f7214819f6b670b80d69e04073299c6bc799aeee5ae0e1f4f8b8a42a62f3d3a2ffd571d89cedefba0ebbda317c25ae9ecc09259ee2b7f21b4d51f706fc86c053423f0ab0e8fcccf5afcdda849096891f2aa5b5b1757f44eaffb2430f238d09b85de14d83c55beb3ae4303be7d456593472cd27295dbb7ad10933241217c4abd7884c28d2897ed0e82a986f0a5a78f328dd8e153e3cfd621d5766a8d4aaa002dd239958bbf0c9a806ff0682abc0a7acca9667c770cda7fa00a1cca3353ca4f5542727555c007398cfbf5614f381bd38e9bd46a9e3c160f76540cfaff5b72a9f10af84133bd462d5c261bb374eeb583d7dd7f9c9cf44d19f372cea6c8ddefae46594db3f9c2f0cd731cd8e5b1e6e86e12d00b7d7d21676eefbaf6631fd488772c11a21e447e80c80e3e907fe3e0df13557896d24e96885e74482bf06265971b171f86632f712c2a65bb2aaaf384c8c4639d182475b36e6590cf593b2de0e93a00382e98e11cd4bb3bed14a905b172eb71b9ec16d40546eda20e39d0928e6f548d512bb75dfe683c9c24c67c3fe1fee7050f18fa007236680be9578086536a90c05c09c9148ff48ff21665873b0d29777fa2406223c03c25b19f3c2d3c70f0a566cf6cc3ffa13e6381a3ef40eb550ca217d74725d6e9bac0091a59e4c358c96bb69d98db4d2ed5cae98fad8bca876f51e2faaddd827ed1e56b55f5ea371cce140f3e8f3b7b9f268dafcb4cedf728e29e131fe19501bb52a8c6b346084ec0c2e8e9b898b1308a9ae727c79d5eeac7690c1d2b0a0ae66c4ab159e0630911ecd24be50a4daa198fc4747bcde4c0737bea26fd77d089885b2c4089ee4608eb34f8d988e0a9fa83784f54525de03b0c34bb7c8dff6cfc43f7ead989165e33d49a64ecd31477eab1b56bf1fa2d3e4b92cfce47864e123b7bc21ae9afe284c075682e0e990eaf49de1184cec455d25c67f80803f46d2797a3a9575e38457bc0943c579b0478e82b34cfa63a11aa9df327e21403ec4a3153c4725ff6212866f73f329fd1b4328c4e1d6fe176c45df1a2673573e724f037a05a9280a04fc25df757570bf1c3b88e08f2367908623f696f0c93e11d82fb9f5ae06faeb5a0e6ebb868a61f5871ed2df31887bb4dd0a81c1bb27ee4470f775ad5f78affe4a35a7e64548ee51ae626d5e920a5cb80011424a6cfcf5c45424f63a76de8c23a968d6d4d6f91fa9caacc970e7681aa9d7037908ee55181348297c568cfd5e3a1cdc98e681583e1b6185adc0dee4f446b78e6d9d16004eb5418bdf3ed6d91cebea5ef26391a8197a3f39c2a9de3ad7ebf819e7bfe2c7caee9c8b4eb501aed651aac559e67cba09c774ad03464f06aca6369aa95ec5652c0dceb1c6c5ba7fcef126e98f60c34df5573c151aba8375a00cdc701e92e037ddd29fba03d585526196b2fb8f454dae184b48446dcf43a95fbbce9b11709174d8442f99c765733fd6962ae0e13f1589985697f14938d24ec5254cdb5935d555475a780fda42cbbdb7a85ccb5faad5332e154adfeb4d3268883c061dacba2eb657ddc2c0bc4cf84ccbb4f712c77b391affc8320202cbe771a7a574b2c1b8e7ecc312cf5bad56da5aad93901d7b1a3fa755141de811af04bbc38e8a73d059c843db5ebb30daeafcfbd3e867900e0e0de70008c70a4343b9b6fd57f39398b7590502728d744a2dfff0d504bc916d9659fdae593f61fa6b746b8d5e5009bb77f56f1d71fa3d213b7237a5118ccda5281082071748a485742aaca3ab6e4c36ff38ce0ce20717bfb80147ea10cf2ae93ab0c1591e0e41b762e38c634aa786c8acdaea384f9d6d5be936ea2f33b0fed9f2f04e7baf9568746b40a38c731297b83e62202da1e80499794b2b6169fee2d58dc3b325f851e10090b776df44917c9889629f19fe2028390e6d99727ec4f54db021495901eb2d8c7b26e2cfe4aab3657ad1bdbb87fc8f5067e4524a21f4bea1d9693cae56a80849e9cfa77278a6174b50eccf7c8e2ee59d37bebd22b1755915369264502133e72d347804cf4f00536c60e0bfd3f356c4bd540ef4a27074aeb7072cc3198ebafc66428e1a92710747dc7c4980c17a14054359084d9b93a551f0911b4e5fc9b23dede725e2239d28322ad2a9536546bb73cc410a14f8af64e9276e4d789fa05b63207fab80acc234d4c2d6f4032f6e1f5fabeb936963be7125b0bfa1ff984cca2ffbee599ea912d29450176d0834e6437e4b26499d2a349cf55668239b4efa88bde3ccba4b1c85bef1b379f57147eac889d6ab892a4af0b3ee3ac02185f88b3150836940208c198758a3d4ef9ec0f5fb8a7a7de39f5d8834dced1f431e85372a180fe07caf5116de3c3dabb89b874986607b0083fad7a4ce16964501a428b2866a3f10426406e91e3d3db5e443ea9db359a30c868e00df10ec529202f30c13b5b0eb26530b13bbfff8c6e330b659a7d119765e7bc8782282db474c9507da933388422b8eb6aee0b9ba34943c3e3088eb1b068ab1ddf64a12cdf960935637ffdb0e2fea2afddada08ae55de684acc3b1965943218fd817914599e44e2a02cda9cbe0360b967e0adffed33c42bcde1ccb42b003d45b0e0926f104e9f2d7e65f7261253836cfe5149f913e55ff18b70929bd414307befb6da3db067666a7d0e4ee9b80067770d2d46a07734c22da6df7e1c1b79efdd22a5e633bf59f949d714bce304d407c7dc02759fc5c53c11ee91fd60589c61d901b53c8f967c77fd2ab3d9b41032547db16b5b6616597e50b881ba6b5840cdc56a51a2154855c0b6230c2f5a0ba72fe5e8d85e49546e49406e7bd2001c3514f0faa2581f044a14e34680015dfcf3f65fc9cbb1fa637eb92031e780bd91cdb4fe56c9cf45ae5a8c0102a3d870fe67b07317a0b1a9c952032f104238a641ab588fafda9a8b4750302e63e90f6700bae0f73f1297f05f5c85ec1485a8093e2256240f89c61cac33538df1ccd6c601d44a46d2ff780f0bf93526e7e902fd0bf4f21ca065d82c0d9bab491851021e068971834625753079ebc6aedf9b7f390f49700f3e1fbaa5352e6c6f3b6e5f2ea845b28ebe0d13b26914d79dcb98a6bd52b7ef6c0a58d157bfb8648cc03026b23900b7650c87f925afcbf2ff036df6c9bfb72344f70e56fff550543a09563e47a5834387ec1b926fc18ac8bd20186f470533b645c09a53e35147c358168b808dae2a8db7d73cba81dc4e3826f3af61b8be11f8fab73ad475a81cc9e4bb15475dd5511ac07f606fd88cbdb0b5eade15897530605338095942bfa4c286f0d79c64f772e7034a78b77763dd3a7179e25a5176a76b8171b2c9cfb575e0d1520459b5c8674c674cded663ba06a4bd38fb77a7e95f3934be580a8f5395cdbaadccb3c2d1db97fd7e86ca705a8a01ed64cf3fe8978bec3640a0ec9583832fb0184370381ee674115ce571d0b109f7f3fe2cbd11ff1be2d9ff27617a0ff9b47e68547b2868091ca27b112d155f7868016cd12c29da1cd5f5856d9d10dd752a222ecf451829cd7c7ee0688fa8394b0251f386b794b8a47fd0d36fa9d946a4c509af0cb64d13b884b4e00dcc0fd7e946d8d6ffb3cd8bf1f58c066395b41c38c470d86b8ed51ef9fa7795a729615343e79f188d7c3c76a00da92bec21d0add2e29eebff897a942218a6d28eae279e62b891c48756b20c00f6a7b9a73e618e35219ce0313ecebd8685bd13ff06f4d1ddc3478b8049f67f47a1f097458a592bedb3e31515cbaf8f4005c4ef890f3af9545d7f7bd3f248745c7baa09b325beef2450c98a77c24a8a74202c36ae242d6587f2d190e394b617834056ac4c2d59003e27b6cf35a71184f7732f78db91d1be3776ecb9674b3a41e044fe7d3e52b8f7868616721e76b862ec3a343ce4a59e34cb681da4144793934c3d21d1ea20f284d28e1e0d37dc83a348c403d1317befb005770f8ff80345431ee9979634bab1f762814721fd94d2bb863f722f74449409be3bce7f8b77ecb6f6fa4dd6fdea61ff38178cf48963c4b2cec5ee9d3ea322e09ec290ee5c7f228db56daad492b1e789f6735438005b1386d9f78bfabfa88f04ce048d776bd6f61965c265abdd533cde33c59ede8dd75380ff085c716005a6983b82363247cd74e3e13bf9440d456593c1cfea09b09fe5c7d701a4ba7730ea7741020bfd7d2141766e01da0e142b9a14074c8d40e26afcc0390cc3df0fe3bae6b732569e29b5be8202fd8325317386fe8aa1e0caa5a1a6f15ea68e9a5e4337205dc7e01d7f3ae77a3a710e5632267db0d6ddece242ea26bea9f8660784d59a7e14244ca0181dbad325b2ef1d9055a60c0d9d7fdd88fd2e6865d77cb53b26d9d00b75907502ead3aeb2fe036f2d1f7ad21bd980bdbc8d22eaa472ba9a6a24c7221e1bc9002ced1b85a9f6027568b499a7b00364e09ef307c795d7aabc22e5c66b8abbfb84a3b5a481fbd7e5d84af2948d7499410d36df73d756d50f9f33ac89e62ce03cd9b0b070bd1a17a4788db75cc476521051683665f16faf278f49b0e6c07a81cd2e5252730375f5c589ef1022495da34251605ca5a089aa404fe632eba414d4be98815147caf8d833869e280a91721874993260d55b8fcd358aa94af7984b605d18a89c8d915dc50cd331219f61e8a1a03e034a26200ed244991c4c4115c22c0e40d333c3adb2ba70f0cec07f84ce82e21c68d17709080a24a5fac9eeab8130ed683f9eb75336ee45c48ec424bc94534d134710b743d0f28e460005a22b904e3d0a396aba7430b1d3d8c6109d9744bc2c34be489a7c568c5f0215e91ad9c071923bb1950ea0d4502700fe646b87a97cff2ad86177c0ad62e554d093c28ac10e82cb71366895c2cab44b8bdd1eee0d7d01b0d7709c377c54d05c4ea08d843d4d66e4e86ebde942e21d21de4ab2a860b35720538eb8429549f1b462887e56739c87338fd759be21eeea75a982e9c8d7a6635d9fc3b5a80508403dfb62988fd5c088b57e6351f3adad53e97c43f9e41383a5ae9eff27c24f8aae0415ba927690be6fecad075212f54dcf62c77287ce2df6a7ea04cb252132b2eafc4b8036f07f44a5fc70c0b4bc890e30c0b531ffa08475b587e20c04a4ea3bbb905b76615642f55442f8ef3986cfb999d22ad5f0340ddfc1937c16be3fd424eb0467e09dd9e5dced16835955e37ee62cfc79ca55d35f994c558080c6d5efc1004867769ebd3ed8c7fe3c04c78251c856265abc99a08ec83eced03082d17a7f3d9d6d3b920256c2bc3d015d5ec0f7830faa986d472953025d0f7f9dff6bee00ea5b8e1be77b467aa2b795cc4aabaa74a5a8270771321012d3121e47ac8b30e6700015af95a6a5b262e59ca597131ffa8485382ef83a4f7ec97a0cc5942ddbc3456570317724b75b156151be904099a969821585bb53b4544785fe514be4e5816ed32b94e492b635a9765f2e53c8e0681ba3d1f37fe2c45e8f9e8a09899c42542445fa4e3a7dbcac76888027c09cb427c4bded5a5a68d6f7a9030cd43295f33df3f223359fad845f30aef84c05cc876febdd257a5c485ee0ba84c47558c87c3cb966b1b193ffcb4c2e6073c102c5af9e0e9bb434b50db9f90911af1242395c13306468ed45bb6461cebdc982b8f7b2d457b1c80ac88cf5b1c9cbf8fa8f207e05e619bd45ae593da63d22e9a8d63667792ec28db4215edbc212778ca7b1732911eeaff12740de17a8297c8ee9efbd52c5a178ae3cd1c1ab6e4156e29b304936fedb79bce166a2036192db8305e6f34f84e8576cf1dce4d883fc9dbeec726eb66ada178f206253b225380aa39135c3a8478389eca9a051f23cf53ff7ee0a50d56decb820a04d89410ee4f92ef414ce0e85a653e69b831c0415d9e834dbb5cf9c8b5d66734c7faca353544b2fd6bd388fd8c07e58e351744bbc0f59100e8b4c200edb2930c05b942525c6e00f74b50794803f378699788393c0126b3fc018dac6b61dae4dfafee4f388e98ef3af4245a9e6c52c8c9159953d4eb7270da0892b78c085059f192761e3c83b08661efc2aaf2a36590cf563ad5c935aa168693c774b0e62dda6a15f8074edb1ea698ddfb067410e90c058338ebe5a982f5dc65619f270e09cd2b99090248f5aaf2b78b1494a35f90594d0b9722f4e9fc125947441c89312b73c928050ddba37355cda28e526466deb3988c07345a52f1877040460ab89c5508eeb4fb843ba87b46cf89c2d1c00e88472df8caa7336c7461cee2e30af4ebb28665311365584bb7f0fb63e26c048b04c5f712e60a50d263d724324ff8409312bf931436bdef3b946baba88607179d4603df8af9d924e1f15c5b6f167c9aee7d664f9b3cb2872f35decc5f35830ea33b3217b46d3e91feb5102a06c2ab6216689d4e413a2784a3685572020f4ccd9fb1d9686151c3a6ed192b025beff144e9ea5a3128e8903103c54689d23a1653447f07d7da3e50408d68316d03711d32c677e94c6ebe84aaf40be4a598f1769a778c892a842f8f3424b8b23e47b3e6d60cff9d62d95bec35a2a47bf6bf0f139040495ede82e42de72e0e2831317a4b5dca679888dca0d970b9128b849fa693fbc2597470aadc7eda271d4adebc25bc854adc06a066a46c9ad0b496ef4d25643d97e520b911b1087826d72110af311a7f733729dcea6906be823c230861618d9d85d6ddf2e9798d49eac7f2d90204341463814cbcfbee7a6a2db49bb8eef3679798768634276c580e8a6a479ce4d306406ce2a6692b1357da8e3eee46d850c17a9edbc5282a6924a81989cb142620b4cc6b072d56603ca0b18ade8b082af9fd2c0453fc9884945bab5a1bf762fdfdea63a6b8c731e327470f6a01651636faadb9b6cea7abf29b453d1d7403eb82023c11a557542a6ba2685e2b71e8e952fb464f306fe46b6b2a52de2922f2171557d33ecaba2fdf8aab7a4fbfe0701d4b6503afe2aa0f90e6f8fe48210d6e4245cfa385ec8559e5b8637993e9e83cdb85455ce8c439c36e859413c53072a1365d739aea78e1a6238e8d4e6d702a1827ba3e4e6962eded2f6e0bfb39a893b5adfdf6109a9d2ef3ff56ce96b70db65a2b15481b33a4694943ccd4a4868d0b3662a979df630aae31c757860b44904639977f6ccbfed6a586c177965822221581c67d5b6c2de069ced68d99abc7e7a31fa73b9eefb14e1111c462e673358fadbfec2803ee61b3f75402c349d9ed74610f9b375c4ad3d72d53cc013c59e6d6a3810ab3f0743edc736dafc564ad764ec9f0f49a5a730479ae6d52340d76b10047b21c0e574808c2477dd272eea94eee6f2c922555fd278d5d57f3d0a87218c42d61513777bd605cb31a37b80ac777c3f5b157a2d91003955fc4d28c5037243d75965b31fd4df7387644c53674b1445ba23ceeff4a10b16ea0b1d380421574ceb17a591800aa65cfef1090a6c8e5e048e50544787e85c85b3488719f95c92d4fab4a904aa536f81448a84c17a8a89943d21190c504a5af9ad624ddae74046c91d3d195730a35c48957e287073ff2862eca56d85fba29f3f40368606351b5e88a54d9c47c29631761029489af1b42f978799e18cefb139464b023a98777df7ed5af62c60366b5f7afbfae94477f77e694f482bdaa018728d38d8f2f6241a516f975bd61d10b29ed922534274897d0756bbcfa6e016aa4c41ea92acdf4767e01e779bbaff81fb4b6cabc5d3069aa6dbb17dc0edf23686c7b1e7d7503cd2497537fe8729de9b0821811345b1ec4cb46642b151057e05ef25f08ff92a7d8f5113627e206c49e1179f5eb8469e3ec8a830c9a74c66231aa98eeb08afe4ed9e869dfd3f8328368d4f036efe3d754a070a3b5919531c0f1188cd45565c734eba99d9691305f383617b3cfa66f2e2ed3664bd6ba69353c15c79a105d0f0a0bf095e5942aedc825985c7bf237b385d9ff4c957df15df0215486b21a9bf9a6e3503fed2045e0d4e68df5776fd9c2ee27aa8b6c54ea467accc936aef38d135522bf8c2069e6d3a94968a40fc81210303dfe921fc83195bdc433882e9dbdd378667b79586a491d34a7bd801d35d250db1ab32a06365f7fc5996aeb74ef6545ef2ba877fa98abaf3ed79a7b5ba53ae8eaa6410a8eff75c054a0cf4cccf2dc38f523f2bfb0ec61d93db7371fd3f14b319652cbf572b4d2abdf0e64785d4d967495a702764bcddd873bad21e2473dd8ebe98ab20593beed2d3c427bea21a4aed98da2415d688191a394452582427e682190bb1ad5ab036497a3f7e516f3b3673458c1e0d2e4e3d565dbd1437fe640dcab9466d3197b897bb88c1cb8c413c875c0a7eacad7dc91f5cdb581f494173c8317b2ab99ae6f0899dbd5018df518d9a9b5f5c0fcde5c1195e0e98b979e1e75d70884f98c71b8db4c8d3685209b81fc83eeb974d786d9c30aad5174ef03c1470380828ae9efcf44e684db748b88141614b21c2378c6c98f8f393f04832eb29b5539c5869aed0a8dd3fc9376bfa4e185a1ddc036104028f82da0aa0683cfbf95d9a3cdf3293e593c81d50eb53ffd01929505b7fed704e7324377d7c2b1d3810c2ff2846881ce02f46f1c64d0de166a4f197868d8805b8694435795b17d9e0a2c01c949cf5a1104d7574e8e19c2c75d16b1c031c0c7d2e785106e02e0fb71746a87a347f04e49540c5a428adb09668e76c319cc790a6641f42ba56b1dd1ae9e045f06791ba19f8fc76c184ebb0dcc1c35d5115022df2d0cd9e285542971d28a0dbc0fbc1c3ca5d7bf9cb38cca599d476a82f9c947612a8d5c5e1b070ced6b478d21287a6a2b22ca721814cf08d5a9fa9e4903ae64a27390956a11e404c2e58386239e9e442f9b185912e8dd236cddfb189bd3be55bd1e00f0d175a6b59ac6dcd2f771e30e6858370d45dbebb8b06106c5fe98b3e1befbbccba6b2f805b8cd75d18464039a942850f89d84efa351c58e461d1cc7045a19450214efc6fc25978563f17f99a6c0d6b7aa25f8c11211440d0849f3ceac5291b41db194c2f12e8f44508b83368246acf092af1606ab3d015367c55b74d22e72031c6cc2d8fd40c82c5e52210eeb6c1dc6d1b7fcabf8529d02781a2d0e3f33bae90a5828b8217f49edfda709985d3ed1854021d094f81fb22c6b1094091760fdcf502140a462cb500bf48636a19b69ae3e7e440177225b0d4778286095ce7e1f97d606dbd52dbbd38a67a98ebcf4505e2271d7a5074a9240f734e92bbcb24ac6f5fb78af46465569696f626d6625471fc981da2c6c65f4065c33b2c186cf44a0e1038c4aa7865fef1e6b4b12d38e8da2bde14a46842d8283fde2acfec99329cf8a59d401b9fa797b6ef6fe9c80371e5c954dabba8d36f6064fd896fdccc9c9bfdebc64b90ddf203b5850d70692a68cdc67c1856de8e7bb44bc3767bb699187f65528c64f202bd2a3255e22dc54b7f73fe66618943e509e990e8f4f7c410f08e2fd153e8ccf0570a0d94b89302c081ddcf9ccc1e2229c7240fa9a48ce030629b33e566053254b3f5491a663ae5dea1f43aad80b7f8c2ad4765dc1de0dec5c2f69d5baa2acb953d7fc086b0ed5fbdbc461577e9c296808bf261f4b1a0484c85ed2ffa1c3fa5c63eafd5d6ef58eb38e2654a193f2d86f64902cd9420853332c970b0cdc28a6eee2ccbe2a54a180511ccabba72c1fc86653c8738b8edc1a687693837feb34531f429ddc4fe8f801966460237c52243193817c3679b753808ff8a1b1ca88c0ede28635b3fb0b655b8723e2ba57e70f4dc2eabbfe59affe9344285354fd8f1e3b95d1d3a75147092b5f01b9352bbf6d1d4421eb7a0b5aace28a316002b2b884454708d4254d5ec3048411e074e86b5414125ffbe3e39b66cc5ef7082f13f6295054694f114fff0b210f310df52aabf77bcf13644ad737370b34d6b4f717ecf664d3e4926ee6259f31e8ee1d9bc129110f0aea9797a820fae56ec970daafc3707c21f31bfa54005b065be4dedf9970e528b8065f6ed0dd14557b1240af317595f99f9f72a19502a73383f177a4d206c5630aedb8d26cb0d9f241bc8b332e7fa28ffc14d0237c477c086476aede4695bf7f5e9a56d4d3e29cddb6789b50473a9bfbe921f67d3de6eb93744d63be3437898a22b129452682fe94b317560777959916a7485b346f236d1c44aaf7ef096f4d3523673bdf195c03d520e0819a5c11f90a25547e9eac387057e45626ccb4eade0c82cb2c1d91c9f1c08b091e3fe6f0bb64bc87c8efb13fc8bd16292d48ff32e6ee825ef86930e44e9392b77c374fb6ccce277ad118dc3e44399ad6b79fbc28a6a5729a5860bc727415688d6d8d67df9c8341f2041745fc9bc04a4c3820126e7542768fa868775d306af5772bb8de8185f5b7045a2b59e2404c09e55b7d765c14f3b16835eccae660067b937fe59076e356cb83d3e441ca045f2d8c1a71797e4fa129d9b1ea2f3781e183b1b67374366cde517bcf02052e61ac7c12bdfa5ab249d7eb413067e888d53121d339787b40dad5f3129192174add3a1872ed7f9043b5a74275e62e6c0dc76feb88c432ba35281612c7b43506d5323eea8c3106b8d337aec3bcace5019d594fcd13ef76469341f84ba31e03162a07dbe0f5ed01cfaca56a88dc0628e7dd86e7557fbddffe4da0961b0e8a6747d624fa62c8f7dac607b329e21d3650c4d7408ac174d2f6a286e9c5ca335c072ff1f1f1ca962445d152f0a70c3c01066f7a3bb431a7a1f38947fa4f031e9522aafa0467b1b46323f4c72fcb9a5b48df9925fa9a18828a8ed7d013f8c38c7845e91bdeb02790ab2f0117d9dbb9ce2000a63cba01e30173f150ff328c12ca4feacda9f52c47693537b8c9b33cf4c69a931bd8e8a3bac9e8b9255ea681c275acd84fcf19df359df49b2d979de24a59baadf88f77b4c386c199a7a48fe200a445750b57110e08d21350df8802d77a8484a99a4d0e99b3710c459552cb14eb0b05ad221e179cab0c0f6febfe9813065b87cb9cdef8443019f2b3573d1ed0ec34227de974fdd230df1110a472ba7bc7817513085ca153bc420f7a84f4d0d6586a40785f4c636301d47f6f7d5129e6ddc749521bb9e992b4b03a3393da4c70d583ca524fc2228039e291ad9cad2115cd6efd6857581fa2408e649bb6384430253b4c2e69afdf218a7c20ffbab3dcb82f4e87a86f4a67caf69ab57c023ca54e0b2c42446125c242ca77b5587b82da0c61a11d36b070d0809f1bbde5735b724185dab14eb590b6fceddd37cc97c9a13f4291735d346cdd5d99ca52f7b7776b1315b054dbe49d92418043b71655cdb380fe7e9da0f8a976fffa8decfc3cdbc983b76ad98ebb0bd9cea7083d0d56f49db89c8a43ca8dcb7ba707fc46a0a1510cd2ac2ade09e8cbe713d901c025b772cb7cb1d7a7f580d224f66ffce30a63aa251b2f64ff0b2ac472bf29b745fd199ffd9d4379b3c4a765f7d0c3d196b4ab3a653e764f91e107c22b648112bcb5d0e51825225f240f1bacf02742bafbfe48bd5f5d865083b9636d53e7b9be211107f50a072a665ca0cc80bc584db5ae15c655ea673fd115041f18b9e600f0f15f4df49d845c57caa195b96ca8c2008ddcdd91fb9162648ce4e763e13fd08aeaab49bab107292914257e0998cf62e43b4a60cade7ce9e4ac3c88c1ee690f2fa17ecbb58a0aa14e89656dffd5f685e58d24999a4de6ef2423cb6cb2cb05977072c170d732e4e0669e737bf90b465c448a19124c38899f451927718369270e42d4ed4f8b5c7356ff5896549f9b922bfe28fd8e892c8ee2bce3c96afe37581e2184848b2355f6c0e99a7a8149ced5da1cdb5df54f34adf6f56668d1eb30114a7ef3d8a27f4efb4518f380f3157a503ffd6d8ce594efe77bfaa4bdcb8aa7b071402bf9871a550c9402e7b0aefe9259cffda7b05f4c9957b686694408826d8e518f12d73e506dde67631e152b3301a5bea838ae208d9441e78f76e32334f723c3468e2cbef7a4aad36ada8d2df56d3521ad35ec2f6b0c6b34b797b71278fe9ff1fda5a87876402b7dd4fbc2750a5e29e93185a557cf4fa69f45dbc6ec61e44d30acb835fde6e869af97936748fd44c326c8c02e29d9eab03abd5e0a063325b2485f7fc22ccc282537d3298ac8a29e944e3d9b78d4b46da9d85cfcc21bcd1dd7946eb8d6b72ed092aec864b5c9a653ffb79e49dbab6b7f52b44c75131563d57f71a44c06ff29f36d4c7ede21ee3e714df4c8a042dedbb8cf8dbbe8a7bbb4578b641d9bde2c8ed52019592ebb4ef72f34e3b93b20279b20f0d274427ba716a8b18af95bdb21419d100b571a5fa9e1820ad04bec5bcac53968c5bf57ecfdc6eb32c92a543da2eba4002d86aaff768b0a1b51c1f79876fbb2eee83a7182fa5f4e24e17f3acdedc95f9cf26c68d72326abfadda42d9eacc0f90b85289c54f0cf6d388941967f069b0281707f5f73e77f372cc22e7ef914d61474463a38dff4e4135a55e61736df5559108e250b632fee02e98100c528c48b5b9bca1bc04ae19c70c81386fbaeebc1b7f4454ea4510f169828c19524bb33ab2813e074fdfba3c7384a19d311d3fa9004b6c8e7829a7fcdbde74495f7b82803c29bba28aa7852abf69473ac3d4d253a3dc78fa3feb997e7ad8485acaf31e7cca0807c58144d2de81de48a8bad3ae5f141265beaabe15ec932a5d7da5100da2f8a6f4037b9c264a5e48d5309dfb70a8931837de0bf2e1f086c433f1a1e704017a3ba59a0db8f77f7fb79c5c0e437baef6385c62da44fb7ccfda66b911cf3fc357fdfc537958b21cee0c6e053e7875ada8038dae19357325bb7a08f476d809415c4faf483915dad4f7d1d38b55e1f6643f7de004108ccb6dc5ca5887684db0e5ca89c0640bd2d783c2a938d360490d6d7fbd57e02bd7e3253abdb5f0d291fb7ce51d4ee4d3821b6bb7de55dc72cdd49cc230510ce448039de54c574a4e3a1707e2e8740b5abde1317c0cc8a15790a24a14422b23c8ed80aacda2f98649cdc46be2da26c426903b3bad35ee7a965af19afb3a0e51bb9af47919bda7cc4236ce64dc8609cbfa2c403742a8c5ab2d1b02af4ef31e83b895b2927f43e07333f6fb8259f23cff39435b57664b0dc725d0105deedc22a5fd3832612f440abdc194ffd71704810b5ad088211b3ad9c70bc1e387b43f159a4349e33937049193322fd361d1048dda6dc92b8e829703e6cf3aeeefaff0ac9ca830a4538ffec206130ef3c6a021d85db1e3fd43117ee80b17b5cfa3ea242f927385a753bf14bae46fadc7e2e62489ccc0308cff9a6a6a1d91586a6345a69c95e760519f825aee6eac3713a09ff351fd4a3f9d58c4914d47ae661ec46b86d4b2647dc5bd5ce1fc44b16e8e14d1476c147328c14f2d75d4bac86a41dfb69aed0501aaf316f9c1d00f6458191004baa9a8840a0456e41232b0cc9b4d4d5648a572f59064216d39f2c67bc8e7cb329084870bb55b80ee47182ea0eeb2eff9abf4fd601949403536a3377d5f151c10bc1f2636c2c4b7035bb34ab0f7e4a21acdcecf4c46c7fcc018421218aff6b50ae88aa40630914c37421e670feb807916246d50d87f0730824eeabd475d31f4a941824d994c87f8878379afea0a6e88d7006a343210cf8f6380f6a0db0269c9cfba54c199846e2ba62ad6e67999cfb350dee985a70a17ca13cc4ec712a7b54e3ef00d51720df960cd4969c06d228f8b051e3f1e9bd077d69681b4ce4049872e4dc39082ee582171df117b9023ee0ad673ae3e545cad333e6a4b3d6419b5868527daf00b845701a34f3578037a514e0c76382620bd5826414b571408e049a15e902e488f5e884ed9c5aab0f722b0c2a2c089a9fe56f9ac3ab4e5881ec8e92c0f57e797820f8ac211d5d7dca1b401203c0469172c96e963e77879c4ef019c203bce9b1d3fb7b91d44c62023bc6fff18504e54aaceaee3e053b370facd51821004ee56de3ab9cefada164a9c041cb6574aed03b3d062e05f5e97e56a156869ef43d67b296eeb85ea487c1ea0322aa72e453d844834591ec197494c2666a682c3be84d6aaa0957e53dfb07d2dbea7a5c0fa8566fe92045ccb625522512027def83c16912fd8fcb46ea6d268b1d35745a9f7523cafe958edeb6adf0d010c80e6dd6fd34be578c39463736124a826375f72adf9ff785a1689c04119ad14a65b8d1ee74c69ff35e693d8cbcb9dd780183460a0a339203bba6acd117f0087e01c515aa532d53d688635f2ac93a703d0eb38b92511cd1fbbe5f85da043b4c78aa938e7682708fe2912fcfa746a79fecd0eda59ea01bc36308ae9506e1533a91cbf56687aaf860a6a7f51d5abeea126d0bd08091e9e77c0b9b88d67e707225bbf9775d797229ca1b965de8c79696f40bb933366994ac1d612c193caf9b5c06841704307b0f3b78d6f9cd7cda8e0b74dc1db4a23a6eafb665e377949bb26d34ddc39475e900312a42c0d197319c39bf3f40a3d5055e8bb679eaf4ca8d3d1e1df3d40847fa7440689660b596835e7168b7b5c7aaeae515b90139242783b5c0b238dca964b1327a86cb6be7fb09d1c646d445ae42cc0e8de71fddd982864afadd9ddf646f12eb80cb57f6af3d9d22703071a3c81abad46d58566d5ecafd0ed3b91958b4590821def350839aae109dccf6fb745f65bdc4ed225f2559018402a48cd0105802a0506f10a6dcec5c81032677c6395796a4afc8c166933f23bf8b4d53dc1f49acc9bba9d69dbb411b252b0933378cdb1336fed3daeede5ae17ffce1acfab79eb3acc000f0a034be65c82ae908cd7ed7374fe0f48295ee183fcaa705362c8efcfb3b4ecf18bd831661294f72411def7d73eabdd61d6a1549fc8fe704a6e37566c1c3bce3ad5844e976817755b2e49dd4d2037e78d3f0eb93ef72757055075c8dc9f640c1eca809e1771723e6317ea15091fb7e94bc383b2039c4143a3add07d9f715b2a2cfd5594fadceead6dc94e3b07291cca27c42f83eafbbefd8f47734930af31f425344a76fed2f524d0bcb2bf4fbf8b0e8f263f189990da05bd03f6e545a62b868fd6acc599777a33b380cd0855a6df2f910602c0c20141c5c637bee3133a74056b46723812fd0c14f7c8f9b41f45411e8f7480d665bbfc7f193ad0686c2d49f39d3060f5ec2357bd4ec9a343ca4db611d24807105d52dc828a901acba05ae2f08e64bf2014e8a9e58133ea3537a92385eae0fa0f901d1b9438c646b439365fe4ba4e89d60cb9a972af0f79174fea58df5d06e2ab0967684740f68fe61d9bd9172a69e90a76571967e6e809f107bf6e8e0a8575be666e1edb07859d2d4a33004f60824ad84fe1639529069f5110c9b77bcb0ba071b5fae84074f207c8e91ad3561e75f2d5e61d4adc550661234f8ef74b9f8060e493bc0af65fdbdcf6456e3c7dd9b8201c4abb73cfa53e0f387d65d9c038eecb2937a243ee5f4eefb79995e6964350e8efe17a755e3013a42f0867dbe2370e1071263cf765a6904866fcd0e7e2ae9ed3eab72ed57571348b8167fd54691b53d2e90333cade8977f6d8ac857ba6b9cc01a4e4243e002513a237244c33eac4137e8061a91fe1035b540a4109cf7139982bc5bf38cea0202a3cb384a74e5c06509e9a4f611976aad006bb83c1e19ae06c51f3ac7cc648ed06055d25a2acaa99f6e943b2691e736c2a67b4899944c5c2acf8ff8416b987cec8f20c151195c1c3347e9c80bc71187fffa8ac71312c887bdb8ad4c228625f71d4bf8c053bab9844a678cbd522868c9169131eeec4713f86819e42e29b79478a1f893920e9543331474fe8f193355ec2b72bcb930454f364a9dd34d8ffc9d293d37ab5b97b36706ead0b68651020658d8973b1464eb82bfb9720d137969ba3ca5ffa2bfbf4b96a5d4b4cef1329c55b5d67bf15435e4d6a6a6cd33baf6629cc1b21d07fed17307131b7d2370f763b38cb247ee2fd9ccf9b96fd4e2430672373545e68ea6662a30aef2a3e2966bba027ce230f0475a04fcc26f87afdd4b0549deba63a6a67a5ade8a247cdc7127c7c22b952d386123e105887465b7147019083488e23cf2e619307a09aed498aa6f31f4529f43bca433ecebf573fd410b5d462dd2ea7e3ac102272eb3b0453dd060633e3b92e11d984efce17482f93fecca89e599dccb9690b7ba72b04805e1c36189d96420b45f198afd1d4a40708e95118c763d9dd47dc92fe973d2505961d11608c10f707377b6204248b3826872e2b0fce5eaa9dcca6c8cab07447b9a491d380137f9da03b07ca48432ae92e1f04b71b62a18e1cc4cf8ed2860f5ba168972fe36be135051d3e1634483a0cb865625ea19ed50085bdee89256130a58284ca00dbb5b041ad92c2742ca4fe5dac0fbfc56cd13ecd8b51e8c5616696efa39e4fb883a66ad07adfe4386d095940a74380a51515b1c9d2e5a65e76e75c79cb2d3836b77f5515e5d4a0cbe8778c7e737c0216d4f743af43275295b45fe4ef3d1b2c5529b4db647013ecf3ac5a317541e2ed4507d853c48be80387e862b6cc0a97f13507f9b8dce16f7d6e623edbd91b925c1b88cff077ce50ed2e6e24291811401fc7975c40af5d73bf7b4c9b456",
    isRememberEnabled: true,
    rememberDurationInDays: 7,
    staticryptSaltUniqueVariableName: "5570ac85afd893abd6ad4907d1416352",
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
