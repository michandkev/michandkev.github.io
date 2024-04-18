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
      "50d5950f411e16f1e8f39c25f7f5d5f06a8e44a7c8508be380f467f764220fe1e22a08122221fa069e108db062bc022786da47f0cbad14eb436c19d45bc2646a5b3a5e6b06da50ed551603cbdd0b69a0df98f02e57ded00da3b29460548147301d3d3c970d07d22c206217b2c193a578a50c988bb412c9f71d8a1429ceb3f2638903c53c6fc97847e0966cc032ce447244520fc1f96fd4fad27233a2221ae91134257bda414b407ca20e1f6381c04cf7d4cd3ff6917462d7f28212c6125aa0c8f4fe356cfd671d89215c265836bea46a2e60f8d1753c7d08d293c94f50e4217fe69e71dd50161027dd42297bc8d69cedf45de026f64a7787688f1f8f235d230451a1ebf7c0dc607aacd1ed858437247260744018266a4f3a514917cb4ef277d90f5209f12d1907240eaaede0b9ea65227e932ebef6aa029b3a714f62530a48bdedc65da90c62d50532d73d20a4f8f57c2858cb275cd0713a8ebc7e9c0b6450806af3faaa9d0bbdefb6d329d7ec5d1b31d63477c6cfe946f27f126c6ad7205723febddcea391b2c98bdec35ecb9c1c3d47d30ff927c713b5e4fc8b5eaf2e5bf9f09ad8fedc5204edc9d198281811d2747f61bb69d7a98966f2a2a67ad4667789ccc19be2488c8677bba7adbefbb08ea4a008f567557165597617dd30223f81e13484a67281a98f755ab873219828b14c9e9d83b018938e8a0ace90440750d4ad5629f1faaa27ed40da1fe655a1909cc7aa337f1a0c882c7f1368eacd13d9e3460a5c645a251104e4b9576e37dc2ac6a854f9bda1444ebf22b844dbe4bb5be035a692a208d7bdaa88ea25795b1eebcc72f94a09296cb1f160eb5f7775d69a65142a410725363b216dd9f5809afa948649639ad6d647beed5638428d03f6126503b12cb86154bfe70acc183a76957446d7450c8a25bf71e02419e6e2f2b99640c4d037e883422f3542d08a7ec3f569e1f48f1a63a42e2b87644dd0fe834bccab80d208611c48fd8fbf1d7d1a170418fbb2b49263e309624c2417734468c8256e076197fb629a94ffd90417737311b8a77c7b248df0e011f0bc54fe7cfb32f16d101a00482dec55c95c6dd764a51e7ac394b8d334db35e5a79479c1a6ea41f57014ff98941ca59635d3b12899f227e71e4529c1ac3694e5a3800c963eb08b8c995c4838653c70cd6e8ff9e2ad8c9b7b588a15fde2370c15e6681ccf2f99858e9a2a741ebe5f5c6c928f761d63ba69380421c755216ccdbbde4e54b1995a21d1e0772678717df7895946361d9b065030efc342143f9142a7762e7bcbcfd7841b14a99fad731220760267515aa3aaf1224afec5178cb73bc5ea16343fbf751ead00e052f4724e17a6b3419b7b71da7ba865b9b7226d12cfb0bbcb6ee82bca2e9d865ffb397ba0a5626d438a4cd11020bfffb3d57972e3e268013a77b758d8c6813e02c742feb5df0ede83514d9332522f24fc027cb827dd5969896491362f8dc4173b232425e6f9a48c812e83fcfbf788bc9f493a8ee32df9eb06e6572ae78de07bc01f915c978c439781c7f2e7660fb2fced7ebd52756a485bad897770a4a192c8b9802813e33ee77599bd3d0c20fb7607ce2b98e4151df9001b124da3e369129188466b8fe0ecee9dc7e7c8424c0df53cae9629a80a055745448c39e3ce62186bd014a89b74f27459bd2a50d08e7db883d749e9f229e56778c7ef12e5fcd34764706ef44f7187efbea244c52da6c8ced5ab24c4678bdaeef9da8fb3eb09fc07814e33a1a7226519309f6b85db742445ad7e9c57cdb7771477f6f9f524d957000859e9cb5ccfd814cc51da6fc2b756938f847713cbfe91f9528c4183206af84289d5fa0a49963fb537503438f2a32c5301dca6885a0ca7ea3bcb2ceb493dc553be3df6bef9183214744752510e6be5022d44395fa939381c1595228594204cb118f1cdd27e9edfa63acbceab9937ac0eb3a1b763b7190ed85fec2642e403468a04f9979c2aca359be18cfd4ed9d0e215e5fad20c791c2d770aa73aa1b0f977862f82d3bc8cee269619a6e70ef7d87bb7c605c5a9f1276d63cfa326ab22babdcd640f680ac1feeb5efc9d2adbf3f888d472de01eb9f996aaffae1016874767c7d66f56c585e7ff24be9cffc59f259b1132c7d75c6e308b4eede198f4584ac2ace11d0d76de4c0a85a2160cd10109b2d86c14278f97ce9ac763cf0c8257b1eb54831d7c014e9e7e32cd138cff614348822056b82cf83740aea31791fc1f7cc3e7a5e5dd656dfbe57aa07560d4e65ca6c82ea609e73491dc3356fde1204dad216c79576412dc1b84ab06d7089a7d2d8ed7b3c943fc8e016fe15b9114bfaf783c2312881667956850e6ee04762007e9b293af256367a63f2924e2ed97fca45a779f5ee49a15da05e3e12c3995c8c1e194607fdd57df9e422096fbeb885cc680b6010acff42cc7a45a97b4909ebf75c79bdd0c450c61e4d39d0994871b4bb38fb1ae3243d767a4cc1bd088210df5f7adb4ca7386f036a50fb45a8b7412bb92c660f3a6830a32ec6a99db3422831665f329225b75d937f2221795088a5458ea6dca043e7dd0c21079d4a45e0cf9fdda02ce773d41c7b7958aedd43dfb681c6240718a53894def6bc14239e720f5a8e55c258627ee7fec91aa6eb28f8c4d7e9bfb8c0bbcf253f6cddae8a1ffa211af9ff2f89b50d4cc51bfc6be1438814979c2cbb1c66e812ce496cac011ab850f5e556f86632951eeff1d555c8ef42370af803dc409164e0c9d845c0bc4bebaa8103011189f12e9e98d33ce4bf36c48ba3ef0d2daee8c6ee011c6fc871405a670b063289af3525c8e3262b0f46157c16e0ddbd5eebf7c254cd50f915b4328e8569f7d0f59a86df1791a7d790c53691ee11ad9b88b2b86ac22fa43cce013e7ab5c69a69c14bd58544ab574b383697c93e1d11363a22875f40b1b360f9ee5f79662d0b59ed6bccd5589cd865d4f68f4d6fa3e5907c4bb47017819b243a3a27984c93b5818c3e37ba9ba2d348053f94765d858546ddc5868d419797be078299d3c40dd792a4a65344490101f2153b4d713f950d8dd894f9cbd48b51cde44b3c2dc45419c54a37b70cb04a454f002ba4d716228cc8fcfb7cdd66d80de922ac1fc950f47cfdd657278dc2ea839bdd77233f6417744c9dd7000d495d0f832d7d50aad2cddf0af3fe213ccac294a6a63382834d2be62ef3f2e5b924ff13dc879411c61220b46246e96fff00f980fe23c77d0090ac38648ae7bdb126301f6ceddc602a656d5141a23f5a2165947be7ced3bc4bcfa4c68ab9e1f81bc29708936205d7896ab05bfdc5700e5de58c45194a24ed95b831067b51afb54b2b4bbbb665fe0229634e75a33fb607dcfa0a7c280724fabd9ea1eecac88bba7787de1becefe17a2c6b4067911193894eca39e8e84c583909288e8091ca1b0e9515851c4db10c17cbae49bd1117cba07590e2eae8b363a1a8cf786a23ce6bc31a404458eb21477c31ec71c94f5943543da721f4f8cb8d85df988d38bc61b042f675bd5b748b17957f98f79adb41a8e6f0c2887201a940b4bae5858c08a8a9bf42f44d314ba83504b4b5f90f210469843249bac371c2aeb6b16bc6706c79c695ec6a5a6a24dd70665bc597a06a50a2cb7d0fd1aced75624492574bf75d2c4572da8e5fc71bdbb1679ad1100db164f2b371d57e95107107ba6171594a497425eff6bcca225d2f8713c5e8610cf472a212f8f83201aa64ca706c864e6a2d9e5ab0f32bf3ee1ab070c7f870e225d7d3467689821583739e7f82b979f053e90c237cf08a83ce1d16c5fa500a5f4b0fbbae0af3dc15ac4db601497702f3a0cfe961984fb64b3ada4f5cc439f4ff67af5b1f46fafb576a6f1cae0b74d0f0a3bcd1bb8ccbb60abf9c3e052d63a7e1f4bf437621f05543eff2ef493c70fc4fa89edf948e7c587735541a6831c2c5d9196efea30d71126d31f5d9d03b8765a77c6575f6aba0947d293326ffbbff8985cc5387d47513695a84b458b6894af198beb6ce90f020f3414d0bfa75f750edae8e3fbba4d1ac004b4f9d14319c6e6abdd8e2943a2a7886ac545da77e180d752d8bc9c38dfa9b94558a38beeff6c2124c473786810ffa5b2a5a8584727903695e3a8dcbe0833ffd2469bb7df68f316fd4d62e1f203ad85bf1b12f28acf8731bd10b1d94c03976e4dd52d5c65768d27e115c8dfbd6d7c0760b723814fde648507631bfa26f3d4dbec97c32616845281f11c00233119b6cfec46ae270e6b11239bb851fa85ff691c702afe5c3811d31fcc362eef3db441fee8e0ba5657cc813023df11a15eec0f9aafc21f4e4cc67896403296a54315216a97d26217911b8434e29b2459868f1500dffa8c9d63ab224460b008dffa1168e81da1c853eaba26a9a554592219cfaf78b912cd6b02329e2e74fbd1ebf5c4fbbbe2753f0cd691ab37aa83f5b48d161972ba2b9183931a5b9a0470185f27746b140f3ba64e8d08df5a11236e3bcc14299ae2746aadb7f6af3eff00749d12d4d5b14d5e5a595278a5511686d39cfd10a1b5d340c3078c32a055a5dbe3607edd173b85b096320ca9e7dd9784eae66522a855c0b0dc5e1db9d67cc57cd95e65bd6dc25fc2e87996320898fb5f2318dffe6c392a7643a4fe384b502e1db9747816f6e73fdf82899eb3a5af2c13481680ee75adc4225a9d9ff3104a188615038e005262f40e3a254391cee235f9a7605a63b0e67155b12bb5ad076084dda2de4429ddda56dd94d586bd0f95e14c75f2c0a87d0f75df44368767a40c3e20138d3b865a43d98261e70301e5c094df2a4ec2445b6312a403595e10c52b636c248c0a44c40f33f81c36c94e55948885627ea55131265599e6e2297ce38d4496248be6f4f2bf4688c519b05aa895a434ca6792e330825bb5a2c08ba7c79d334644a720a3d59db2792a82cfaaaae7c76f66a089b0d662c61b8099c3c303fb8296986ac784fe6d1c3cadfcb8bc8472fd96522d09017559e3f608d4c835a1aef96788d6f894c0a08b16db38a2da227cc0c5542849cd2b1f6bf70bb078611debc3244bf1f6bf4921da1514ced8fb590fc935697ea0ffef24d12539d36dc3a668e77318caf52e10f7cb9060abb330d317d5ba66afe3334be7070ff8874d6b4615b9cc1fbd96de08f30a833ff6a6709768b0a5c631e05040d281fb3cd5343b0d0f8618a5fda0c1eec629dc7d38b245aa4945075b4c751c072cdbc9946d3d216d9fcbad1d1a82ffe852373918839d3902de30b823699b733f560a2c305c96d61dc8b2bcec77a0492ef7b9d0fd718cc3913812868f3a44e0a038d8ac25fc03e41cd7bfebf004ac71abb22bf3d1fc425635d3859c804ce1eb75782baefbc4d7590fb7c399d8571271afbd2ceba403c12cf551f2572ec6cffa2ceddb63462a831924b6b9e6b6d5941b0be0f610ca927e8c8ecdb71d40da74fa0cc5d95fe20ffb5018b774eff3493e5ec2ca91be13511a4fa7d02addeea97fd38ab75e0f1c09cec2f6ab634fb111538a41593f57234b0c5dbc505459962da6cd6e8d578255bc3f0f044d842a411b548ca9b77256d51c96a5665a30ca961838eb85661531bd59728d4b06f8a21a62afa8776c2483488be52fe52c614d2b817398a302bc557e4ec5995bb51f5f797d5cdfc15d2ea7583f8ad2b80c4c509f9400f377fac83f5dad321be11f37505428d66a559750774ed70c922657e9cb5d6ad8dc281c3d494e4b340df39b19c165fe8835cf39912b98998caf7677a5dbe10a92ef6277035833b5610809149c257c2979c0d7780fb27728c83d9798e0d385c6d85c9fb46d8df1a2fdc8b1ceb7fa81018489f68f6d746cffd2839b975475573dc63a406928d12e7d51eb28c68e34a18b8e6ca630a64b6334262b9e086be4713bc300f97133c6141a4c05bf9619a1f92da389b669201e7914bb887cba0700f4c9c02ca3865b408b7709abde309ef7400487b8c0ea8da183df1ab342f166d03e6219425b912a8a4f726c02b082bf613904db2ae5e92f262c975dbddf90f8a0acc5230284dec45a0a1faa37d8fcdff660f520fd3b1169f74ddc9cf13d04bb97265eb25c6c209da2ddf417f7f59bfe83aa676b1ddb8751475ccbe55f7e3e8b66768e75543a2c8288501b11d9c05d04c38d728a26223e023f627e7dbdee05c72989486054bf013b2ee9ddd748613b865ccbcd469ef09f72ae1adbe95693d83cf5d93ac3df817f7d307734aa804ecbed070862bb5f54bc879216aa38cfd86f40fb749af802b1875a04c194d1058910ba115cbc86bc6949ad6faef535676c484b8374c5e9a2a4e8a5896bc6a58f533b645594063e3eeeaf51b76cc7ba1a6ee3a67ba9d484476a30f2acd8b6e748581c1e18736a79575805e28355a33620b43ea43ac36197579f7afadd1cfcc7c3e58f026319d62602c9a7f6364e1b4d8e414cea105f4d3a85d860d227849ed6ad86bc67a97701b0dd7b4502c2d4dc3129e685b36c4b753d38391fddfa082e7dd958d45b96f383dea5e29e5e27df2b804116420223480d9af70e3905b41a2f51451f7f23c55d704ae2e2a4b2693eebd6164dec0ab70c7cc57da0e6ac2abc234c82ab5d5097f35bdb013ed2382af003f5806a6bd5520972a450dcd4ac66b862066e48199733d2e55cff62eefc1dd0d247905d99c2894f8773e0a4ced80f148c8ab7ca42e7dc075730baa3a3fc532778ab9b7da8314f1bceb3d2ede6e0503c46508e5cdea69a302d99af9c692bde2e8a035d047f112ef3fcd17a9a74469bd578799615c5a4c285e264a6d11ba575201140c2ad10cfddda5b74119aab9528eeb6614ff2cf623d8719d810d3f1100a4cd8506e898ce84c7ea7b26f4ba9110769985ff0a3ec39bf6cdc71688af46699711628228b14eae60119dbe6d83ddc3087962c863a07c90def092d3e23668e9cd2d0e8fc0dacf52994788d732ea6af0fa85cf53e06ca5e75f0ea948af391fe785fa992eb7d7a8a0efad1e499a89409c0a3554d092390565f537c9990ec9d98e9ab2b5a662660a56d7f204c8265441b5f188d9ea6807b4631f7bd4639a2bcb6dab245cfa17e0de73e757ed63c66414c4f4230a5424a73852533ac434a42c5e5312a6962e0b60fc3e0920045b1ab84fc6fdc573f3a8d65701b01f1cb24c97d9b8183ec262a64dff381f5d74d19aa179d9c49eb11482adf3f4fceb3cfbab2fc6962b8d80142b26a608db68c37bc0d17a367d4836a2941c2b1c4d0139bd557e0b160e69799ec319ab25f7869cfe7662cea9a2c095569fcbf1eb80b9708b589e4fbc8d6bf2893da2068b00b691a54ff5c36a38269e6ae1d56e32793df69d461335f3757d8a8594fa42f7d6f64fc86b26f02d802b02152248fe7e53ce8b50a3ee353ad1f305b34f53b78915daca0afd8d3d886d988b5b981f42e30293f7095207ff417ef7557495dbc1e1becf28d6584c7f6356bcb1e9313b0139de2fd0c999110e58b7f8fc2993a6a5f690d3cc4a20028195ff18a82fcc5302757351246827d1f0adc735feb1014f9f2c33a972b4c072519cf266ba48230726db87faa2cc0d9dc329ecf3a88cf5ca05d0a2055b00f2c0fc8f46e4151f3644ccbb6f5f9bb5c7cbc689fe6cd3ba1b6259ff7a49b8849fc9aa195061d97f73eb2c0d7f395aa597972069b3c46203a85e0e0d070e49ff7a4e932036f100f755f78db2c37c404338db5371034f3199f7cadb516c1e86c2ed9a86057c8a43d5635af31541f11b9a699e3d1118effd564cea3498f5d6b696c84be5c66192ea0dff6ff2352aef89867ee27ab7d8ef1ede08d8b974dd13965019d593f7d1f70408a6e55736ce12419900ea108508c7f1cb6c67aab996ef0b5bd48a60a08959ba19433e8d9fbd41f82ff1658bb4e4eaef697ccf015e19fd1e3239ac3e54bba7bb596c6238047453e528684d71a397d59f098e3dcba7e978f9ca77404ca98b4d8f50930620a75633515b156287809b6f7f91a49ab8143d2e975a11ca8392c1f322f610c218c2cec6a7587131ef92d95cfd480fa7f11851aaafa3a67ed264773342e2d741f22a24b1bdb09da11f4710794320e1e09e93f07fccd12c8c56b7e5910c311bd50202ad348ab2b53c54b5b7b8c459be9036846b6837af1482cabfaee6e10e671ba05b148640df599bc7e3cc86517f432a6bd16bb74deb14858578a4944bcf101e768b5c55207a5e8b76568c42049c27731df89b6b8f24b2526d7fbd67aaa2853d18e50a8787fe6a9ab1b5872dd388bcf58919befbe97b457835ce1b99bc7cdd8c922f49d8150ae766b1d7c4e7f6f1190ef6440e3afa9c31b29cdeee53db8b8aea76ad1e009f83a6bc13c6524d3568bf238a46260c32d6fc205f94a120aec9426a3cdff5e44dde467ede54a56d64f3bd4e669ef1def5e435a6cc127c43227baf859fd16d6557cff9d1f32a62cabfcfc244769588713614b1e46251571e9b52357ab8b3e8086939ff15186365e05800b8b9948418678c74df731e287e885b282ac3d26c5f7d97727846e3645bf60fc19d770e2c40ab996bc892a08e2b04111ac3b5f8f7553f5ea5a42636d019e0234834b83f79aba3b4e86f258ef23078c97fe8098790381e790c9ab58a1a8f53ae42e11facbaa65a7aebaeebb4985efe97b978de9894f67650a3664acd790ce00ad2d626dbaaeb480d174165dec8050ac938eb09dfcf450c3a4e1311703872810f3959a38a21d29f64339d52f63bab3037c4cbf4e5f5d19c920b05476b734f7d986a2447c883ee15879babd6845c54822b4cce2a22c35a403f6ee833cbd8c77612ba8de521fdd2f25cdfe248a8b1be08bedd02eefadf6e5fedd418b82c408b9d029bc587e4a41aef977619883e57c4958272cc7122d04577b65200ad226e27ba0a2aa9d7a4ae05cf046002e432fb8aecf26e9388ba928a50a8459345a17ca5d72b1b8ad7ca28d4271b718ba7e1b2ae81ba02805f5de49194b0fad900e639ffbf5a6f5286302d8039206dcfe0dbbfa35bbfb142cada22de9f25f12ffd34abc4d0b85a176afe1a0ffc1f5e9768f17ba83ce8f9280403a0804988f944e766965cb5f9cfeaeec707cd361ee84c63c087561f5e19c2245e739d34d0bb6907eecbaa9feaaa2fce9778e2c15b75f33022c778657e8d4b65696e670ad6e4165af85c741ae9878035e315e158c57bc15bc72d45e31bbbefaa2fea5c53effec615d20a2e26cd2acaa62c31e9386b7100d2935724b92c563bd6a940424a2bb674ed667aebb7887c7ab4ab6a84e6da505835e288d0ae27c3f54880dd2cd8aeeea078994c4d2f0e0cafc14a5f216c96b948cc071463bd139a28e01f8f645bc442d8be47ece11a78312f20bb818cfeac1c3c8eb5045e5d7f00beabf30a7ea9bed5603decabd30a23c5e0476e5d57005915ae8b4fdf2ec5426c0d8f658c240f155a9ecbc86918869e76bccaf1f9cf3ecf24a57cd66ed7b2bf2e7042202794d02699f96fb8425a7dddcfa8097d7f9fd565b5212b79c6dc3d699e9fc4ecb471383cef07d170823757b5d06317862ade1ed2b631e3e281637ea557f8288184552534ccc01a49e975e5aea9d15664323ea798181bf6a2995d99ef73ecd3e973be168be19b5ec145e11d2634283f10809dabf927a00c8725da199f6e5590cb8f3e50f3c54a3fac6e9be0f5811533105f86984572b09a7d6ef6742f116a490b253560ea338ce8935c4b351d9d22a13e9dc60663b9df1b32753d151e341c3100db91c2b22efc33d9456e36954a90cfb970158f84ff27b70973dabf41f4fdd47b50b03802b2ba53892da7479fdc6c950a99d94e83fd7b6c2befaef36fd288966f53c0fbd17d884f525042537289426cb0746ec0e1dafeba41cbbfd5211ee5b082596b5e5e8ee970633ad211d7874333d098c386924448525c8ce8fcbf302deb41e37f21d23100d4b0a0541e57d6d9a3670b21fec773105c43fcd3acb95271ee28836b53652d4ba46635b1ec406693228f922c138e30ae886398c900b9dad0168e0b265aea9553fae9f74f61d0029e44bec68ad205607833864a89f51c9530d5d140c81efb0d36c51aa98ff1f4a73cb8714e1a864f810833ae204b11e038d4384098ad37bbe64f7e8c7ee4fd5bd60a16c749b35d865836e9ccbd21a7138ffb9ecab68222b2674dee86a0b1e0002f383d9e30cb940018166b4200264778753249389d1256fcd8d5ac9da30413b1d6526363a68a5b9593d560d09773f3d794a7eb8910666f824fc12d947b6dd5969c1b8a954f21908f55504d1131d516b88a5f20cb991a0e0b4a5b37fe77277e1d90fe2782977f4e24acef850a6cac63f5d03182ff6112407dca16386d5988ba667a06e908a894c96df4bdf850b6f5164c85a269f9b9ad35d72539d3a0a87579071b3aaee6649991d03011df8a85b491003e27f418f1bb0cb72fd36b9ad9cf0721cc9e1ee5c6a6259c759175cf1a606921d0cef6cf42d113b26e855a9d27b6a03626dade2a85603af5ea82a0accc479cba5e4d39d49e3087a9c72e45de7e3f8d5ff0849717728166ec06814e6d8e1ce26cb413485b504ba01f646d98ed0247dd5eea3325dc8aa382cb2426ea5179d4eecdc63928c72dc157960946ab0da946de4fef14ea5f587ca6663cbce5d975dd492f1c4c35c345fe51430b9c3b8926d5055996057df44c4dcf9ae186d55fa5e2ad35fafe406bfe7f1922dd91fe7ce41e6b2a8872f6e2fb44ce757b9fcd3721b049ad820d0364d8b58fb8edd467486e33fe764fa71a77d878186ebc21d997228aad13cededad16282cb52fb1a6f5651b794c24bd8075f6cd62471eb97785884588fba79ec7936870c07151f8d6a22ad7c31e39a3e162219f95f8cb9d993ded2d7d9c30d4c7aa17bcbee1891e92fed56c32076ca9e8ac87004e5d59b5e6fe9467313e336d9130f97a3fb33c41cc252d5bb9cd6911fb8d31066c7d8ee83c33a75b93ed4662bfa80fcff34fd5d2166a92100e401b2367ed02c48040b29160f9e53d60b4bdb3abba8b218fab787edef811af8b7e709d93e2454e07d6b9a4ee51f20e974fcb722584d2a2b345d52580e1bb3891a7cf862ee1d612d3f39fea34986cdb0168a0ead9410bcda0b3d7b59a37d26af7e777f68d4111aa41f173b5ffeef920d4ec59c40e9c2dae07a018d1c716396d3337a387e8131598c1e9e039c236ec30c8943be15b8c2b0594a84b0c12115290df020b57abe4f24e404b35b1f58f7ee0a96595388c83a73d7f341d1394df8612f028b0877e6546db1089c757df38013e794472122bd410ab84e7c0684c8b6b1532cf8d2f728db3e31a4b45c58b396d5c5ef954b91f9391ff237e534e14aedc10334820002f35f47fb8d7561423b50e78c3e9afed6454de41ed987916e9793bf8746a70ee98609562e4f6f1fe05b827d3f4fcdb9029445d099bfd8b12731359380eb1549dd560eacca62bd2ca8f9421520b2a87536b65de8d469368147e44de8647e02b1d930672627f2fb2daba24d40f4aec2fee47adc562cf8cdcef70553df2807948986c93f860b7f30fb475fa0d7d23e6e3456bb436c8525639eb3e32f67966bf64275ce8754f751756d6e9f46691965e8222624dd5705aaf302ebd127fcc10f14692b655035bf9afcd0fcd3f943c7eaa4d60dc47853e8a23e0c568c7c28981c59bb4e0fba1b22c474aa8b798910534fe1f38640bfc25f92873bb4151ac8d9702826d08caff0fa91becbcf26e309e94204277d464b3c5153e3fa268fd706c596fffab8d77590c8afa8a525fb3f4f49ae7be679962e5b45d08ec60e1fe2775ef4803dc3242a2b5c291f3c8e931749d57a62dc2332281fc3a9bdf0823004682bdafee62caa821a2d44f8b1b1161c6562bf160b5de12ce1d8ba1fa142e4b88dc1112f06d5fb9bfb1dec8ff62677d21c49b7dfaaff44fcd85eaaa6e6c3eb58e227496aa203390ac5ab390a56c486f2c2acb15b8483ca31b94b530e5b97583ce4cf3b65b8a71e8b3ca79664b254324a6df1f043a3e69acc00b5f99b045fda2131518043c50812e5d6d77016ccf3b503353d05a6386467ce3c19b6cb662087cf6042c121f8ae0022a6944a3d529bfeb5e27710091daa7605422529fc1accc13a44bdd6e776f2feac888d01145ce9dfa954d156b9545f5a3dcb988fc1f57147e6a6e8f3e20f7191d515ee46b86679d7f58b58eec0b89a88423a2872d899994b7b11b13c5f8d34a58be7edfe389f187e03e043ae1136057708b27a5ac762b2dd7995a3c71f751bec92718d9a835a77cddfd0d89d7d6f4645b0bcd1655f490a3b4753829db3c9dd7db07dcc8571c4a40ed155d98094e68d99b2be5a021e75ff8afd24e90b4439a773ceeb722f24fa12692f9e05fee606381ce99208ef69a14c5cf82d0f696fe2c0c27336357a085624fe4d65c6af0ab655851fab640581cfcbafe8ee0cf6d6e2138ed8999d66de9c0b5c9a214fac3cced8edcf5d0c5ee9542d8cde67c558829c38eb017c6c2a1f92a50f30af366e6bcd30122d54255d1a40305b13f23a096c8a903004305f9eb01e3d53c9e9f262bf70b309cb564851e6b416db3b273e0ab3b82e77df47eb19138ca45e9551e9b96638d12a918b58b4b7670c58d2b4a8ba5ac502e5d9cc572783a79b5db8caf123527fcdfb9b3fc8b904f40886610f8b83db896dbd84a36dbecf08575ea18cf85d52b79c80e8eab83e90e38698ef6887f6954d7a60dd7b2e41cd640e84d65e21ed2815f3d44e2c8e3800b4a5ff0a11a98e4ad1a852d7b96c65de80efa2750ddc3630d781e2adb297f01d752136a6a78130549d27612d8a9dcc0ed053fc5d0a11fc6d4cf7f18944763f959eab7866d0f6d2cedc7e753b4bf5d69ad3f1fecc7e1ce0f66a0a287df54e556b8cfd9bb339565ebf70953b9e7015c68f81b4169a7e21f46471f7d8e0c9ce17dbc26baa5074ec13c1a092b56540ca66f184a4715f07062b47ce981d149d5ea5c275822fd7376fe11d57ed37f5e1f76af5823adfe5c67e27dd600e6e86e1128590f8dfc6c3c07516670ad3ad0f483953635ce80393a8b7f75173d28283e1b45bb35e966a0bd3b7fca48912c8bc09fac1dc7c2a2d66e24aef7886fd0006794906054ee9c59edece715d1759797d9627c1681ca95c79a35e8b448a5b05c46d8696da1f51547ae9d3835977f695e7f1dfa43178b084ea0d6c203c141dcdb1557743a6ab98c09880425d22a34bf04fa22e86cf1b7940c1c8a4ce6251c84bd6dbd1d5074200d8af1547059528d771408ae9c14a4bdbc35e6cf647967c37ea228ad33ace310391115cd8546605ab2f9e9d6caceb5be50a07c5a4f0216c61cf0de9101c2e74c2d3eef96ef51c1142fa14c59eec2ee63a4b343377b09e0dd5d9b7b3e4428546a57362e96526a8eb5275c9aa9e1b8f8a297472967f4ca78b5535b042ed3bc2d466597673f4b899a29fa772569cd29b855a9aeceda0f5be9af20506b62a9d8fb7060e7be85e885252a0ca7b5210327533393316eed9701ed8b360bcaec40e7134e6740de4c81f25c905279d2ea05adf12a33797f2ac27c9dd16afe5d7689805cbbbed1f03572240c5c699768e8aebcf9ce119c26f327872ff8d455be0b517209c582dcd6f89338a0b1169645ddba275a65b1b04442458461728e84ca703fe52936764a7d09c355273687c05e00ae05d8080b98ca931365ec7197e354a89b434b2427bba0d08214e542291fb8eef96dc0cddfd399c946f774f3de3ce5b5506a943ccc9318d7bf128994a4d2eaecc669da6c3965a340b89262104e065db5e54c0bbb85c513379251ff66d584c1ebeb423d116667136119284d13e4b07f26922b1c35a8c260b5e50306e88fb23b37cc21a56e3b0fe35970c996d81e385f2892e36054124f0bb28c127c79efbcd3c55412584d1ed2e2e573c360b60ce6a38082bcb582d98205f7958e0b11992adf531d751827666911f6667ef1bd7c80b486cb6eb37ff35c9265b72b58a307dac97260378114ccb7c6922b5c099cb9caf14a1cf99c7978ccd227bbdae49917d89dab6410b16e3a06f853ed8dcc58cb7f67738a461066b43f094f485627d36c2cbc7814f0b5a7fa415ca3bb70175ccbd34d89827c1f74379134a491f20bd8a712e065c68350fc7da358038d5516670c41119cacf63b16ee6ad877f5310da557506c0e589fe934eb06b601d749293221355d2d226363fd4b03a29ed437855537f240f6e41fa162d7583028e7c8af5d05dba52c1ab7424f335741722cc60d3defe7f04e73bf897788d25b11cd72d522e78034dbb067aa4ba3252ecc820c7e73fd3f0452720641d9731478817086c18f501a6c22e161c828ece1f5ec7508ab4aa2b99a8fb7ca9901d07956a23ebbb2909e550b58c2cf8c94cfc81b4b0d791e61500827376d2588dd63e6c9192f0274d4ae8090b1ab73f857d4576ca4567a74ec6cf4854f0080a85b6987482ad0bf56dcc633649291cac8d0afb6ccbbbdc4f84de4c94c68870ee3ffa52226f41fde99b7b315219b070e91132f7d2b7b8a7abe4f50833d0ed741d1de30f94702966445db71d075ab2aa47da9c81355dafc6ac70270662a7138e1b2f860c77fcc64eb7bf8b5d2c5a193322e9d1dfd7247cec3c8e6a638cf4e8e9bcbcaf6d4ac95824e3a0548eee5699859792ea443d870aa07a86f83e577d15f8125c328aad37fd40f32dc9afc393e45f9091ad6161732a7f979c1b23bcec6aab089504086b2da96447e7153dfd4bc72df51e5f7cb79c49314d3c597ebef85694d6cc9b8dc488da2fe1ad730a2d27c11996ddc09967593ee757e8a9ff29985600e407acb99e3db6f5944e02390ebda9ae01d96072813081337c07258a0afcfba77e334d957a216f26de6e423cf71325f07e719cc66b1513d1d3dc0ecd27f4ebabd74c46f68e3ff182a9e400568bb26543c187a95be1979d46571e08641f38a6b25f88cc37d32d23414dc20e2ff76cbc2642f3c525e131a175247e4bfc8e11d7c78b9eec2571973361bd1f7b30e4f3c981d48569f3e9851a223044ad477f6655a82b5046c1a4f552c51a5a907b393de29da4c0c425d56d557a5a25364959156876abf3d8e0eb5a6c05c9354e777ff0a7d53d4153bc4109dce81da324a29f438144b2117a9c3968db12ed605aa25a179f756bb0c0004a0c755ed0555b30989ca0155f308a7a92d16072586daf547f68fc093e31cec2e309a9145e27a1985c54d994b83a1c66396ef447eb859ea290b08926ee24e5c4a4039cabdc6adcb7423713bdbaa75ce619fea91d93bd9042019943597811cc86743611f841d26759dbb1f946e148eb72ed205bfbd608454ab81622fef9e23e94ae8b8b65ffde4caa1742949cfff5f5849074f64d57e60e6bfabfc71fbbc930a6d517218c7d4b9afc2ccfe01395b1cdf4491ebb81b56ffa28aaaa0e9c74302e8019b3f6dc03802a7b9a97c35932b6a8872351d9b72aa0cb9c33fa255fafee8cb0c0465b15dde67c2cb4a96f383ec2a2b05ac2eba4faaffdfabd106e933f241f19d3eb2f97e3185f570e747a886f592fe6ba5a4325fe0e747d18c5a8dc30c1a947ca56619b87ee37af8eb20c8e6390477f7775b9c2c71fc0856062ac4c3d500915994cf59fed6490a15d7ee65b18d4b0e4c8c22b1951160df0c22d4b0db4bf58982527e161aac4a7861fad74b677fe47d9f01364be6c422df10b4bb9fb5479df9437c0f17f515cf941179d1bca22f77f451a960403bf5e2df4f2a168372dfa73f29de5e1210ebfb0cbbfeeb047873369cacd467dd5426f7488094d72ceda297bc4628ece78f109158173e25a3035282000bfb5f7bbf7e0d08ec2a5e0886884b859cb6def8ab35e34677f41a131aeb164fd9588693957ed54a03c8d32dcf78010fe1407b6530b2f651dafcd7ef4773b1b6c10f14ffb486f2cb44c26ce24516fa2e18ada5a822cc7c69370d236b853524b7f998b3566f9fa23bd3f673eebc7c5a42c12e516aa936fd8f8c15a52aec06a235f9aa249510f11e22191c453506140607a1c750151c9b026865be79f08174e5683f6f4aca68774f77fb6f990f32edaa18139eb3fe66a9191b55404e36aa40fab1471b4c607bdd8098cc0fdb65cdd5bd33698cc4a871b6524d5f7dd8d694af5bfd8c68b8f4eea09bc614dce82758e51aac7d8515a4108fe5ba6fce8884cc28823ee34de4c638f2e9f1f4df049483b1a140bf8d86957369df93c84a14f1f478afb4912e528f8b5eeb176301245c7cb0134b739a04c4c3d3bfae74b2a3fd1789d9bbeb30dc8c7ea912f8889330654d512cd52611869716c2cb4bd416ed888415542600fb0b11fc8fa3f63ace75e353557f5752880b9e84b9fcae27e6ff591e0b9816d3363ce155b5a14483588a624162a3be52feba1db7a8f6043c6194a8858704bec0314f15ac568fd5193cd5f3c76bf7cf21d0e4d2df33bc31c1586f6c2a996223f9284ca3866f7727f9d299757b9c23950439a7fa66a6c969b08be4eecbe4198be9465b8d852e65b1a5f74d6861ea0f593fb2017123cc2a19cf0753c42eb0bd260072f23257baa99b981438ebd4f30725fbb7be3851fc1cc0ba4f1fb4496852b8476336d7d029fc52beddaaaa2d663c7cbd39e954e5f8439dd640dc2c0a0de207894f452d4831cbca5edc809fed8401a1ec7617fdf78ae24bb4d9c787aa74aaebbc6d609f5463e882430127ccc75c0ab29a9e9d78ba3a1a2f06e091eba05581b27c94c71ffdc9d877c84d5488ae73efb27751c963be64e2411d1197320db1b184646fcead822db67747cd072ac422b8354e99948be40e0e3a2761d14bfa07e659408fca09459773aa9a1802bd4d82094badf35b84b0600c4b36c2c5786b05a93b1863cd1311a5cd120d74ce91924df082a4af825a6605fd1eb56edd8316d10625628fdc1eb8b2acaaaf82abb766a0f479998a5c039ad1e4255797ea41b7ec82567f4159a3da17d2e5ee887acbe481b06fd12ef5678446ca7da213ca77e0b15dea9d6680e1239be860fa379293f10720e4f3c7f1519468fbaff4d69d7acc3a249e1193a78a39d810ac99c968a28bcf37fec91949dfd2fc7bed87d310e7281b71d4e5fbbffdb90d9d8fad61f6780e421434eee3261b5344768bebb8d9d79bd67006525e5ae3b99285cdc26935ca909acffb49a0139b0a5f45f3c5363a5a710c04561ccb6fdc6d25e8b64904b76d79abe30e50cbf7f056c5643d7de05cae625cca6b8f400df5faf805f7c1d46097c6bf6535026def5e3eedd738f62f956746a80f2bf670e98c48d0f802e27a28dff59f86f116ebcc9d978da6b00a4892b5428964a445c489d3e6a520579ab630e83aafb0de1684f4d251c95334f99ea4d6f228d44c2f131da35a4cce10eb659e9a64fe6cc838ffd0c6b5cd0ad6e2f42d9b349c3d2aa82c4d08223540f21070efb8584513166effc0e1be0857f76b7ec856a9260556a8a248994498d967dc61fbec1aa16cb20d2f9a0f5afd4ad70efff456dbed6f9664663767e8682c4c28b0e15262e0f4893ebbea5e29f86059dae6f1e1e5a42985d794ede786071d75ae2d36bbb05d1733dc9c214d596a5f4c67ff30e8590cca8f5fba4bb514ed52b37a3bbe1964d27d7d58a692973ea01ed6101aed72c1adec64bd4b21f70003ba154c7f8621221f4f99aeeaece175cc67298c79d7ef9c7d97831e9dc7eb04aa8557fcc3bd794926669bf22dd348ccb06b33bf32654710dff485f073c1c32c291581a40f1cff89745472365e0cc803f869d7024e0b2c690910db8be0b9731028da8b28245dcfe63f87c21ef3f50dbb6a291c8b51f28ac0b6880cec54c0cddca509a85a1a31e8fc1138853452174ab8c8021ec52e7017309597a0c3d21b427267634b89b7dd20b11788669d8465f5426ddd0f3109d1dadac8baa252a4e7a8fa1589308f91acca81f5ad18e4abecf9a2b261505d044902fc72d2c8da1ee5383f25089f9df84e299c34993b2fc81d31cd15941924fd9adea402bc1e0c72f95dc1ab9b89ea7ae90c68555f57c2708ce7a1303f81a62d96d4c2452e9ef70fc2f0991c101abdb85c40268843de64fded0ac4077edbddbb3df5bb5a8f82096f82ae9fbed14fe3dade47a1d78c04cba527e76a4063843020e6a78053f12d8f788e250cde3a9ec9523e9c2a2cdeb8f2d4ed3f44053a887183d0d19e3fc62be1d4a0d08c0a7023cb4d6ff4c765cdf70cbb3c03bf9a4ad9628d976e219a873ac1aea4a4167cbcb63ebe35eea7523961bf757ab3329d903e11a83d88240c11950bded4943169e7818d670ff8a62d0e5814c82593b8b96e91f972d98f44af3e0dbdbb2297dfe30e57672a23ff27737139c2990c8bc18587aac624cd9a480d63c1b2d67686ce68f4a931faa87bde6b8cf5dbe793bcccee7cb282c6dceaccb2fbd900da10eb5632e2c85657648cccd442cdd254111ae8652772b03a522684442b5373bfd50a944d5d3fba6ec9deece4efdf6bcfa4008d45c99cc34867070f36f2fb1fd3311be7c442946813a81bf3fae7e6a4f132b57d1f3d11bd992b36485afce7361f285f06970d956bc575c2af595b12ee89565a769a74e24813605f333ed54cb8c5e9895a87a75395205c255e786f3e15f4075790607c494a703d1f4cd7153f0a519af60409d4107aded11d88c644b06c3f064b160e4b35d5bc04f5e6b99f98382bb43ea9748fd9f9810323ae23ca40c87960636cae9a04e86fdc5c4e9b31ac564453fac8d5a7bd9562dd0ed75497ef46c207b0490423822f93e4ebee9803a763f20f71f51bddf8e6f9adb933f4accc76303bd1e272ad231bf73d847f8063bc52f4ef92c71ae227be0b43950e0d10c291b557c1e02f331ed39d7f3eeaf3e5db8e652befcffb03f3b72cac78104259ed25f737ccc06cf9b49740d0d0e94995eb07c940ee62b1eb235a7e224e95aa539a14d2ef5b5c68a09aafe2a408711740affc82b2c4aec0e43d8ea178727ee1046bd819f498d44cc1a7228858f66e86d3de5010f170cda99b203541a56e67a2e02afd39bea642fc822cec986268775294e14a02fa3eda7cfc4232aae50120dc8d6aff0c8cea5f0a55095f60592bcc2178a78c86ebafedbeac79961aae5f7d9e4c31759e4424a1eaaa95b3acd6bb6d1e6b575e7312c1391da11d44130efb9b13d7b7afdd8142c44717f6a7cf91ce22dba57e7029ef296cf211ee23c3d0a94a8f282918d2206dd9f94e42650ee18df3705c2036903dcdbb659bbea7a174e17da9df198d5399efe61e67ae16094f39a56ac2e49fd97b3ebb8166983360f5c0255086818bbd6760f075123a085f7f7626bfe5f5dabc93a48e6e988500d8fd6a5ef9087aa57df3ab10a7573a131d62eaa8d785debbb87bf3e99b7df2e566aad8cf0f02b1e4617b3eb5f458fcb3faf2baa1ec87cdae430c53156d8c78bfcd3806fb89b5320ef6e44f653012a63b9b422e03ac756781cf4390aa31d5bd59ec34b3c479eb634e9909696670865262a661aeb1f0dda7f35918b1e352dbd66e36ca4eb4f7c269ac81dd6aa1524cd801ddf422f024ec68040a9bff3ba90b6a08bdeaa5ddf4ba8aa51ab4c9c0a93172c03b449465a4535c7c0f4f34e1aea4836c11b3013c43bdb8ad45d592e39a1d6935f42259f15457a9452b6511484a48c14d0302ef4341da6786f690a65302ef3937a5b78bf2e3d833e4161390cfa22045df9ef70b36ecdeaf64054daa8dae6a1e0f20ef2b47b427c2d5567ca83e9fce02933b4070ea3ec9db3afa24c409ace17ad5700f02045b02ca00d1728aa38e9b31d53ad79bf1040ae2bd8be2dccba4764cc2652a2b81228cfddd96de0224dcb853f00fc554a4e1570cbb39c8dc53106c81488c27573e97d8ac9ea23dfe7fa889ff0d2d2057713c975f5b17054fe14f14ea326fc9616209229b8feef03054ae420dc44902205a3c4e59ba022eb56914e56ab6d51eb3fb52eaeb3a128e14a40d7861aff8d65967e44d75696c5ff25189d82f10fcda93397c802cf3532d1b17da16bf01f393b32ea4b49c8dd7d73427b38efb51b91c37a30c0a679fe05478650033f40693a6a0a9201370eabee4b10773a6edbcfef08deba606b9825b5940eacca12454728dfb4b5fa6ff3e6e623bbc2de07279b4c668431aea5ac00632226e200ad80ad5fe26000098dfedbd4821468001fef7d0cf7db571253b5ded1d7ec334bee681d10c58714f4950fff4e9e1ae383791893c12c8fdc979fb4141caf7062275e5aadec2e849e5a1cabc05fff66074fdbc326e15ed0cc342f82da0d42a65c5f6c10f70228f5b06906ae4a2150b0bdca9494184e82da6be6000b9f81b8e9ed14c206d60eea5ca68f1bc2212cf489c49c6a65421c036cee4284a50ca1eb918264afd09af6dfda944820658dd67c08b05feb6622fa0357c28c3726719168353f73c4fe11dac9d483e81e4f81d0927bd10ff6315fe9e62c2cec41238408af988e17368b87d649b0242241354f2f184db43f6cabc5c1b06f52759f5ea0946049a2d14d6753a63e3fe007453cfe96f4a57f5c5c649b03e2268d20611b9e641cd1aec43f43f6b2599f8630955dda6c10bfb8b5157da5deae48097dce52b4342328f1cf130271dbaeaef15b37d761dff60c7d979824618a3d1fbff6577fc8fa66c3d24837d787ebf817c22bb16079e780b3e52d487ad66b5bf31d78019a2d0119bf7458691241fe49099e3882466c03f39b26d88bdae3e40f5a5c7fbcb52e6d078aa5e83308e27141c4cc8dafd8cf8a47e6397e0b3a3d63fc97c47eb8486ba0fdf115f2be7db18e4b5d1504c9996673bc17a0c018e1a4b0b1a636c2993e4c3d3a342049de8091a7f1f6ad1205939a4dc160936259692747a64a2dd4771a2ff650c39d9f54d64963c9bd994c0adbbd422f90f0508947cbe990a4f9190f3171cb07d703a96656fc9d801350b7035760ebf5a90f9407f9c5983dc7889bb18d5151aa2e84de05eb876f2c493433639eedc09e6d92d6a0c10acaba7f598c1cc354d13fab9bec9c0393952fdb30601eeff43939925f70ba32de8a3aa5fd5a266f8181873a550bc0f32b31ce4b70a2b5d5250da55a960ed3d9b2bd7770c7e4f6bd66f984ed666f8a77600b3dd7f1ab8db49c1da16f89cd764caa10ba223b5f62bc2fe2084e1bf4ae64572344a0a11862b2e1a5b9e5df1b6205849804af71b46ab6c7bda0ebb6ff02d186d7efa48c2287e36fdc42bb1e722cbea532d4ac72b6bd88c683e797f3a4406c6e6696d5fd40870fc809b4b843c3b338a47eb24ce292993d92a08253e2ea8acc34103c56ef51560666bfd6fe58ef19f7ece87d93613cc9b258dfead9fe6e3134c057827b2af768ad6cdf3ecc6c3991bfdef5987fc13f59ce7c8a7d5eabecbfeb77ad79927c1f7dfc9ca8c3c633291c870729799a8dc99c3e720c6f30003ef04f0ada00f6b4d7176a6b0cded0bb6cd6b529a0487067cd84d437146f3829db02af6772be4875421791fd1fca708ef18d2e4ec2ce782aa5c2376e073bfa67f9463d4788a1afd61f7b65b100b3ed48247e69b42e51289d67fa618a7ff9cf4d713c8e20028b8eeed51e01e6ac012e27034f58fcd125ae91f0cba360f89561b23518b68321d7ae9ebbd9fa6d9aa699b3c68ceeb395987e7f71f82871d3b16150eec05076619b1bcbec3a808b00ebefcb0f4b0dd7470725d18a51087a95689fc1f0d1466d218472e4f2ac8e8845eedf9acf2acf64bc1972306f5b9a0294591ea5e60bd81524e16e73d068f96645d7618a4452d0a3e5fdf7be1d53141dd6aa637c835520168bb6c7ef4641f7aa3330d6923e0896ec50edb198331f4d19493fff6f224fcee5d3190ad18200c5dcefdf23ad37da26feb0bdd3a21394d0578928f877c2db63dbbe09a4fac9ddc99c0011d6af663c426d10db76466df3d84bc6bc515958dbbac6f5b123bdbf9e30d8b492a780c84cddc85c38189b08d2537a930a1b8dc9aac5d2e3c22f92a52675133429bcc70673913ff86b475eee910ff8cbad59f6bf0ff347f29797b24d11e860b4aabc1390da5c0f427227cf497455e7cdd76845aa2b967e3676dfc4ef12e301e1f82bdaa698e0da8ccc18840dde3165aff340718edd188c91d604a73ae67002f694e23c3c6bc2c2dc8975f22f32274562e951fd09a23114892437387fd6bde9b61b88617c794d1dc6963b87c7656c57dd28dcf95a82c4fd7f5036c090792f9d24b3f3aac94163cb7db0026fbfe32902ba3bf04e8c94d2764e2a04747725a9f78b8bf41ca98f6a8e042f1d144659a7f7b7799686a3f6976d4fa44805e094c9135f5b5095f0d0a683fa8ab99f4f0d3fb4b0e6e36cf02e68bb9f0030e514dfa07e464360e57a28edacc4734778689de5a67fd8d3b667a0269f4785894c417fd5ed6cf833bdd29aa9f39dd821cd975951624d38b5cefde42c6223fae571e583e23f85132fb81884db00a2ddf173094235eac9a0cd3ab6a27f30b7b581337a06b19d600699dc63b367a2a61e34049ab803650baf49035875f76fde37b305e6e1904c36b3b3c6ad61598cbc32b862d927a2ebcd08596142b8cf7e8ab5ba60a4a976af4f93a72acf2ff5a7fa93088e7aa23a97168f3ff67cd86ad7b6e594b8aa70d8ff38a7f6fb9c82ae71ee9a38647a69bec743ad8c027e1a26941311aa2b4afa84de1582545fbec45f84887016ff91670ca2e67a3b0f3ab480797b19be1edd233cfd6d91c731ba7e77020b19ddff8652d942ce7d6ff459aff292179dac0f8ac8e072d649572dcf7ebcd2b74c5d5c4080e55c1c65a41b77f72ea2280b86476c83c674bc13c52991dc10e0f380af422da03ad357abdf8f559569324dc1c3321b6d99fca10894c68f5a506be9ab273017a2ae6f3dfc0c6c172dae50e84333c2ea39cc86fdd9bce8b92dbfbaaacecacc3b9454daa86db0f9475e70023bafcbe811b9f6b0bba88edd01528bea00c3e2da41cf123b2b5834356e8c25594e3da525831bd0ed0b82307e4eacaed5bcb3ccf2d23b9b849a8ecb5e808f08efed60e1bfe80bf139f6fcbdc8d762c262fefab0f1640cfc193ebe4b484e69f9a3f2fa647f8bfdcca104211eb6533ca0814dfb28a1a6fe555c8975d01eaee57181e6405446ac0e9909349ac20f23b31f59418e3f107709b0a3977b7749f14b531f8a0cf9db7e99e61c855ca35b22e3e62940e43f8bb3e53173fc6ee50bc25d30bf672eb5b4dd8db2857f73475e786dae434332278d587c2d620121f9f62f79a967225d488ce189698f6765ecc99b8ca724b703f69ea009d9e16590853a6d91e910772de0d2cd480f31c700d39dc2af2e4b20ae4b0026c20be8ca4f1e01997aa0c20e1c7649753aa360924a4a59e854339250477de53976325a61387f16318e9b94ce2be89799853fb3f0b68496bcdba629ceec86cb6ec8ab13545520add525a26ac371b47f7f33399f8f26adae50ea85fbc65a283dd3c82b46f79762a5f7a669654a4251ce57232ad978fb84901d5f5d671e42ecb5c7d29d9904259b465e8b3184788564f86f954688f333155d257de0eea1f4ea3b6cd03685b9bdaa62dcdf44c0d650106884ca35f18b595653740261909516fd7505ada876f0abbc3c04d6f37a9039ee286eb0d2c9b7bdb18bc23c3a733b20ca72713aa055338c8b22bd59124bf7f77308b525b7170f4b4e1fc2997f48bb2a40877c2905cff215c076d5f76cb9256edecc57297506b7da6ef1df4cf7c065c62bd3d9441187fc99ee2b67a676835d37a84ad705c521e1fe84094a11cff3425ab875211860cc65f0a87364ee78ce83c323e84a24e857908489854f4fd20b2a98393361a86a420ece77c19938ee222da35907f43c91b92d15378157920ccc597cb191ab179da36259b97ec4fc775d4bfad7839ae14d8bbd7c071db691bfab87f09683807eda57e79c0ff5f01d013638de601f3f97af77025036aec89ddf08899c3edbeaf37302ea7ea1387a4a57928625494235d486429c6b7b4fbfe4f12f99532db2e849e481c333452e3ff01d906fcfeef6c87d57d92853c97d9cab8cdd32bb254cb516fe51e5358a1ef3a5eec89b3d21a72c7594d2e7015f1b0fe82406d09deadab93d26bd85df8de9ad695f864c3f06500df6f42308e1635db9ad385b2bb3cb55af564e3f4cff545566100cb106189730c7dd662538b2e7fc6eaa225a31477297a52dd10b7d03570621d255a049c8c406ac534ad8bd49d7e73b329199dd39c3d4a31ecff33912579054c8a8ec67172a3bca473a0cd329821e071eafbba736b97af27bb08416c73173bf8280d005f2e9d5b7dee5cd2467a5d35070a77b8bdfbdaca1e1ce6c6b6c46bc50964beead09117587afad4ed91d592d6a94b2df986fa5874be6d13cbe253742be96244fc9d59d3064b6bac29000687ea3c6324d5e678803e885ae4ed95f4cf8440934b86d33ef961f2e9e5570815f06093b5deece7a06fbecff2c4a2420ecadf8a53c8c7ede0ab4cff0ede90e9f2166d4e3ffe1480ff5cf094f98fd061f05c55271508f8d312da3e8f405c22d20f19c7c36dbb4073e658901eb04db19755f5bb46d7757d4e1a0da7ec5860e09214055e69ccff3f892ba7cd474783e5de8ed5eae965057257bac56473fa032051e2370e49bf5c0d887aac9d294d04935d492fef21ff25c98796716ebe1e2e5c437159778cf7121b7d7cb81bfb43dfa875905ddbc3d9ebac4e0d2ccfc10dedb5bbd0357e5ebfb30ea138d7cf349c272de6adcc23d5c8c0673bae3701ea15789f318d507fb40920f715bb9846d4c2d97246b49d545a3e7dfc58951f362148e17d017dde64923053b43e8a7434f43996cb4a43c4707d0362f8177c82d46e1789a72667e7a8b2111f9e06efde64a060a0b7afaa34cb4f14555c152c110af94c85883ef174b74c3ce50ce47c6f1c0ecf211b47b8599b11642eac95c9f1bf83c6874c9a2effb6678918dda9cc020cba0098bf6e8857eb206728382f7d9aa686f4e84f59211b3bf35f9619b36720478145202ebe03e5e97b23ce1d361ee878e490b1ce3e6706120ea4929942d79213e9373dbdc5a897e832a4bfbbb8553ecc905311b9827e9a83acacdf3d486bc1d9f42f3b4693d9e2e40ecb1ddc6e1a9e322833dbd2fc5d1946e36de2eda575de43acc909fe86902d7025d10d444d7ee8c18cffb4ec212aa4484b2da0ab3ee77118fbe0cd094a80b4e544396115f0c81a027601c0dda2e8b3c94a20fa1e5c70cc334e8f51eefed8ee0543b26cd5cff5cdc9285f2a4be188174e96119bc370894482357360316dde3ebc6ac9cd5384ec5848fe360b280f950828f03ead420fb52b998455c277ed30f5efb1dbf66b94524ba867d9873720b51ab270186b22650e71b0e0fb3a9656120830c1454b38174958cbef0a7e4f8fe6dc558d715071c1e569e2c272f2b8d5a912eccbd7631212cd9acc6099771df8f66d2b0290f6c4b76506b80ff51322800125fa5bdf5179291d84433718c54a8b648242770aa13b2349f0fd4f67bb4afcf5b4b77ba03d3bb9f3badf4cf80dd6a013398ee660278f387cc51ca3c3647520d3af08b59944cba3a7e0c39203ad2681d87086a6a7135cc307f0724b8599fdc08aa085290839608404424cbc70087b66952c520d85dc9a24f67aa51e537d8874b678e7412fdd0182f12a0eadcc2ef568e4ecac5cdeb50efb99d75c37aac30aab4b43971e1311689be1dc5120f7cb3bc63dc3b08776871ff9ac62706765a2ee311b02dc19224af1c962cd31d8c2de863139624443a136a0ca7a21ca52544acaaa23435dde716cdab9e886d41a6cebcc0990094597f3ab3cfe64f476083f9a19b3973c3f08546a98319bd6f2a527dadc234d7f531b3ca44653901e1f172cba6689fccaecb347e7022e405836f10f6a9f9215fa277dc1f235dcf6decb36bcdd3ca1066047410a2be3e3868ca726c6a0234ef8eb750a036c1dee843871b03a4092e40841eed8e059e8ab022cf9092ea21a2002b64c7d33208a9e8e822bdadf14ea4ea1bd1309c9d79752dd8c991b227c66611b75570f0150ccedaffa0ed61b9400a7dac1a6a2854eae01ca200eabb2ce1f9061cdafed64ad566ba0da09246dc5c5edae390e479f5798fca2608a17b5c0cb514c5d53edbe4b6a56be0c206533508753f6776f323352b95bafe852f0853a4937f7bc2d00867240a839548331bfd06b61b7a2210c41c5a9757cdd4daeb459efbd86d572587e7235269b7fd98eca4513af4ab8260c356f926f0b2fe0d6d60e5f991bf5e1c120e2f4059c402c7df786cec1bd13e18be972deb2e17aacb16d2c7d042f5450000f505c0344bdf93075270a8eaee3a3e97842dc32bf8bddc8c8058a2d6623883d628c715314e917424d31e6648819fcefb8a1224ab150b0751f1dd930e920ede86e444d42edb4cb05473bf603c82e7fbea403bb9ee42cc6a8d2a5759278693b7d66fbd1d2db00c3e1359b50da2d7bbe210b3246c2e7601e6a1efda5d70926a8915850f52449800eabb5b45e9ae898c35beabe945597d9ad646d1cf3af287d5cd8a626f76062c7805ab60e376f84885e7230b8e77f4b0e36402a9c1a79a4b900c482e6bc1de69cf0f0ec6df55a0c9ecab52c1ba03f6c1ae424dbd7531493c96f887815cf122a03d3b91d99f4ed02a90c7e5941c06feaa78dceecb0128a6db09bc0ea95c39b122ce092d74e1fa181b36ec61a965561e14d3690d4dbb21a6a9ffd9d75063a3a3567403bc5e38d6b10b4f95c1049b207c2f1e85172e6813a3fc39a81881b36e2bfa3c28c1109e4147fddc9a26fedeb718b0e2cb025dbdbda1d41f4a3d8129e6bc9f1b0ca206a8954cf4c731e58f9d3df78691d92c25bb03cf6c84b81c6e17fd66a4df0d7c5a38c5428bd77ea8dec6677632d43832b35e4a81e0963fe007d89b4e06349911c4cee4f75c7d9b96c200f50ab71fca7baab18ad214516ed4d8ea221343d136e0bfdbd51fb0689ad139ade57c6729970dc99ceaa2d83d94119cb0874cd7cf0fc0123ebe50895615337f32d55df05c7fc6daed5a4371a081e8d9a4d5b9bec269042095b37b813801485967ef1bdd8c2c7a24ed074f0777a4e708d19c5e8e252743add06495324ef4b0b674525db90ad617287aa6e0c0641c8fa5a5255807ecd4e5283b06fb0492d819ea909a248e626df16bc331b37d3434804421e427f5ed8de8e84fdbf7940f112b1becba818e60042e934e68be07056084c6082725a81b1db6a1dd426247b72592e0c78ad216224079440a7d888e40f4473507817dcd50089da1fbfa3e199eb552a9a45617ff2bce23998ab3b5b698f81a458e4f2cc8df5b798609f58ec79bda82fd0595d39d3c051052fdea77f903953fb55a94eb8bc3f2bd11d6653d9feb6e76d9e39563f25de87923c45238bc8bd11003ad83c8419a10ce398df333dd4604d211844cf315addd581c3120a9fc7772104a4826d83850a670639da183f2de544a249832063ab6149ec8bc85db3c1c35438637a4e4c7714d8b3cbc315944ffb9a0896481e5f6f78e6b211d414b75f32049d8982958b1a5423dc3696c3b6bc2b8ddc4325c838d26287ff92768a94c35845fb6637fd89712261bc528e236f037380f9621f7e85f23c3ba4fa39be89d23c496492fae6660a4196f7b8ef3d002af0ebad7c5b0d085312eacf5137a3d36e3af7edc1f187bec3d550691e291810bdce4a75c3e96802aecacb8bccdd1737a83658f604a2c139b7c04b9b981216deb0c4373be245231703de4747bb87a2c2423d187652ff906bc9682017acfc5a95b35e77cfed31c9010c28763b44e935f6941aa4a45a194e1bbd49bc6c3f6d23c6eaa2bb84ba7092e4aa41fd5d210328257ab4b816ae509403917f46476f60aaf290b6be1cb8e13d2e7e4cc58b6365d6ca4b9cebbe4681f6b9273edf92b3b16698160114b583a270134c6cabb0bd11aee0c712e6ad23afd431f20a058345f4acc03b004eea84cc6aa4fb44d536a82be3a1f706c2ae2bd1dc56d2b491e6a5add3c64140ea1969411036f8aa503746f2eb3b2e664b4297a004e3d987e3c66162741cc5ce6dd8b0c8cac964606fafff014b78e144684f40b0dc83686b57bb03a5d22a40b52a11cbd202dfce472cbec1d4ce7b0705fffdb85fbc44d1cdb418b322d34bea51496961d19ab2781f5bebc827310cadb63b5c6dc5ba738240a631fd00abb6bff4160825c8cb8818dc556d2651ae5f05b08914537b4d435f7a50b3c9568c46c0149a01978fef7aaba926d898a434b8ca408f571a914be3ebc061f5a8ef5bc746c1a7ed3444ae5b9db6beedfe50cafdb20d7cc47972afcd6e990f19244582947bd8c3d2ee595fc95adcdf3c2fd6cf3d33c0d8274ae40e2c1f4b6a122bdb3dfb26e913957dff98274552a483e11a4007a2f5b2961a6e13aa289624c3c54269915b47ecfb59e32bab1f63370436548a9c25c224205618b4c834bb8339b2c1f862fd3bc94c306114b97a88cb85a7672c18836c25818df8de8c135754f01971208b80ee90254ee1c12a29996dfe2d710f75c53c5b9bd0002bf44a4051239e745d081575778d3e353dd527c613151cf627ea74de4223811cb5512a6aa3ad658712c5e4f2d0c8fb8a0e90f7d1a34d8f4f28fd241246c906b30581ed4cc78c9496eba2c414af30d9f3ffb51d770b87b5411a2e233797e19388f5d113f31595f6ab8e3ad5ecb345a93d802f4a61a200accc0e1502600ec7160a4392b4e340b99b6bf4af0ee059623e66cadd92f30f48b3ba52044cb4bbbf4e983be01afd7164c06d773ad9fe1aee4500191ec97f2b4309189fd9155ee6f608da7bb5986b8dff2d7d041669bab8f3f744aff30c85ee6f7348848ded028b376f6a49021bde3ac105f1bbb1437eab4fcbfdb4e4e76abcbfce371e76d42076f1a154d529231a9704dbb48ad644af3a0735cf646d3e2aff568ad87026367370562eb2673be26d042a1c2d514604fe0e2cb1f0cfb624904c2bb59df905af679d3fb0dde49bfdd141aa37696eb0abfc7fcb44ba5319086d666da44c8969d38d728d1a892934febe10d58420fddf398bebd8efabc6579061851a41e74cf58f96cf592e049052e29b0ea2041ba9adb3e6ea5b79fbdf2ed207f2aa3d152a043725301d10d3ec5de1e4190e84ab1be357ff4685ae4b9624de3f4d574b8afecbf88c6aedb0d2cea65f229b1280c96abe79846d8a63ac49731422179aa844755c153b5e93a801e4d3a5b92092d0955d737a91bab7007f88f459222f8042e16e6dab1c9370cc0aa865411883c6a47de683238c7577dc4ffba47729ed1fe6fb729f112a69256ec9cf44aebc3f29c9a9497a3ab5592a792015bdbacc3866267cecac0132b0d4c719095dc2dbc607edfbb3fe14334da91bbdd9141713b6ba310999f9e2f1cd527876e2fbde4a64df2db14bb578b10f7971919db837f91e080655681c9f7e45aeeb907d28e5ec7ec45780911fe7bbc0d41537a85d30b4e3ae20e15b330d3e566588b558b76b3e37c47033cce90f7cd9a16b3cbd21d97f28e53f377ab37cb2e1ca44916e083a874bc46684a831b4dfad0db5f7a7779e37519edda5a5e94906cbde8a7af1ad9adaace69610341ce5ec410c4f09acd749ae81dd2f43ad4e2f8a083fc13d127ca5114b15fcc49123d26d62546898403b72128c2f9b2f63a810e76dc11961062b94b1afc40d1aa0b20906f053df4bf2f8cbaa18241e853af15617eabba28e4775ca923a1824bd14598cc255ae802e5c3446ddfef5f370533ab22d0dd16ffc539bff6056c9fe44eb4f376bb077fb9bb07f213e15460ca12b50602b59ebb59204cd53138b9e6bace7039f08fa683a6b9b814b251dc35c9e4b4ec5576dd61216b7c0544bf67d27777b19145348e58cc06383725e4855fd0e1a3cb92f4644acd15e92f951987975f571bbcbeb13a9c95c0ddd3a5a6b28c1aeaf6138c17241a63690c4a1c9ac9628a946525de41a96d7f9f83467daff8f2d690dbd986b4c24cf638396672f2e33f12b109cabb84f4637e1605f73939c52a783ad4de8d6edc1c7b97d7b96662fa018ba841dea7975cd000f8237fdec411a83f8b5e63be340dee6089b24eeb7d2a3d8d79b0476f98dbc7bfd9d9874aef4b6a323f2a2acb6ba8a5838602de9afd7fb6c76f02a5133bd4b7b435f5188043ea112863572417e8aa42acff57bb3d035876591f17ad85b451dcb533c20db7b80761065c88d97aa5782af2940aef04a2a8e731b92e3f9239608dd9ca0d52764e456ccbc029e707c3f5cfc3a9367fddaab3ae183e55e5563e0d91af985c470818df26a1ac31a22f69f6120679f5748bbe1e7dcfa7c1289b72cf600f1ae95f754ce3dbfa814cb157447ee93c6a2c7105c887cf165161c1587be3f726adb0f18cfe151c4faa94f234dda180315f4d6f703e281a74f8c9b683aed7a9632f4d004ff92e306c58f529f1b2c9f99962c67247c820f8bf06c4976a4a269c5ff60948a6b1aa212e180d38be3ee9a88b939810e2ea533a72c01bbcd00929ecc1abb0199814acd6ff7c3c09eaf52de6ee07231956449bb88b3d484a7ca4e270abae360e2bd0497573c9f53fc98593042a689c2c801578858efe844d0998c9214635a4b8df184ac106b3334173c17ae9615422a26d1d3e07c9d1ea3a6c1f46970a9d8decad7cabb17e073d39ade5c27796e509a791dd99aeac234823a97984209fce5921d27851c98944b6300402b0c4afb57eb1e5b6a2472a77bad45b44c737529926470502c8ebdc5ae7e0017389659c160cf6134466df6374444d4d1c5f74ddbf2b78694bbfd831d48a815159788ddc34a24dac4d651df0514a45b4565ceea7e615523014ddd9982639fd49ffc01fb4f7f8359871bbec5df345de1aa5e85d6d9b95c638ad0d938d08a0a3854e40ce6bb1c5e9d3a4a20f4372481daeb95418c1286665eab74b321fe548e1f1b9c5892432cdff8224e78b204b032a0df1f9515485180bde3f457417a048e759ef67039b8a4821502463eb7a760a546d51df1ed04f81690a28176ce0d5b152523d505a70bafe3189b328d0b4caf51ca14160d33cffe9d0460cdbdb81a4cbb76a1610fa686982c8d0ce464876096c6f6b9814e39eead72b38601d0c826a11d30ad413f61be12f38117a205661feea52b3bfb351769edc4d88ad13cbdaaf32fbdc92a681c1333b69ce32f45bca349da40c73636d2fb48f3fb3aecba1e948a5e652752b302703e2da756f4f4713c11ab66a6eed7ca8c9fe2b9e7e1f147d2df55c979198e32ed9b07546a0d5deb03b324c47593f2df20926fda4edb835d018576cedf29b8f718f264ec3bc8b83787a2d24411d6a320110f3eb5453d90ae0c6e1c1a597c403b3874e2d77a051d0c22a680712d819d90569f4b09652a02130b3683c790ed5064142e871d068ae1ff4db90194c082a1306737889230bb3fd926ea393fe2a95203022d30f9934ba3bf17e2a4dd21441c97beaa067a79750b1b73009c3fea2b3b11c267072dbdf186b5ec2afef2173c59e7445ef2aa5a9eadddd4fe52dc808bf45f8f1ac52103e6779c6d5e91447bff05600c33b193db30c26b8dbc06e6ba3fac52558648c0f912a7edf4b3b0dbe2adb8417d9f0c889c613b930258358acf9818f2fd3ff5d65b6354ddd43797b220783a2c18e7d0aac790ca4083380833693d1c36d2696dbd103b499a51db651b283abc6e6fa450739e4f1eb12ae179fe8d96c8cd6aef05a245a247483f77ed7520dd3211c36b4a7a37821ae36bacb7a99e7c727cbc5ae67b964814369085746febaa5154aa9311d99bbe45e6a5bcbb91337e206eaf8ddcc255fb8a72b692ccab4e1e280c751e35151eaf2f59288e3f66bc5a7d2caf8e2d3f325b827c411d590e2b02f9b8ba21bd0220605f0a758e45af88c45bbd616dd8d1d3113985489158253b95838aa298d8ff7d22f4afc2e6e6e55fe6cb28f33df9670df937ca7d1b441b92418fd1a0af3ce13b8a4673e973ac1ca76b1f5d107cf3c94b7c6118b8b94c7b14cbd2aee516bd670af652925e1254b7c771fb321312e7b8765d19d9361bbea9e6ebc128c7614d81924b189e644ddf7f06b2aaf63ba85c91c79449ee9c91e5c4c183cdbcb5599c19c973c03e515faecee11dc166c1551d40e81ba94d4cbcaca0967cdd2a09b1d52d612c1a30bf71200596a1f0036f1ce7ae47515e4f3097123d5b6f810d32ef038033128b52bb7be51fdbfb2214dc46263b7effe165c57e3fb27078563ab8c64f29feca634d7f45b841f8f705883f67ad4a14579b1fee71571896fee21a9a2be6688967c2866b65a52eac0885ab9f7f56120236bd97fe04e8321f7d438a9fbf751e2577ff23ad60a24e89c423120e351f1a5c721d53dc54f7a6030ac4b0c6d52ab1bebf51b26cbb050589f6eef54ef2b71548841947d0b28b0d4bd88cbf0d7caba3d1468d80cfcc2fbdd3d497d40cc770a72e446d1361280b19b182317e5e0c7950a34cc88600b475f9196c4bf2197d91b038f871a3cb32adb2e03d9a7adf8910283edf50dbe2b0658d3230991553e51c55d64e7c7f7b0969ace1ce8b5e11d75b02d177e2bef94cfb5584ad8eeccf466d6cab2ac29a5c1aa442e013fae7bb85d9c195972ac6a016e915f6749a231bb1a6acdd29932b7f8841437f543a0ced86d7ee350a4998c6e2ee56c05b63893df492da796b9fdf8758ad1931cdee94ec08c43761bbdc2ac1e1898119c292d02e2c00f473e9219b2f25219eeac7c4cc3023f6968b94fcf2ee46f3b72c335961a3455f135412dd1d5c1bee90c4ba24f88822178b957195b876ad353c88e67f3ab25f70a254f7adad0121f1ce73add179db9b53263621dbb0fa4b431525f308ac842622fa0ef97ea9090b15ada6423d096c99d9d57ae5a14546fdd689af8da320ce60e268814c1668894f5d48a9ffa1a97f0be17fc8e466a07a862239319e1a60718b8db7c3471bde35f619a549413280b4fb853efe04623b22e7d779543bc4320e8e983c6099aaa289c18b1cad375a9d821d7f8ee8776e6566fc63094f15fbb63a4a0619b3c40552035e1777267482551fdd9effcfacb90c2658478cdc210c0f3fc43ece75432c2bbf967f59d4223c39c8175a97c249ed084b900ccf44bf9cab9e72faff9f275c91502bb15e2928b8c5ecc013cb2ec320a938168e70012f3b294b2b10ae468d983d04cd337d0296efd661aaea3cffca9487f66a073869a9fb2330b210d5c0b0b0b3082a533ef4ce6ef9f87824503c8d256b7780b6bee7bfacd0941f6ab064d5b673b8e147f09c8b954159d255accbe4cea012f156fc5c6b98c01593e2bb2a2a66d79ceb8b2440f762b90d3370ff8eb0f8e71122d49ea42f645e85eb6f2ab9d07fb8b595cba29bb0c63ecf88a53da7079cb2633a5a7dc2192bd3e30c263bf3bef9a817ccc2766ecfacd76790725e9ea50a5a7b1827fff339e8b75c252932ec4a60833ce27fdcc4b48d80ffd62d3cafa1473367dc900b3da77d4a745dd734cc641f0938e8b91c4752f3f53e7cc78f1ccb6c1cd0340569432990f6d212d2f2036c8ed0d2e8b9194f3c35f87085d99d5f7245a11f0b954f1de7d188ff1a95f5c2371d176f463f53660876f62add265ba6f9aa4aafca372504bffc20c9769cb98902a9bdf2c6228a6121611ce4fc41a068d8d750872f15061a8c3dd4aab91466cdaf0ec92ca26af1c0a5459e66d904921e73027c9000c1ea9d45f8716c6ec7ca369f42d1338509d3657c4cb2153884e3fccf0314c5b3500c35a7331c52a96543d62994113e691f9c44f0f9fe5564c8be95c3150ae71c767cb1caaf0dec35794493f8778de86cac31b3e53d6af4b250958e91550fd5d612e09258fe43a381290503616a63c1d49b1aec6e49e0ae959a980e60e7cade6f519f60afc6089aa04cde2c05f6451a1ba8675b1c46cd403983fe02c18f17493ee01c0161d5559af73b54aeb0997735add7e5545fbb1e170e899413f359c30d703ece8b48265ece798839481ef302de0d398f97f51e77ecb2f4337dbefcae93d648505d86c09a67f4ccb1d257d352655681864a37348d41809506ea5c55a1f1479170c4bf26ee2e7bd6fa269144cbcb22dc133f3ca99d09dbf5039458dcbec60fbe6bd4fde08c56591a3c85c01607d865cd44e36fde14ad401ae6bb7cfee11cdc205d3b813d606432e3cc3db4a1551989b74957bfdf8b048ada310f01b451861f51b703dd662cdfa8c0ddf887257eec88433b19c49e015de303c924f6fb9be20f80a27baf96376d873cc9e50c7c2dc209cb37e03c298ed55578f9c664bd73027888311ee7ed29b85df81da75780e7c55fe2c062e7bfad93b9cff7381eee70e1ea5f4589903c3a204a2a2cde4fd50322a4368a6a176e976c16c84ab8e669aff526fa2749814b6adc9757972b4d605eddc13ec7ce54664d33ac673a92a0c9273628ce179087f64c5cd4ebc6bae6a183252f39c134b198544c1f3ee12d7e152f9f14d1252b27a93ee3964482f019a2c8eb1daac582dc20eb615487dbc850daf2a9f0805f46cbc5fab80c39e00052d8edec230c2f1d100b010ef86f1b0fbf16bd5b7b7eff68d2e066c7f49f3f01f1fa1d793ba2d62ff3f19869c466b15e792cfbf0be8603eea6ee735085fbed0075c381b59d97016cd174574ba63e0dca2cae0c799089b33e50c97639457a487fd21acb76affd87c9f94ad609c99b70eb198a9b5d8ceeba02a9066f7fd52639033e52f0b8b2b56490c42a4f7254fc9f67e3c005006d0337326cb6da7e2654541ba4306f44a10876911d70fdcb0eddcde802b067d62b870c62cc4ee10bdff20cc43448c1c2045f29b7774ff3c1f9d4d90ef4de3e8d37735df9eaf9b558a991e0ea79b379b292a671b4e191b5aa708cf8b0ca4ca5262e4e5185ff3b6044fe788128b6b54cae14d3061ff932b7d380daf2dd3b566b046b2337d5393ef37c9185af6960cda686f0b9544a618b30743673ff6ba6e3486dbb4c3898c146e65b0cc4622416e8d7c8fbf926d25efea9cdeb86bc6ab55b08e1239c020fc051ef4577e466ef26d723c8a8696d7a200e06073aa61e744e47107da9d3de01e2574cb3fc8b23c432d014132a823972c29340edd0b7a727fb8c1b06a9fa7dc55411c24564198a4dbfc17ea52811f5cdd35bfd348a45e52d6d6fd6b9c3ae443257adcb19f81ef311b068987254347fd34271a683d053974ab2cdea5fe1906f40981b02f5638f2ae4d7f522cd0dac55cdef1da2452b2b16ab7879c29708b15398fb2670b113128ab85309a08a043b710eddb92da1fb54c120774aa089786019961a286edee1a8f357166802e374270c48e9e6509194ad73fffe99f859bc8d9c9414565eaa2b0dcb33e9cf947d830f2f927582de90ff62f17be26e22c7c0f9a3f46feec014a56918f811bbd60a1845f8e3b353663a1a220ffa4e768f68615761047c9b1f1430b982dd5580b9f033f67f3144e5230a775dbfbe8940bc2520f25f608bf2cac5ecf163b59c842070828370eb8e0fe88d88cb40e93839ba25460a4a06e525599b49302da3251912ec835dd2558ee9a20623971fe242c713afec6d2d25f492b3d4085ed493ec2b88a8a05edb91ede6f5451a7868d024cb12c3223608c2c0b60721122d180351a3f938c4e982bbe4aa65dc2928b574053c858da4a101521065c54809760f069de22efbd4bd467398a97e83b136807ab25fb54135118bde30f6f35afc2785dba4239e4c6ed1abadd7d72f66a42fced1c049c33f19ea603eb5389cb3595e0e07cb5dbc70b547c4fa8c0633ced7291c32eb2104a17c4dc59d2195015e5bfd98a922b2cc44e6a6d12b24053ab060c316bcb9e6a65d91c8d5006c556a1e7fac742cba5077def0981fe2dda534b0171d3a187b894bdd014d6b727ada99b588a7b6415cae514a4ea017d2ef46a7847b81c78625f7c24934da218d41942950ccebd6a2bf07eeae5796d2d926de6aafd3fddafa1a38396bb56b6e30f7b14bd883f67189f04d2e96634a7d5a35bf71b41ecc42ff1323ebe2c9015902866859073ce56751222d6198ddbd9e2338879d4b5a8e9a2e2c05084f20741707bab08871f7247385b2761d352661ac09e5146db575b19f937e22d5b2ddecba59bc21dfa55e08bfaad15329404e0ee4df6998f5a3c6f3932fd99e870f388ed2ac21f374195a9b090cde18d592b742e55f10b3fce45ad02c13e7f809495d10d4b3244f3d38a969594eed3462e3fd85e7d002972ccde3235bf25d1adac738df822ae0069955bc96a39366bc9ef35722c52c2fdd9af7bd19852a0bb7d33ef1f51e38a419ed4d8dc2693b32afe52efa981f1e91ff213ce3f8e8647467324ee7735161acfe7377dfe69c1bde34db18a4219ee3aa8ac43ee5e703205238dae5c3a39a0df002ab390fc5a8939a94b5be2f2408dc18a6c8a8883d83d6880cc94862b879f68ed9911fa3917d3462bc56b37d55570d5575bf0a2a27ba920ff17bbab529926b223c409f4ba12861324613a046fd8baf48eecde81e17b8d087ff967723c5e8616d4a3e2fa9e83b021e0d063414ac02a41ceccba7aa070a9242e87b98f0e3db63e347a63132860665fe39e87358679841bb7fa40eee758d29e37ceefdb3171bb937c116505088d97171d19d223b3d93e38cb53cb3efbeeaa174247e97e2ed5a7fd32b8c98f224561b86a6deb4121ae9c8f00d49da2dfd994b8b96aa67165675adb28b44f96b70a971fa6e718749d283dd7acab16c4f45282e8ad8b68830fa0b385a668ee02490501eaf286a52d1f0a6edada916e48c8598ba157b7f93d5ae755332c0ee27a94b69a87a8381fbc1772a5bcf969c0dbe309f69e28157e2ce311b4bbdff59d477d3d373c222b2b9756e632601b89ec01e6e1d1a0078e5792dd257ad7eecdbc146d1517619836cf6c1a6a2221265c7317f70dc4fc19150afdcda589317157d3666f7f0762ddd0e40e5910bb548f8dca929039da7e0f2e0a562fa2a368aceeb0442d25a444211a64eb48de3a79808af2ec97b84d231a7f7adfe5bae7efb351e33c59b65f7808bd504e2b3ad5968dc03fc16499d28e8e282d575ae49dba0a2be2610600e33363103aea91ae0540612bb13e51adbcf4a54efdfa96ff11621d330897dd6257d53c753709b0fdea09c1c5b1ecb06bf152a379beee69993ac394629577afaa49df46ab2d0329f3925a4613997c6a2aabaa465d2b794cefc31f2e9dd2a48fb4ce8b01fe5468f4a801a20f10a8ce6b6ed8c120812cfe7501191506daf8a676df22748553a98c8985d3730ab57a820ce34abefdac75a76bd73b866dcc65181ef94398365f16d75bc880cf3adc481304e5fad772df7a79ea6f0c7a12fd700f9873ad942d290ceb27d5b18ad2f115a86ae0ae64f960ac8c972c38d1fb882c84f8ebf64ef786830a15bfa337b73f69aed41937e9dcdb2e926f91d2266ea9afb0530e7270f3e2f013f47cf7516d1105261ec976f932374259bc1cdb25d5f5a4e0f589cf306f6657701844a43d546cfd668222ad8a6c1b9c2909ad13d0d5c96c5a8c420fb67737e358733399b30a49838a2eab1c30fdf593dbd8f0b31c6c53d0400058c82c715495e6858898414cfb6732bf6a24f3cc01c0b9b6c55ae87e3cf698a2c791b47b30b8d6bf1b11dfca244ae200d0661fd4a247f27ebd149e1fc6723c2da1940ed0b45c754a339eebbed99bdb01b0d9f2b663e0617171e00de1747d06f526c40141fbd9e459dde39ae50d9debff7576e4e25f26e231ed27bbeabe1a60fcb09d00cb815a1a00f225ea105b56fb6c6e287916b39c3dba6cb198e8824a21d7272e1d2ebb01406a58d26459f8fbe87aff4c7dff6d93f57d3d7b282f3955196a09882cb8bd54d0ad85b54e57bc7de358057fa35832cbb37cba925bedbd09320c53dd75a0100863a9e67b0c0161a6de6498595f7443eeeb03fcf8e6440fef9aca3e831d1b6d771fb278236a52a1cc8bb6ee4ac9db312ae622721f9cf3c29624bd4c6c9d1b652bfbf50694ff520672fe28c61393e8ce4ef11bb6fafc17c269ea4593017c8a10d74dc76d4d121708138e77372b94091bf808fbf63f28f194308eea50638ae3588f45f21cf6a5b0e554b1ec2fadb9336670a5093e6f6e20878f18bee19ae2ba2150ed677169e008bf72b4289cf8ca1ec39c6cdd6e0e681b81c1df852ded3feeef14e3996ae40490b50e9e5ed15dd807be15c825e7eab1ce128e98733b1a4142e85472c9c48a27d50ac1bbb61c757522f361634db2b221a26d77582f5071e10828d085948e316b0cb27b7061dc2f9e32d46d4a95595877f25cd6c5213d8cedd182ceb6fc96b53e2fd1ae99b4b8744ef2db76d3fc6f50bb3eaf9d874882de0bf424e406e395ad2ca7ccc4576ed577f3c28222c2dc90b77e8f945af013c99b9ec6a8ef0fb1dd710243fc6439f1cdd22c5dfeb90205c5bb70cfc52a1b2741010dfe7ca3d5ac749138305efacdbcad7a7ba0743d3953738852c206bc8983941444c7db10c801870957bccc9ecd9daa558f8d223b748fcd2765d9dd044595d5a776c5ae0e3718cc0fbdc7aa7f77a27b4690ca9f9539f3ea7dfc6e9d1de405c3ae1f2603fe88e1f64f4bc7078b7407299a23f76449da68f32e1b7c5a2ab83522ea7c241fc8f09fdf6b256f0f68bc0a31340717a969d372575aae622c485e98f20f996434215a5b8122641a9490dc0cd83dfce27dd63808f82d72bed853382a10038af8abb19ec8aede54341952733227a66ef0cfaac4fc2134fb09793bd1807e413e69d4406c90a9dd353458c11f77a6cb8dd25ee0826925dfc324f404407a18bf69ca0e8a75834299e678e9046cda6876c7fde531957a2046301a50e4c41b1ba377a2ae230dc0c3d6bc7e74d024ccf1e923bbe8f40a868f98790dd76062eaff3e8940ee649e5e4447b8954146db0da9c5a88b3a7bcdad77fd204e025db9907be8cb696418a13a818116f3abbdbce21b86b545c4fc090ec36feef880d849ff4c6e2c544242e7c8447df1babc8752f92205256f0599e619985ebe22ed3d67daf1b71de76d8095fba9f75357ccc006afa1e9e4acabcb49bc96ac060b8c9f31c807a200d3fb037ac8abf42c5ee05cd6576f3490364e0d9d44047171a9a3a05ef8885df22cbb88b734b3915b156b85541d1e1d9108341ccfc9fc9c93a0c8b708ae930394f26a2ce51b163be547740b1f5881d07279f4073589847a3c5812403f733db48be2b3a643e556625e6661d77e675e99531ff7c25d655adc32a4b3152b7f5af6aae330a6d57f9f9703a6bfd65d6c22a2d04f80154cc3f7f6daad252af33ddd357f8e085f985c55a405cccad01e09a6e4ab153fdb02971ac5b562121b5aa5a911fd623b5c24b8af0f23442096fda9b789fb6c59cd743b452e83b0ecce2c299d887d41e0c62e99c7515dbfbd61d0fb62c46eaa0dc86d52fbed68750378af4dc9f784bdb9b67554311d78e43b0b2608ae242768efc4ba72c6bce3448bea04d9b5cf88919e7bab35b66d12b7427ef4d42f9c97419926207dd2c1de3632d649afee227ff611481706eabec54597c20a7a54243327866f697fc57e116a4e747910de3a07187baf19949f5d1442fe239663591bda879c2a03b809ca81f9a71f7aa1eeb250a6bc645cf829f0e98400f57a3cf70b8931a974d495e20a129ed930dc17ae7514176f72cc8ae4cffda6922a7a47318a0fc3b55175d81443d62b9e3ef1727884085bf92ebd316e8e5fe362a40b0d9de35cdfc47e6d0dc1870242e5d46e248cf60dce27c4cd315765356d809c3ddd2c22bcecbb37802aa037e6f82cfcd2cc1a11fd5d78fe0dfc70b7d01e298f4bfac26c0761090cb216d270e4aeb63dfe1f4d9dba8d4b548e4a5c644051e0903b26ef05e5d2a0a48212fd6e50549cb2cbfb9536a6994d1939e3ab0c62dbe609b9b7c19fbcba468a485013df0e0b68b780a1fb0425882f3a56a6689499ae51e60aa7649c5ba19902c3ceb828f9597f401c356729a99c75434ebba12775e6e94aaeaabcb8cb8d692fa04871d386c9b6d29eafef038a4a21df1d24be1d2206211faa54805e4bdf4179829ea408df15b4383e6aac8184d10c724652aa39ec1ecc23d3952f33688d5ad373cec9394922a7dbccde64da33092d6ae43b90dcef1c152335035b0e116964a3bb7c3d93bef6846bc97ce43f768aa619491ab9d39c0b2ed8934b31de8455fe185af188f27ebf9433933f2098468f1d480c07c296b37f3af47fe0b6d2d879b9241bd3aac991fe64df4c2a062b6d4835a7cb08c920758b50ac694f20d4b2e543f95c46af96de09632f607578f288801a6bafbd5bd6cff5333849090e513046617e54f2b56babafb90c8c7aacae9fceb86480db27703c2bccc7753824303d28f73d542282424c1e43fe729be3ac07eb4e8e471e5e368ef82f09874cac768cb5f6f7e17950004cd7299fc70d7ad2837fcdd068e17c5dd8d58a40ec205b02666f5c55e66b38494d4bcec65af95db18bb64fd5e2088a353100f3961077d685ee07ddf64188d1676cf6a30e27b82b7347c44277de3c6a5e8af2c701bbcdafdbd4e92c58c976c9927c5601a03aa2cfb00d1926de7976d2417406e769cc16cd1aeb8cda105bda71f2bfecb045ea09aef8133ff9e1edf77f8da21b581258591f40334bcca72e8cf5e1fa1eeaef714927a6f737703a1f1c6ddddb7945668ce62c157f1a934358b18f761c13f1c2c5896ef0baeb1fa891b37a8aba887a33421d199a34b2a836dbd1ae440a3a69852f5c0cc5c5745691d5fb25b0e4d1e302923ab033aacbc0b4c8cf7b5190c8fd987bfde3b27b834dc14ae22da34247142a4fba100900e2301f588c0f3f99c471708e6b8032dff6c2a309a16e2dd34bc2b05edfcfcc42bdf9f22f0d3d25ff3b20ee954034fb475f40006a95b07a64943a8eae7713f196d444e9b68268d9615e778fd312a6facc1fd527d4be8994d30247462527938c59f5ccb0918a7e73620ada1e86a5de6eca7a85ab1210e15e3d64c234a4d6cf5a0005d48492bc5583e0d8f2115daa6aabe41d96395b6d3b205ab007eef1c9813eab475f489d3a5b3ba2985655e526e5db0597aa20782aea31a47ebd063373f8314c40214179d32c7dba6dd7991ebcdb1a779c7bdfc00d56ed365e582b5aaad9a6fd73ca9fffc687b8f8a334f93447ecc2728736548d48c10f351df2238ed2f13327f5964919475a167db0c4165098f8a383fdbddf21684fd93ceb7adcbb5f85347e12234670a6ff8b195c6509cc6fe1d426a416f11de20813534a1ac5dd44275c5e98293540e7635f6c75a6f1a9eb300c3bee93e0e4f434ecb98b7fabe4bca4bcb3471ee5f6dd7ab2f8b0c2860b800220bf44df7b17e301182c53178180ef3171b855c13e9e12ad3da51dc687b7bf642036011e071bb279275e43bc8bf370421e0d29270f52b1a318fcdd83fa77e63236eec429a04327339e4a6dc36465aa705fd30c112d7928707dadb72afd9e36d25bbf5c1eddd85c9e7d954c518690ad414f4638c8e65bae62a8d1f1269190468f7791c624fb2f5474c40c5ab5f930fc1837d4753507d65e47bccc117be7994773e7416faabd7a87a7ee7ab0adb4a3342f86e85a2c14639af5be2bac761f9e68b0fd9a2a1a8aa3e9b5f18f5499c36f8aa1370a2425ef7128f12b74c0aa497ee0ab404bad1abe308f5d340bf33a4e4491f57ccbaa337367d4dfaee34f170462004990d0781a8f7d503fa73e91949dff08dd7285c12d2ee7797d1596d2e40364a8150e6c6e82ed51add7a95ecdae91612376558625de5fc2a234e61f1bc10f903f9a12942246f738062974b8a15c0e11502f93c3045b66b23ab3cd53719dfe6e9296e5a609ca3e6eeee7e662be0f6f4594aded34c103cff66a67572c180d6c5d3ea16c543b28041954576d0c4ae87bd432b78c528738daae26cca23e6d5a094da551c19c8f7d58242ae0f7d5da7df421f1fe0681388c9f3efdbf27bf4db569daa3b9b917447086e8ee7d540102fa12dae9d6c98937ca9d8cac3539c719fb08070196ae3931b110951085f0a8447b59a862397aab6129a95809e99bf1dcdb6735280c885959d362d19166a295934e848b6d135019f63218e82a6af8d3f369ce6f1706506fef3806dce2eb10a2a4dd725e70a2fa44ac319e9c5a00940011f4b01a118450d670bd54f8f6c97d1771b3e590c989dfae9e55ffd87ad099272a0966010c7a67425e3754fff0c407d3dcd0a6897f7554dbbe24552fdb899af281a74847614a06414a9a3eeae0072fb49f0e44cfdbc85f04c492efd3cb11ef277ca3f1ece81790886654928a697c1ef01748df984f1ef4452d2a3efcd88587b88a3bb234f420e40d6b4a8f91d17be5d6299aa48789fdd5d9e2dfb9751220a02aded27ac1bd3d26f9f14ff5eee04e211e36271e30a45f276b35e3abd4becc971190282548e16f463f2ef57b9adb045ecdeac074e3e22d255d3ed8e7a83d9d2fa9559d09fb180bc173178f6b1bac7a73fea490fe530e1df9a2ad75c69be0929b1db20e31315176533f8c62da5185353e4162a9a991bd29bab6f2550476eb01e2e22ba9cfe8a246be25edf01535f208a4fd025252f3111c6b362da42f9366ee43d7c91eb9908e06952eeb984f4af8291ed79e6dc38d8cc48f88f60492552100c7145c404f5d4fcae3ec739b9a86a62e34f5891fdca3c1a00dff89bb1a22c486eac85d8551344695e2e29ee0c12bee44c7f24f126153a5ae9c9fcd38c881694a29ac48334304d2743392591c24f203b48e06ffb50366f873dcb8dbe99d1823ad5173ad260079ef0150d01571737982784b473d063c828d06d1345a4109ae51dad788b818eb0c7cb7e2a4c48162f59fd550a9a6188f8f78056f19c60b11610bdb4e829b864d3631d61467027573b9eef2cd8b6718b40de3ec17c7747f8d6d152c69846a0293e9b3c847de15f025ffa6c577e7a3fedce7d2ec6571a32b9307552c3a269e0a891339a097afc10774b3162684d5fa2f3015bb49c1484255c5ac186b54fdcfebe2abaf912cb743f1b1c0f4ba9a6d09b35a3b511cf3093fd68054f3ab019728c0d2ca4e9dcc98cab40925ba506408506e0b7080e4681512329ec9a5cf20a18d22a82dbfa0f59ea433312739ed0763ce9ab664b9b9f9244e8e47491509c62cb8807e6cc07dc65ff592474a21b1f7fdd96aeb6acbbf4e403e65754e582d2cded26de6e9198cf9b2759f044c1084a9c3b19be9bfde0117f14c6c550a42374a77052a3c420a9c603b094ce5f9e7e1925c0ee7aefbbcbfc56e8988edc6084bae1e19755b043b3eb604f3ce7de189bc830e0516176eb9c07c82f66426500dabdfc291b519e984a510b81d88830ab670ec64038a34f87179082590971e225cefbc950fb46ce852c155f254c1e5bf089283de54f89c68a8d92c9daa13355e0ecd061b381b4a02e5df56adb9cf5b5d9d3d41750d1653372520b031addc96fc657982e2422b2a128de0b8734f260cc4243737607927779b4024e91823d1f335efaad6f2842cb21bedadb0f2e3af20d34be361b3a0f6ea8435c59c1ad8c4d7b45fc542fd3cd692aa4df8d1144d7aa252cac08a9ad4c4263c840c7e585c2dd541e93fa526083604bc7ebe663965b5fc53f77a53c5efb3d613ac57bbaed707e7073638b396e2722a558d3329f4ff9eefe592df32051c35f19ea0bf4bf89e9647d6c2874f28c9df2d874751546a32c6e39c9010acc983a30febc1481ca23ab7a122213f170e934e3f8995ed1cc2ee298104661ce9f99462464edd527b222427f94ec324e7c483bcb079ce10c1a1c0ebcc79fabf45bf3b3835bae8e969d38046ba6ff5492a858a095fa1f2ac1bb45503db3da21180fdca1781513217ff0837b92a971aa3c28812c4da72d9039edf12fca93e13025e15864e3a410035cd1053a37f6f7b5f7db72112190a88d0c67a9df3119d75be62d2aaa668beb26b33d30bd6f0179c511eae5f4e2c42102d63452486b776cfb5cab7925cdece9aa47f1aaa88eafecbee97512f7503b1afa9f1ff60abafb1f764b5fbd5ab5762196ce88ddf1da7a7309387520a161c79a8778b5f659f35caf606be158c3d68f8ffd0c89539eee9f494387cef25850f0a9d03a7ea456c9fab21d88d704d35a586a9754b404a88ec97d35dc1aadc69cb4c80ed1cca5062994b0e89dd013487ed95882c805a0056e7ece9d5b2718dccddced5b55adcf0c2952da0d3f9ba005568ea24d50cd9ccd46521392751482d2b012a08d4fe7e1594a7de43a037c888fe56d8e1d7b36bed7a92259ac4651471bca45f537c4191fb3f6c9282e60a5f8249c9bf116de14aecdcd4e0394f33ede3b22278cc5ac86e353c863acee1a09fabef1a93bff8f81df11a4e07adddf59eeeb757ec08259769d0ada37a417b01efe88f966a6558c3a391034f11b8489a65847c31b1f50c08083ece10c0bcc10a70134c0806f0b70e237cf2da5e83441b0bf4f8ce92c77fd0900e77127f6a1fa4b84c098269865296bf24c3d7bbef859cfe8334f7f99346f2a6f68fb96a25614acf9169d8b675477dbd0320a85e12a17e28e3b3cf377c2f88044941a99e484f36294c79dbd96daf09c240db8067a98a47b80b5275389189aecd37499a22f4a6fd3ce4c99b9c1156336a8ef2be0a48cd9bed9dd49ee08d3014116fb4bd8e0c52076500026c9e2449bcad58c7d196dc2a5c06923454516ea328ab7adad00f2e20fbfec719a51cfe84cfbaac4f287c7e292bfb43eef8f8f142c4b92bca91463578d9b5e5f580c82cedb3993f768c1d203fe077d1f534a86db81cf4737f45f7d9b40484a395f12b4a8fa9bdf6dad80c509bb8b55f36948cd164203d8c061c24a4af65ca4812080b04b163bc913b395a304b65eb0f0b40d890ac8e27c8e20ce7f175ff089ce2a6519c85cf2c2fbfaa731abd8311bafa656d01670c0b03378b6331b92e5b9ecf6dffe686e53cc8b55b4c28546b6080842a32fcd70460078a6ba8b86bc290bb49427b9bf81f345854c7721ea5434a751bb71cc83bc0ccb53bea0be63efe29735f4d9188eaccb5c8c23712c922be069d081c6aaa7e860e78289219ea59a82f13f0616760f23ca7fc113d64258ef78a5cc2b5d6fa7541801cfe303a0b4bbcbeff24b314419719f5501092c4aa4fa49d2c5a6db5f8e44fab49c70db5d34a7d585ccb29f0086c3107d553552a1e1243b60f4611b8ecdd458416c8150d16d3934782dca4344a40701108bfb8e866363e80c8c63660904ba0e88cd276eee01e12b8fd476466da8bcc42f5a193eb0aac7196c2712ba8701da79bf330c52b0d34d7c8ebdc8ec3764f105b75dcb3cf6473e421217c9d5a00975c074f266029277ad07bf37c9574457736e28432a184a4207604603bc5da4e20f33ed21ab5063585367187ebfcbd6a9086aa5ca6299d205b2f8c53936922fb457e686721f7d26cb17a109564ad842b1535780d33415a5659bbd9148adf0819251c603f9ec10ee0e94d183a2bc4d28e203a751b725ce3d678eb01dc0de20707061b24158b65f94cac012693013aaaea4ad3dc1e263a1f27cd8a8a66c94f7c224a73f8f967e6c9b856644d5bb7271cebed9865e434c245c42326e2487e6104f850ef117761f8f77e73491f42be4bd884010ea2650b2f4b6b537d9f5f0e7481aafdcb909aee6d1aa60c054de925473ce54bb1f311edc3581538061b85d70deb39ea4b848efd882389acb448246992dd455b334d0cc5e615594eac5212621e9e43bb11e42d0bab7e77750ab8a113c63dacf2377852cc99c351e525cbf02100915c2f849e244c0487c810e24985657359f7b3da3c7eb986eb5af483a4accd277205fe8f277ceb3b070e42852851d30352acdd16a7dcc182c3ea3385c2f6be92f5a2091cb626300ea559c3232e526556ad01985e29cc1d06565ecb392e95ba35a350ead30ebc9333b805a7a3a5eb3228d775cd735ae8236a17a6cb0641cd150eef22300008678603c92bee15807796f308c85f18c031914ccb04ae8f811f10ac1056a57608fbf0a7513f312cfce0d409f81a18dbd4f887373bbf9233ec7067053a1d407ca9ed5a421c006b4defbb1586bca51643164b7fc5f8916d8fe0dd8ea909c6ae5c58882da27f27879af7a1696ac034cd49e0fd6ad9a1c78b651fe497cb79e647eb9c091a4b60b7402e743a20e5c7d102f2a580ac5226b051222174f011f073146ea1d621f78b3cf6587e1f9be2fe352a21292d198d13547b27c8b4043545017b0ec2235eddcca80feb8dc43bfd9cb42eee716d4260a586b00811322033aea5ed01ac63ddff2cb594065881f7103828531c4cfbf3a5dce53694383a364489b39d363d69b5ba9f777cfec5cbb6a714a9b2a40305c7c0da58174fee36ed17edc8af3823d1be4677fc21284b5cf2c92fe30f7771c31d1f0272e671d82ce3369d15854512d194e8a896bb3358bb531f24b95d1d2c12185e9edae4473e6a96a37f20c418acc07678d78886b92cc0444bd19688b9f2eb5b3590334ad3474b3c2c361f3fbea9fa9a9cdb51adf449b371040f0a09ee5fb62922c893a6421a9b6ad4969ffc5fab4028678b05e2b764b760737ee5e7da454b693d35bb81d300fed0633e369187880888a5cc5caa76fd3264a53c4f2358039ea84216dc92bc759548477686874ea9661c2a6142a18c02652ea7201a649b59868cdf2c96ca0150d837e4d6891988627d078f30154fb236503f2701fc216c355fb35c068116dbc731112c72d5743561bc837fd7819aacdbcdab62a428cc6803df545cb18373aac829d96ea968cedbf554fa737e395fb381a3f26f47b727f1fa9cf3c5b540f97bbbc900a906648563f755be0550ada6c9e5a9fe235483d8d69271b6b5aacae4c1426dbeda7450e6fcf3a1d4c64e8f55a1b35f53a433119e6b59b8e132951a506b4b89551fca131ca2c0b5560cd8b600422db643746e14e26f4e6f1f63ce1916bc777d9508c2950630de501930ea5bc5da927de3ed82c664dab86e3c74d992a6d11e8bcb4320aae3b7cf556d38a28ad0fccf1c026a7c8f742da238b6e75a2e4463d3951db96abec28dd4a8424ebef27f9ecc9f4b3c7a773b6b36d9d235d19ff0f9fa9131ef45ac8a72677f465b6cc6d7c9329ea5a06b8b0a456e4ee537deacf1eb2de8ea9c29b104e24f466b6311b4b5a9b701e632565769971535caea7df6aa8d86edbd8ca80dfb1aedf8f6fbf356759ead27b3c5c988819baef15219f7602fa68f0244e0d3fc7396103de1d213c1648e45c9dd7483f7844f66484514b134c4d374314032f6e428ac8b334fcc21b3c96168e668fc3dd8d1011c0d095a9d1782d9c0289f4168163c59e8ee17ab7c4a8b6f7b63e7d1ba25885355c0824e04ce777643adeb6912c34cf2a1f61e3c53833be7e42a85a80163f7a1fd1a16aef1162435a9d14d3233857d998ed7f711cba416f10675dbc03977c56315231d1427662ff9dea7320ef04eeda924d1820185217cfa4f1ca436eda0909fc39e9dc82e713eb6420310a5c0a31b168bf76d3cb8ca6b3554a2d5eea2aa7f72235f5adf33263fbd35ccd2a4111244c9920c463aa68701a7bd64e35ddb3b49100693ed4c98b3b83c612df5466c6bf0cb1b975af50f8ebefd51fb23aa61c10147343f1e23366b21986a8df6d15faaa2f0596c901cc60706308746e66465211f0b6e024b8b3cceb1b94d3d82f6e42e2a0a02e26490cf4ae3d742fb4011bc3fa006ab4bb8da78b37b3938533d622e75fd73dea2389580ff002ceec114d34ceeb08a6bf116da264ac91ecb52b0d03218ae4ff9d9418904f3fa0646f71bca0f31da2f074918d1ef98d205020d214fea791598a9da170d759c4dca26b148d5bfcf9ea7132e1729a03857980314ac4bbb22d1b845f4c5b60486ed25c141850ea9628150f61c69b9a6400ada7f7686d425bba196e0dcdf821d6a1c7b5d46c8013bb2ab98c0606a532ed179bb2c0586a51528f9e8caf76869c4d36c91440e2278a3db66c1b3c87009556061bd6fbf6873315506833048ea591776cad6c967014179c33e8e7638e491902a3a83c05b6131b370facef46b07300a5a93101e4fd28a9fba6566f34a90661fba79fe2dc61f2a93ca0452396ac4f881865ccda167eff52e7f9a4b9f968835df62424c22378fcd268b1a55c8d40a32050f920f89e244eae277f1bca5441e4949a7ad92e8e338679ae186542ca878c8e2779c5a2ca8a2d6c9ca4fa4bb181d56dd5e402264a6749347033123e265831008d11a074b8117d6e92ad1bd2bac6e518caac5878d3031c2052aa45ac2dfd77fe9fb23f067cfc54c2d53d83f43ec9c5caf6d6415c46c26d8fd490ac2baa80dd5321849c879ef9826c0d410163f4dcf76665f98b90eb9b390012e69a832dfe803ff8329bb52404154accad92f8c63735380dffaaa50f3cf22675453fdf1aca579ad032ace2418bee56a95e0e539ecf80a561525ae80f35536332b945dd400de37ebf4dde2efa091d9d5dc21d6d5114394d6506d7aa26959cb0ceb9fceb00e09ff1a8f1e5cab062196b50ce52d3a51ae9b45813283cec49eb510cfb48fdc231080c03e1a4caa6702372ad095f11782abe75e52dd35c10cb9cb912afb10de67a990ba0dbe577909654b0d9b22cf65605c45faedacdebb47d61c8e12f6aa8b45549f4e733b0f57c1c89892461fb482a9d464603d2596611aad3ad9533db6c1e916dbd806cf118d4f93aabb5feb1d4327df73f71d7e1338a321e1be39ebc99d999f4faff537608064ab0a9f80ac8ca245530b2e15b3417de172d54e16535dea2f7a471b4bc9a5997287e3035b437507f7e5ab4890443d711664add54af1b126583c75877b9f630074fd603d484119feb34f05f960a1d2e7de246c13d771edb72a888bdcd74247cef7cfb58bf0174d912fea5dd2f60d9a1339576f78fef6e0c2e4cbf54a7074f967f41485ee2fb2013a41ef27ed99b151f360d4e30af339561ad93860e23288e3a59ec49af4b4aa06764f58ca5d7fb23e7b3c5e1eb14b0e7006f8eb947a8d1129a47cb0ccf60fd9086f37db8851498e3772b556c322c6d037bfa2da1b463a7a7ddd3836776d3b792fc7ea15d3d5b7c7f79eded26ce61030c0f4df97d8d4128c656fe222854f7ef2a6726195879565e8324b9bbba27a4a9677a806ad2a8b10757613912b00638f977b768202bcb6ef1400575c8631730deced975fa56f6ad48f3f22441a873bf22f9144a8b1439bb92a76dcfd8233ae5fff666bfd1547a09d23cf70c61f4671b051cc12a29545f2666d9ffaf142992a04e3d47ed4bf41effc2d8b2dd9c1e30281e4a8713d4a7f9ad58625c01c7bbb26ec27aca572c28f1abdef336133d2b7b10be768765acb04c5ead60d1155d9a7c7bf72794daf43435998ebfa0541777837e199e88f293f7214e18206e1ea94b329558c5a8fad340957771ea032dc10864e0a8a5dcb139df4c9ce7c6fc8be4b3d32e03d8006c8c7c4d823b23d46e21f3d4c91945a09f01b19615f4d7702283e841f2a8a6274714970afa36d780d6d0717a1ef4289d9c5b3172f4d8da5eca4f421d051545f95ab2703fd2162d2e127261ec36decb6e614c525815f0488018a7047bd4a4a6415aa72d88390868447d47fe51f4ab3ef34ae50ea13820ca8a6fa92e28d6ae148054972b5c37254f684d2dd36f107e7d140160513eaca78be01eec0be8c1da2e20a3c60d1c042418fe6e61e46e49d88ea9b4dfbf49ed48107197d649c612f726ecf61e40701d65365763ba23c75688fad435c633be6d75ffc91176682ad4c8d8b838cd4e07f0a530c48a1bf2f8476a006a445aeedd4559d90c1b547fffd5ceb162f08089be67eb79a38194f3cf9b850d6ccef2297670af043c0910873924bfb59535f49cacf6d4c40082f5bc99e3b9d49739ce5407c850368db900f8a37705e0f86e19d3a72a6cddf6545c8586802d6fabdc5fe143031ec0a1da3c28283112d5807ee02d17250670081ab31071a7537f4568041c59c4693aad9bba67c214f951fb17256914a12c75178f844d577d21052f91514ffcf1cd0a1037a60d1b773162c01d1f8f5420ce07930e6a7af014266115d7140d8cde7756b8a21b0fc9bc17126b092497ea8ecae22013b9a01bdbd4920b335eb7f568cfed3a4b137377bcb55f736172ea55dee0006ef644603da16f7713af418a1e119e6419cba14ea3658b0072e308233a9321a16c1d62b89c39aa16dc6a02d146b5d217b19dfa75913ef566492abf443f004553ddb5cf9b7c043db92795a2e1b452b1281022863e5cb1f34e20c0d99946b8fd78b5229acca96a99a19d63741bd57d444b2e61abd737eb06c98a7095c592abeb378bd7eebea8f525d666ac93804196d0950ac1c94f7cf5c24cd60de4850fa7d1c0b652f9171018a117d119624bc6e96a00d65607ad7e4c725e33c0b1537c386c2a16876a073db73f924a29a9b9c253f462c3597f5de96c7a27bfb3e78600ef1818ce2a0c406d338112a5f438127b35f9cfd92ee28feba41fd04335edbdfd20b5bd7d98f51fe5294d2b381fce96f1e86569bbde663f46c238d3d519e751ffac83df98824fc9e8dbd7b647b532fcbc8cc84d8daa250066247fef32da908d69a169f187837888bfeef5c0ca50268c731004782717c984924e4c72ecb1ce4a875b88ade6e2992df2143ef13fcfa9c20138ae129673e399b2120cb8ddb2549d7980254bd1c7699aac7b1d4a3d88736ab73a6d90a71092a09b1177d0326e6d30caf2c5063c0eec544250969b90704c51df45e38b2dad2c3152e6219340f25cbed301f0da43223cbc44a3c926ece2024f49f1e9a93ad3886d1d70809df6ff95af6c0737deeb0e8fde764a7f29e21fc322ad19b6aeadcd7d6528b8f290e4cf7d323fb3b7450c89f0b2eb89157faf9de84dbf0c827919752747942c274f9cd9059094ec011988607651699297213a31ef076342356af51b5399cdf940e5881a904c0e8013d253d191daa0e0233bc5660446ce94c735418576a4bb3ac1aaa6e6d74047bab12adc01a5abcae9fe71711652f864997a14fb2ae678d0b0fe5d1d70def824270e092cfb06e392d1c09cd8637013c1869e698a88290503560e73ca4b7e82e938fe6b13480db120a876b773399796116272b31e1a94b7e8374ff26c43434eabaa92f7971b02e93805a96c71797446b743ffdca276cb80538a250b208d7374ba137ea05e7209a11562a95638da7da457bd5bda6bbb2de7d60cbd4278cdf64b2f5814f49f897f41fe5ccaa8a9f0312e0090cb5a041c61e25c91a1450a92e40a864e5177592464c7b47f0e56ce8af6bbcf18e13bddfcc57fe3542c15eba6cdf066ed8cdaee8f7170bded6b66b3012865b49f66a3253a563b200d97c94d047c1490f4b53f3bd7cbb3ea1d375b0f338faa2d41e689c4c7c987aaaf3a6c720b52f01b03635e3d3646aa7d29c8ff208d692d6ac5fc903e530654f2b509c2fb1ede542b61e0de081639d41e7fbb0c1f9b47d2dc033def4d8ce66017383d040d02cfcdb8f7b8579cb49eccfb1447de6ea2f241696a374fa1e98db707405425dffe7cc762a2ed1fa663d7cd0c4747b26966f08decae1eb7019ff7c09a4cd383e1233aa22a99d553ddff4921a4c8c142f9a2dec5cc3c4e8cb2c0611bfe0aedafbcd35444aa551802fe1f7ba3974765ce5fa5b3df9e8b837f0a49c1d3a0f5c0a2a8f361f49a2466f38b2f0467b93677b6fd15e15603b7a4a824c37e69c9b08c6c05a9b6817f385416d64a78bea57cd32b69df4d8858d6d077f944870040dd317a20466ce83f47100190bf89fb8dcfccb3db2ee45199a5c9cfeb388cd13119f7cef61b47cde3bfee5fad7293bbffe63f27cfc5d0dcc99bb6837bf696152c02dbba1fbeb01a020f86143682dd38b20718d8b5a0463eb6773d5f07cb4770b309492bc4da9875b5a1c82d91bd9d2b049c7119ddc0d080c786dc15d329e9c4fb1e79b37f16eeb1d9d96ac95e736421eda1c69b9356467dbacfe81d44ddc4264401b8f76a7a5b78ee9a8d27d33287a77d6f160d680778e5d6d585595098d699c17095dd9088642f90c41f1d27b4b7036333380d4cf2ba4911533d0b77bbfbe7d656489086ff056642f82e43c42836809ace7f7b1de5fd56fcb1515cc29bbd1181028fe679b36b751d27f135d1627291e88c6d9f23ddd90250b724d81a9ec62dae75a5a664d15abf9bf310fe05ac59be5356396a87753b5d3974a70cb7d3b535d81ed197f0ea75873bd8385effe0260c8af848c963528d57560b722f91ede46482b29d64d06c08151d909e06324c1c5eafd5445203807d4b90cdc720ba48a0cb2c019ccf78fa00050be22c28325df4c61a90077706f6bb925ad7a9bea95f2f4bbe1b204477c7c6d1c3989db51daca044caacda855402bc3dc41d7d42827cfbec9c62945b6f1e105e30e5617653cc6767d39c0a742c6f02ee4edbb48d35c151a75eeff618613b9e4304e1ca6586f777e2a3da4ca7de9edf86843700faca0d4f3d2a4f29189c1ee9fb92a24dbef19c7dbc017d9c2b7bf2d749da6b6838dc005146e7c6905faf055f82ea11bd1a97e127580f1fe44f09c8666251ad5f5090a5799341b56fbae1cfee237feaff108513fb27ebd392a7ef20c505964d9d5fe3caeef6b8d89aa1fbdb8b0269053187c2c9baa4f8024da6b3fd12b5cd16cecbe0d51d0340dad732102b2743c9457557905bcdf8d32c2e3b1b5169e3c4654f72db401e220c83c23825885a1baac2926e98a949a8390bfcae09b5858ba3e8e065dd22bbd22736b244ddcd331740750464cea9afe709ae18ab3e2dd22db23f45e26a0c63252d706dde6ab0172766ea66db861ecb37930c62c945bd50699dc78273a624b0f07b87f3adcef95c3dcd5d26f93cd390c77f982d35557c953aef5bce10905222141bef71a054f4dcce995f1879bb2049120e7e2ba64e9dacae2c2540a6a3c2b3c1a3155c479c7002f028adefdcd54dd6a039df8d96137995862da08701fc4659049049637bad263028a6444957e3aaef1b950c90a985bef637e377c7d3d9361be50359f0d08246ef473c02e497daa361191041e907d1cdb9fe6196bdbd0ccf578c00b11e012a280a151d9cdbb59966c5b2f50567f7d720a0183c71e3cf744862b16c34c8ebd77ae62fb8307f42efeefeb7cd986b148b3e316613bb3dcacad59efc3a7870e0c25e35a0562f29c3283ebf1ea385e50862ddc5f4fac6fce055e2321406e38fd4c78592b8fdce30aac949e6ddbaf535c519d9d3c5242634c06bfb51ceefe5e665053be4404feef871168cd0b01b24a440ebfb370370b5062f0dc2240b447a1827fe37550408a8eb3a9c8f6aafe92f62b32ab3280a5da12417180e85c41f6cd131ba9a3e550a8b85a7cf3f1d61a7267540ab3cd1f4ddf0a6756fefe95d1ccc413b552e343e7b1d5788cfe708ffdc531fab76ca0943bad46d54882ac68ba3698d416d6b4a6f78408b108b33737e6319a306bad20991e0909264418602dd258648f71f4c5b157a481dcd970b68522f1f78e3745681696f1602c062fa4cf5e6726dd849724576aa2744ad88fa2800672a57819e9cb4cec97f7fdcd15700fd200b424d90fe555a47322966651311bc93a81b80978a2a8327d464ca7602feaff4573f1ab31e71f220ee44c2f437cb4b17d9c09534d3d8f9245258ce0939914bf7f2f6365253176b690c2506dac93d97d045ac356800f14302401b4e0615640ec32c24ae43c1da96a7ec6da25a59c77d7bf52a08ca79b382b76e09f7da43ffc899b4ecd37a3fcf548a1a16ed5e7e2b2214aca213464d96f2ac62ababc1c8e869a4dec017167e4e8c4dd789726916932b137ea99cd42b64e0898f9712468dc6039c432ab6f5e41451f51a8cc4773bfe149f8f1a43946dd5f7ab3bb3b51f32543494515394ca93880591bf96899af1b32720d50b61cff7385648d005c702dbe36e5b0fec4111e4a2f127e0818f6e16dd4ea4d2678cdb335b7c1a46122296c6322b817b32adf121dd8b39f33d0755eb3a027068451bfbfba478a03cddb7f3367fcccf48129a8a5efdd3209c330b263f360e9be6431972865268bb5d3fa8e1bcf2ab384cecafba52908539f91ead15c19f780b758d6f662cb9efd0d66e348c7670a39ccc6b3a50e518e3a9ab0a8f1ef015554e132e42bfc3d8f589406c7fd3ed72f2af66a563587da1e95cac87844f84cd26c9140b1c0f0686fef5524832370faa66a7ce03c4bedfe8ad4234deec60c1b07976c8d7916ce88434c66fdbd1d240eb49f2c6a249118bd359e4b14e3fad016ffd2db1a09de7f1046806c67a604a35f10b4665600d84ac074cc0ba40639c176bc8cb53ecd079622fe11b5abc6348e4f3b56a47670b8264148cea203437ab956b7b34f15f4d3a095da67cfdfb0c28b410f65f9ea45ed42d1a2ef569d2b1d94909275f5629640a1a4ea89e61a5e04b6b37eb709685bd67f91e5caa985860d5710342cc8f5ba549b4f0971a4a21d5d3feef05915323baee097d727ac5f8873c7a8eef4120735af0baf1d70372486ec11d568cb0f29fa5e0f23a14689e7d278a764fab0c5cdcb47bac2c8b0db98ac77698744f90232786a4ef40296675b3fd1bea51468328ed25608fec65d4d3bf928f966bbb194f5d0b59b57901d02ff10f197dd932614c6ebd9a84a23220d3bac24f0d2b8110e5efc7c67c219ff2c903d53a45cbeff47799d32c2737580de8a6bc9bed4e80f3012060bfcfbebb94f739635cce82d219c3e1f9f222bc981b5971ce126f0f5656ed381c6d2f788a1677961e199d43741efeea28c7cee8b50e109f9c3a8d6da634bb2efc7d5121bac4a2468e3b4b15edfa9ef58f91999cd7ceec11f4e441693ab26c56e734654305a34fd3664e6db925e417ac82d10e6dfd8b6eeb3ac45479906c9cf02d2d3a85be367be42ec638d2eb69c870abfe9ed3bc26cd41262cdad3331bd134a6ab76bc5f8e93589cc273b94fe361a9ccc97ba595680c06cf1620bf4f00760d066e0024ed5a78ffdaf825b6d9210f55116d225c8c37be0454caf469bb299323eb378803c891f449d7c4b2eb8319512e81b88087950283831d472c5eadb6770699d12eaf596dcd9be5c4de47d2ed93574b72e7c5150f324686e99dcbdabbe6c21c8da3a3be794531e395526576ac281df3551ca9f2034c279604a69f77a5fbc38586d6d127104ae487af6ce6209dd2ffaa7637d696d4a9e5376ff44ef6f8f0192f7d6db8cfddf3b395bb749f02bdb289c8c147b7f702fd4dbd3a1e58aee850a6ca7f07589c5d25d8ffa4f1c6cdfafc6134bf478c4781131997c686b01ad0e25ff5da1fbfdfb16a776913b18742054c14aa0fe5fffca1e2f79db4c089967c74a9bb7aa3805ee7c0e85d5c367504f3285aa2fa5a984a454d937c5cfc692065e5b89a4e8bb0f7ef501cb793a55cbc4b08616ef71d98b29a8e32b3497f23b8478b7fbd40bcb1a3768ddb23a205dcdf2bdf1029e18e0326a26920f38f98d9923816d181de1da94f85862accfe3e74c33bd564db6afb3027d235d157940ecb6ac808827fe2e65e723d50484d0257a9b1bb3f3e9732c3a3bee988d27455bd177b6cecafcb861f89b3e4e92bf6f66b3c214c775f98b5297ddd532807fdceaf1857b1ec056419b06be91bd352a6699b5f1e0f9ea41e2ab4624690df782925ab6d6329d610647c3f785b9b8368d2358fcb489928086ed9c3690ab160016057389c2e1d6eb3ae9a5da064b9f1265ad40d3d223b2909fed91f975d83d2d1f9238390a84047090a0b64223f16e436dad078748054811a52092e8af62c583c56883b3bd425d6aa5c2cc6747f501e71f3f237265aa79cfbaafefb582a9864413ec6a28a2035271b318ce798ec4344c3fd5a13554c16afc2e9d5fcada70041786fc587a2532dd311a28511bde9e3db8ec974f818f1b5df1f646f3ad53d38921312ef9862ba7d4de886b9c599b0abf715330b6d421aa4a05654234c3d2b2cbfbb013612d4a1e6d31c14696201e995d178315418ad33c5b7c0f374cb1328b3763af3be2e44401467ced88dd9150736546bd9595f213c16dfc2a58c8473748ba53c99dc1e0c4bbc8e5e52c6b19e3f7c042f8e34b2235a0d6da52db6d3eb7a60c9d9862fea7f074f3ec60964b0b4e19eaf00f4c907b9dc64a1f7e7ea0e84d36d905428ce5402127de3c0c89cff83125e61f94b4b7b38194a2a8f8d5f8dbf08e711a4954c81aa03b3979ef036c988ecd532ce15d82624a15ae4e2cda925c3e0a6f9c5d67fbd37f522ee93f9f61586e3c4e1ff1649084b8c5b62885c6778624f09458edc72b24ef6cba6cb75e517fe3012ab8023d002f75b2213cbff1a767bb76b6c58d67dc5781276f69b33e741eb1b4d23e70c14f44c739f67864136082d7c37ad788bc33749807bd93d02e3ed1724f54fb2043eefe5639397a01d0b3ce8933f664009caf0c7f17331f12f19d50746024c61db79e3216145d5f4df7a9b1142ed8abcbf166797e8b84f0a843a490d0d62bbb4c4046cff18447928e1b1a4ef96207f131d8292266eb05d10a6593b1d26b6080e3f37e6ef16fe4f1633a37306811f42ed90b154d5addbfd6b12520795bd1545c57309b9260f2296b3f8ef95844f970b546a9c7c3672b0b5fb026c97da55c2fc51543e3a047e7feb1cd428d779c0edbb37dba1caa6547726ee16dfaf05185140e7640c55f1ef9707123d99a3d9b8bdfb5ed6dbab2f0cbc02c0c58d05346ea9c2eed73bd2e27e3dd2e6cb48df5896f3d89aef974e0781493967bc84bfce1cdf0cd8fd0d8b6e9c40228ae69b615edad9f583c2875119411a37a93f95c7f814b020af44377fbc943df67ee8b9744db77fd2c5a61f48c078892b4a03e5e4833661b74911a117afc6b752b6bb26a11eb154eed6f5db4bdda4ff51950e757b8e855f09b6958794882f3e33752557491b15f7c836a26e53efb670904eaa99ec3c72ef2173e1b6dc9899b7a40fe94fde3ef2f0e1f5d4c68c521776f7f37275159adc1ec74b7b0a8ad43a0d074bb0d86ef43486d48ae8813360f17e830b6523c975df01ab1f5a01c54b930249c56d40690447217de6697523c10055c93693c921f655ba374183812bac5bce1990154e94b68c10c2be4659729c506cfaeb7f3a0f33e2a2cc47f662c4043834ad00d38cdd1f0bb51858a6e338508e3221ef8fbb2a9bdcf938c34b9f44814861a4bb294888a659d24f90cb4967fbf76f5094c4337dc37a99911c732bfa8dae90f852cd85e8e0017bc12fed41de445b4cc5f3712cd80fdf346ae129678eda99c02c3d59eb35ad68f85a7315ed645564601b3fb36718255b625c15641e37c0f64c9adbe724dcf320d9f79c698e8cb1e28565feea8bebfa271e1d6080ce0e161054fa6f17c6d6c7a1d97d37c426aaa1d1c7561727d703c0de059b382d24f4af91928c10ae3f3a47c4b25d8f7ba55eda079bf6c894eacb23f8c266d2c4adf5988c1e26ad435b01b74d9d1d0a55474c907e55a51f42c92acbb16f601bfdccb22110d6f861d2a07440010be6c7276355d4495d1ff1eba59efe29de2ef1239e526e7b185906c3c928e375d9328d6d43df32ef232a09754bc478c3691a8ce0a49dc2cb4cbd4c14d53c098079815a8f37aa63ed079f6de4252520a835cc995ad61ef3d9342397ac449f22dd8a71720ed326d841aa27d8046a5ce795a2f1b74b8df74e2e599c88e5a9301d8b79266452486811ed791e72dc6efcc24f670600e5a6933efd1d382944913121e0ca050a2608756a326720c5c9ff2bd03b753a725c2ce338335dae8fecaa6accdd86bc7c3399b56f32f2c102c3e3c31a174806b777bd6e94cbff0ac7109b98d7d5ee442e2c4729fcba7510c73c093e282d8de5ddcf47c13ea7e30bfe7259ed9a1998316c6911a22d0a500e08f8fb8d8439d8dc579a8ecd9a4d7955a6b28ce12ced32a44ff91c0c59575c307db82268ffc981191a930202cd7d32024419b44f081174ea35a5aae007f7c858261198bfc0f92594c21d24e0b3ec6fc35cf9748eb4d695152f2b1a13b14e6a5e48dcd045329687bb417ec417210fe8618def83a9648d3881670dde212dd67302386b9193d54f9cd70b7dfd6563f3a39835ae326dbacc94aaefb2bbd3a83b532e0464515980ff2b468262e76a704f557d9b2ed87c43b39198c6eb3fadad252ab93a7b4b19c34bb4495ac6310172d85efbddd7e2c62b4cd0fc67fb502c1687aa4d32d9bd883209475784e3ed8af53df81668bd8fae2be182dab90ee2ad19dbbbd65604a4fd8236778d89c17f416725c1a38f1bfb75e7e43d7c20494ee0b1948b781294fd82ec35e5b29546e155cf53c0c772118ecb33b9f0513a19724069390996b78137c83ec5990f0068cf578963a8cc669f1a81417d9cf80a0669c78a85a7c9be52e2baf92a7b3b160925435a644f8f059cdbd51b15dd08f57d22e039a43b7dca7fc99dc0c786dcc707eef2dbf6ee7096152e0b3caa540156f4ab227319cabb4db6f6fc4df3b29732cdd7c767ba025f8b55e97d8bc6e8716c8790b0247f8245abc2e3199de1105de0b9259f1fbbb71d6f569798e5337d3d5e9214e3fdc7976c6bb1fca38e61c4fe4bdc9ca1e7f484cb2363a88dbc3258c7ae0b35f9fe17c96f9f67ec150373c09f4d6addfef8a647737502e6760f5fcd27e9e6d9e1ef125afe9fcaddb7bc09ed83e5b51440b0c86425f63a793fad54a6b1b2c500efa83cc04ed622652694b19e58ebaf3015ad207848581fa4f8f5fbafd3b1b7f835fe71525d256ace2fb090a55435c793667c09cd50dfe18fb34684bc17e21c129ae5555f68e8885d89ddf44ff18d0408e6c3dfd5933e80f8fab524205d776169722f1ca59fb42d4a6fb2a8c5125f2c1652a886551b0b8bcec81035fc32cb52aa7935d65c06f1cb937d475b7b339f4d337a4691f12a61576972ea53c4b3878f38ae3da33e7cba0bdcc67fa025a882afe8e976496ded6bbbe4821b915606a1143cfeb692efbc88fa1418918f8bb524457bee5029c0cb9704474850e0a89eac5c5bda8dc42ce98511f70f0d15482eb43618a377f23597f9c446273f17e09ffa51a8bad505078ca7cab5a9e97bac6994b5e2c4f1bae49274b45620fb767d86263f706826ff6981df9a431431fd1d25bf1aa1a4964e461f24f2e7a935a35c52660274d8a57d0d205c908422be6bb63578759ff2ebfef759e4030395b78a9c41e9e6e1361d8d4ea9f92b074672967bab644d713c4441fb534ab9848d67d8f5004950900877c53d7456da3b561e143c62e89dd05293c976ce8a8d522f525ce5ca36fd949d293932dfdcaf27c8d1aef135f2e48aa25f22bee950f164989c4f8629a3dde78113fa15d6ed4d538ae5e7a1d36383440bed89ea5862ce6cc9d4169b5691c12001f626db7c28b34b816db364bc5e5c332bc964d67a29a1f0f27b3dca757e4e041582a2cfd065687aef447beac02466d1feff3eab53338bf77cb11b03f8eb1a98e212e8e005ef6cf9f5be8409cf030d3402fd6569aaabb11b9335d7ba0acfe9e8e658304105c9ebdcb4f717f7af6583768293ca7b0d0593bdaf696207b999b8df48ddbff28b2248e969d4f96f685e2b0aa413d27ec9eaf0503166d1e2019e8088bc51eec4e60fcc7e7b8bd9160b43c1fd716edac59b8e6abf16e9b3f440043bad44f9baa31c7fb50ca6190e01008c697c1534195c17fab8eaef73fcccb8b514a2191b1c071bff127b7a4f613d1074f0e1f7c6f7b0397dea778cbe332dcb38250683794cc213d88d463794a90b235f607d6f6a2927076cf4f0f2b26e3bc00e81e87dc9565e3145bcf5aab5c4dc2879123da539b9360071cbd8fb740badeebfce06217c23ae35d8577eb6de98170aa2e639a73bd4436e05b189363e9a73d17dad0fd8d10f73609a97ae34a298f6ccf968d63b4cf977cff9fc01ddcdcddc35ed5de7c70676d7e5772d61ef294217756d60ffa8207241b4502054662dcc6e8aced05aff4c04328d94c81859736c2cfac53883c38f74470ff7799e4011e00bd71a740b1951d3e17e886482fc7605a4b2f58b34614a621d9fb2e36314c528fb1ebe2f64132d72ae8c49c62efb3a9b1deb3c870af0c34cb26fe6cb75552c541c09635cb8a5d9dcd05efe99a2d5217ff9e435929718c66edb4d8561eca3d85f1f256d6769618697af9d399d1656a1f8133ae364047da1a2359618cabacb7f9f0cafec2f835ae7bc79d8315aeec2aeb90d98b36b79c5138b278f5bde01737303327a7c6c12dedc35766ab27281d3cdf32e0bf9145071c2ed9d44e5dcc582c541366fa15d6b4836dc22745d5b81d2f71e37843c386b24ec8b4834a3884ea17506cfd1f65dcf490b170d701a9221e425727262cb81f218b19bd434dfe6f5f1a1d65df94ae27a3c714fd1adc766950d8fc69eb28e2a99c04e51c05674df18fd67819776909fde8b4f8e77d423b9792039463a893cd5f4b06bb42116b6b4b1890ceb5bbd5ade5b6af2a8d9d321eb98e065e90bba5a2aa22299b51c064f5fd3fb7f9bff8f3d0e6391fc83f8886ed382b92fb2a016159b11c081a3979bae404aab79874b1f659844b8991e512b214107a624fe4f65a9f882ef312275ede58faabe51283b7d25a62427d83d58ec39ee5bb75230c9ab7eb4114909117f5af6eab885ab1be24a5d923af08b8960ee23980928cf5704d1ee27b60a28f502c4e6a29d92ac4365e3551ce82fee39ecec5f9e870f63a89e1e84ca1e076561e43cfb012e3c67efe043055596a6c56b7877eeac75b21593977955bf33b9bd4074f865f3190a4db2868684fd067156f712e1465587955d9c32ecb36b66cb5b9aa557f6b50d2f814f21ae1d00af6dde25ce0134b38853f7e68e1c345cc9217387882aaef066c85641b37b5e4cae096ccf25ec903327c83840fa7852ff305cbdd991b53434c942f1e5360747b4606f55c11db319437ea707069cac6b606c8bc05e0e543905bb538d28a238e6dd7d3226fd4a72cbbf6816190a9b9c24a3eab0d71c7f6f537d1422d324fd2fbd7175d49cddd5db230abb03fc17f4739d9a1460c75a986104d970eb6179eee8c5805ef1bb25398f408251144f4746a912b59cea44729b8ba1e137d1cf352ed1a64e1fd7232da166ab155e94cf684f6d3116c9f1b9f18824e2cfac2d513ddbdfc040c6ad214bd8323d85fb3f32f499c82f80b9efab85bb3b7ff55ef5533690727b711e58be451c7db845b934a6c35dc747d1fd34652c0bc1dbaac2824b1bb03bc093ad7cd48983776a37282084252811d24502d1c6c7d26746a441b5eb1a5c915c4ad247d69fa8aa641bad59f76d5e3f39621e919ef0ea90ae23f2681f0bb47706428ae30ddad12426b294410336b17a0606c402f3b537d9f76f1d38b3ca7a",
    isRememberEnabled: true,
    rememberDurationInDays: 7,
    staticryptSaltUniqueVariableName: "0c57ea5e86ef7bbc2ec7a799f337fdd3",
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
