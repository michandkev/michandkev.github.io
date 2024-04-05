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
      "98410130fea0374a2a69f43b41ecafa0d945abb597c8161a807301a22c37e0b28f6a38e27856a4285760b5ce21805ce0cab396ba8ed66c0aed34f6c7be100de019f87ad71770ed2a645a9931f905329098d08738a957c342ba4ecd8e72df27d7aa172475bf81fad249987185048071139a0a581a02c62622e0777997dcf911c27c9bd1edfa7a8f8311e69474cd11a2934ac5a53bb1c1f567986b905f31acfe134ff95a183127231e3b4ca2e4655712e38ef13096441c5bc33d09997d9d0cb8c61e89ac586586e8dae496910edd8268cfe8fed3e0747ddfb68b8e52135b62bd88fbb9da051afba8968cb01e3bfdfc2a662ba80c076c1370226ca8c4fb2c959e3eff9a5d190770e91e00c6e4d909656a45e50853ba58f1cb6b2596e65b13c732491e2d75e9de9e3412dab0a3ee4f996ae2fecbac40bc5e437394887364495137f82e773f0174998e15c9d4bfce0291ffd9054ff98b7180813586e441caac7031c2690d35f16219228b5441acf4a8615cc3effe10ab6ecacb66994563f6288c750d8bbf238ab67697df9065aaeb385be2bea3a0b6e88e1616291c3ab5904575d294922bbbd186ee935c92276cfa4a4ddf2a6d4e81e227197554703abddae3e1d30045ef762843a9a7a4d36c300a44c0eb7426dfb21da5a13e99d518d9d4d46fce38c9584cc11139ca8fabc4a864841be33e9203c4463bca28efde10f68a18ce2d5fc321c314d180f4dc6f085fe25170eabd90435350d6d3d4b53cc47ca27700cb4c8ba1e84491c578f9fbfd228f1c763e883848dc65388ac97839fa73237ac905be815e9827e8ae611ad754dc3027e97877df4c122f1b5e79c6823d150faf7d0d331a9477e223d2f56313db3d975a7afe728bf6bebd0c3e5f6a323d5c8e63ead2b67b6236b3ec12da6a075bdf97fcd806091804361c86539bc81e85cff6aff4dfab853d098492e129806ef73f6421319f0bfdbe0f02c153243acabcc8fb5f1bdeb141a56f944cda4340ca32ce6362dd7b9d4b9ec9947a22f5f5ed958ccc60b28efd10b298542f0a25c3b840953d4864562e29d35292099359795e51015ab1ea34f330ddc4b672215949952ea880d1d01889800ad40b1217934bc7026ae9ff1b1584043a334207533d2dd0dbef1aff4f710dde421b23ffb548ef9462092e4d35dafc0af759462552168166285b73b9b15cf48747307c6452ab42165363e35516fa8bb071d7d9adaae831cc29cb1a9e96858869a14e124d6031b66d7269765f750473a10e4d55980ed2eaf2d25b9fa5bd526f961ae9f5a50e457bc59cb74559be0cf193ecb85caac9a8161005cc254db0f0747f3d59be7d740ba44c6f95e35f1c15b8062e964e65618fd54f59021c565ddee0b7304397af00019bf0036fe00f98131fcc2990636eb92d7bb91775ec39ff11135aef5d10b3fa7fa55d252ba72a0ecc3bd0461ee7bf1443b4f038c533c4649eb5b8a35dd67a8dd188630bebd808f2626d68a9ea4ef9cc4b855009d178722bd046aaac240547301de61fc004e147ff0ead087b2a2132e112efdfd6818e2b2f8d058f1b1d1c6e24144a2d2a8b18e2e9aee140286e41e4b6ac397a7d718d538fa7d478d4594e98432780851d5a752693cd3cfa8138664b4b3580a2df6bb3d8f7e4dcdb5dc648e4c1bb6e674ca261fa8f9bf1124d54c68a179994e4e703f7ff428d7ec5bdffc16b11b535f4f0d52c5f3a5c84e51f8cc5cf1518ca12561646bda27a9397236468687dcbcd74984c0a6508df2ccef5573c875a803d9d5d0c145758c31685a8ed4b695f48b2bdecb65252a261abf3032e6790f20db5c4da478c867d8daa0e227c4e2d2eafe161a8516bdc23e058499021d35e52f446290046fb4fe64e82b68220428f0eb4229114359cd2ab55a5e47bda6eb43f88b4b5daa17d9237713aaec2d081653bd04984aaa64b42efdaca1d3f0ecb7efa403c60e5581a685ac665430e2ce94b2f7482a9224e5e0b3db519c8f509e5507017cc04b177d22a2a2fffc68d334236e45e4efdd418d2efe9543a1e2631dff9271478044513f953f642c1527deffe25806f8fe2b78ccd8db2a4e425e550f172375bd99683bd2e2aed907cf19f13aee6146fdc187e28448891925e1101a107ae737e78da4c5d2291e49c9cec2b5622f5383631b2331611f4280a71c80b50af02952701cea7229d2e1563a64bc6d11a946a52346f1e9c8a335c160bec86f40127aee11932c9d1a0be53bde2007b02543d9d95a9beec4c2028d1173ec24e3bffa38a0059ae109de017d793defd551091c16c72787ba6ec651603ae290fed42582795e71e4291e7358b863ebf64bfc2a8d4249d8a3ce065aaed290dc8455285a66dd86265aef51aa4d9f6fde44cdae6bbfae83f7e7feb590b78b326a9042f0d8356b1126ea269379eb5c1d1a304b5947d34d5f8e11df831fe940548784736be0fb1a128230eac0c3a9bc54acb7c4203cc3d5fa641af9c4466da7b5850e9dafb3398d8577387a0d14f289cf5f455a29e0d85cdeb66e3f768a6d4356ee1dd6bc7643bc013e5ef267bd4baa0f3bb1f763c90965e37ab69d8bdad583ea85d6aabf94358c7a8fd10a03794f164d716002d62e7795528935f39786c40dd0588e934f589b54a7974d2e60320bd195a3ded39a34c717fd92fc8567ef3d8d7c19c65b45ec911505b584f74ed0daef475a0e5d2e7fffdd26a6ced553a2c5815e7f229c2dee116789a97cbbad64c5808e0eb93591900e92f998aa3e9a37a278b6c00ab023d4a6429fed41dd75ab6fb9aae143caffedf3821b3acab78849dc764988cfc6b2d1d91f41533deedd9b2a5ce3990509ffb5e9a822716ddab7e86aa4c0b4d3c2a96084ecb8296cffaa9bfc286dbb0a582a4fa7169ccdf2e2899b8b65bdb73b44c0c8803abdf3129fc0132bcb6ec1052c4ce92f469c237bc5cc832d37a1becba3bf16f062a6968f561dbf9ee17fbf6ce9031a804c051a9d05c11a68cbcdc8c21b8dc43e5630fff5dc0abf9a0bc2ba3b107f6e7e03d143967c952ecbdd9c8f3ac6efe3c5de66f34e7dfe9c9611dd9fad02428c9dbd6fc7bd4db5d615e4e584e67786bc02a03c081a77ba8b3f87c2306bd84b0d47e07fb53631b471b91521f7fbbbe48c21b311e8d34afc0b8194a7e153dbb90c5f1ad345e8a45a6c0e71d40f562ba7a3bd2c149771fcd06c46273d33b2716c1bad6d17a45e1c4b5ffe45c7bdc1347348c460152cacf51525a7044d17010a63fcff080eeaddc2b243563ba70d6df02e9877eb9dfd7d5e70c16a3564b8e4577e6094a60d625593a7f9ab9969e3648bac1a59f5cd2c0256f4812b2e7f4ecbadc4960e85bb6cc0a31e1eeda61aa4e16372787c0bc08aa8d029e99f8fc590a29a3e0791dfbe3d33408e54555d17d826364e340523d6adf3e510f18a625bb89b3b6b56be376dcb952bff4327e6711d6da451b2ddaa98ebfde70d53a887ee44af34e3af96fd9bb07f7acf8da0375f0b7916f6f6570e58b07c357d36980002b3ac22d57a45ed92680d621ebe47a6a5b92f643472ba35def9da7bab9de615a7f26df7a945ff783c80a6838a4d67980efee669cec38a59edc41db0e10a8193e8eeca620f644beb760f8e80e0711acc66ae4db191c1144d2e1a167b75e94d210b0eaaf646a3d2690691283dadc0ecf96b1c2da347a33d0fb26a64dfde9b57a7def4d3102a46f63e0a2d5973d729af584d566f5a094ec5b772e03b0adaf9600944954c182ca006818403793f8170276585325ebb7acb60cde7685179a151438e7e61d40f53d53211559cc5df4668694e2abfe1ba97edf9e98aad0627dd05e96edf7d75c26b01483a5f8ff3959c3e0e295e3709c803c719f6fd3626db8cdc5c6023c10a8ad1286300819d2ae454180e393c4b8e37e46e63a76d46e87ec2d756202b09d18f75b81380e63ba248956409c7ae7d132cad05ccc9ceb693913a590579e6fe877226623d2e74d8ec964f5af5016b01ff2825ba0c0a8de08f9c3d7eb48a42d9b59a0dc3db33e51adc495b7bc8600f76b59eb998cf14fb80868d181f3ba76142634be711b197a186d45fcc56d4e42349dbe99d58ea5819c6d5d183d2134b5af35127cb3e847c5bdfce258d09f802659c54e39dbf59738e8ad49c62300524dcdb0722b656ead1b9e9ada1cc8a9621fd6390052721c647000f800a67c903a6853d2a572e2f9560bedd30a806106186bebd216c7deeeb059cb8c33feb246d746f2fe771b0c39f6b868f7a40f35a5d0e662eaef734f1865f90fab4665af026d9345001d3ffca9b99ec74d4bbb01c08938d3181b394c958da09637d04cdd8cb871f02165bda32708bb4e3c33e2d0a59096d726ee56cb9f047ee3b19d28904abcf8981325c9c5f33d498d481a071582b343cc0ec785b39fec16d846d0d3a95ce29312af9095615a9cac5b4648aee378ed4ea6deae7e558089f3c11a5acd5d6455c14a186f0eb5b47e6075218dea51a2b931c4ce12e2ba18207d5bd8ec8343ed79a02d5ffdce562bd259ff357692af18698f24f0a5b6672f8a1a144f79dca013efb3e4a5528c5e916ef2212e3448b003b373e8b4d73d2630e6ccc5ad7d7b25f636bc3fba5064fdc8a050291cba24238247dc82003b34d2080097a8d55632f25c7ba4dbacb673a6d4769b391c54230ebcca70df4bb375dc9896d2d58464e47eb2709adaf2527bc75f1b833fd25d2c472eaa12a1347a59df33c0f8f9cab4fbcf04fe65bd01bd19c419f71388b7b7e2ab9b60b4a201bf60c44c73d78a87a06eb9a265cb97b39dd56a37aa8e4cc693ecb5ea5e48f97fbeb444b1a09afda6a86bd8d7359bb6de5a018f03bf7ea8ca56d20effee40388062eb93dd9681f06ea551bee23efa294128dbd640a86911a45698ff135dc9b7c9dd27ff5e03d88e5d33071725b852c3f8da765eeba16395ff4fc9ed5e023cf09e12be8524336a754c1243e1ba3647d591580a699dc38d436d4ec40ed32b3809c3e4f7e99b0c8373a536f99a4917c8bf02c81ad7a592011970c6d71a48398676dde6c6dbf5b62859e4575e195cc7dd8d8fb62da8fb7260af8ecd292f185afa7d0cad100563cd8da4453955fe00502501962ee649cdaa918edb5a62193617e4db77aaebb167bc72b2c793e225bbf78b75acb9eeedf6d12953eaaa404934f8ceb3c68966bc1f6f0a7fb289998693fcf4c65034dfadd64b166296f5fcd3c5038fc22fefac3ecbb715ec30ff1290d067274dbaa1c62af10a8389fc7985aa113d1e03df4faa6b4b0d70d724f7eb9d4a3ecb536d12d638d3b12424c179303ed240138541eaff6be80da7ed15bc8ba4cbb13127fc13bebac79cd0fb93fae97319a91d3e4728cfb1846cf4569c2be95bfba5b0dc75a4c877227cb5e4ea1dcdbf38eec07a84d4ef9d2298912ad183b37689199a1fa95f22a6d52bbdedb3282cea02d08d7333b9d236e419845d42b8b51cabc655063fca54f4e287b9f6d36bac86665e3be06431540b43d662d51bbf8e7e99540bc5f95d3324128e3b53051f8cbdfbda3b875c4065078ef7f1ea2f5c9373a6d203779b6dfacdd3931a9306645f790b0f3caf00b566fb1a32e9f07b671c24d835a7a7fe152c135597f0c61536d645c734c3f0b27a626c0263021d1ce8a5b0cf7bc41704569526c5fa65dd3efec23ded9cc8f9008adce99d025deb20c38b93c9295c75e2291e4a8a860703a90b8ff27a2949bc25a2b0f5ff623691c474f103d666e7e9b96ee77cbff0afc7574bbf2d1ffa129405d990c02e41e1b116f2f7664981732571b76e9d1887b03eb99beb570829eeedd82ccb133132287a139bd93e4770e3bff123b4778f0a4614b75754e944dbd61d920c4a03fee9903dd97496b5814d26ee5e73cf1ced3e2ebd9022c1e790cf3ec4bae427b49877ec558f61be267008c0fdf40eb2ca54b7eaf28ba94a63e7c7a78f570c83f1c0be17aeff3581ff9eda72483eaa5d3de56f82ac0c125a32aff94b50a0abf9a3e01a1a64977d80bd4f3b511dca931d9799e6a6872c1c6c39d0fb8d82bdef2237eb2b827a76b7291808fb4559e2f374f887e620723454385972074845c0003cfe00deaee977c60ce43cbea39074390a0606b6ca9e4a7422d0373590c8d165108558bbaa384151aa31d1f55bf8657bf06065997ed4b2a016eb433d561a648effb4fa6e14932e47c774e7c5ffa8481da0681123abf6cdada807ecbf0a3ddc953d6170fe8f4b1179f1d9c71bc7fcbb03434806e027655418946841384b0ae552cb02245fdd82cf9c977167fadaaf7a060e04f2a7df74a5c75c48c5a646c3c65a54c0a6cb623de4bfd3caa0ce001579ae674ae80444b0a6828cc2febdd2b012384048f2d420cf42733b7d8fb985d1660f4cbf03c7652154d43d8ad5be7f5b7eb7418b007857fdcc7d219177ce06b9c45cf72eb82dba25c8cac49cc9ef91687b28e456e42cafcc8db9f939888f6c76524ae4caf823259c6b2be474fb3fc3531c21a4f30f974890b433a6f876ac09698f81d1b581b957e7d9caec689fed4371d88e80a6ef73c5ba19158603685f71f478061014e03752440934d329cf651d77c47b1d0be624fd63e336d666e0fb5740805001294180087b93f6e93c833e84622e1802745a421b7b0342522894f8d18e383723320741428bb04ff4e130e8496ec901a07514c32485bf526e531e24b98228097118b14de6f27716d509d58b76fd407cff3a492b7bd0602c48fec76ca34221d46f2da789cc52afc3a81b0f49c214910325d36192a830d715f626c67fb7ef038b0c2d50278eeccdeafacfc3ff0dc0cbd84dfd925307845e0fbaa7f94ada088ea781a4021f507a2fe76c4de06f37c44e2b0d04d5c80db715d5fc94ed192d5ee6d5e9f95b877d6a179be6204a50fd69406dc2fd837a35273f87fefe9eaf52ee34bc86b39eb50dbf4bf5793d2d6f4b31aa952f50b41934a41dff2bac972204c6b56a3cc7dcab503c517a3246dde8484e81061385fd5bceae5c359b66ea0debf402bef9efc4f2840083fbbf6fb1e7c39b4643fbc041b92a78ec76cdbd0a726a833fea4714ec91ceff75a3330d092f6f67fec448e44e42aa3bfafe15815b776c6149bb46a247eb50ddc3ed7a2b74e36cdeb2398f113e315272476cc266a02d5cddf443c1218a9b16c369903c24606709b29eadc2401fda1de955d6c9ce0982a6d863c335bc0e2fb38bee1505300f24907bc70e14e0fa499d09b252a136f7c31c560a727038f3937a8cc51488f3d47ea847a28a3b5045204679bc34965261fd14e8ff2d806261955ac55198b8361bc372fa0d1499bcddbbc1b3deb05b2550519e96cc2632b7d4a743c3fc2eb5efeaecba993f3224cfdaff8737a433c3a21672d2ef380230c4d8e418d99d0da273a32228286308b9a89bcf040850e63ae848b993114f1bf5da5a56ee99188d2a9db70e695026e54284db0b02da4bb2ce1f5d09bea9460159cac80b3e08136bfc9a2de1217a95bf5adf72fe70dda97b276ddcd89e3fdd7abf0d5181cdb619365870a4fc6d2d791b59af4f014f467e71b59ad948667dc0e9b231a370da798f4f123bb85aad734973313ac60de368c37d6bae47549fb3ab725e0244888206870434be8845f63abdf84a876e825608022101490b2a5114312a0c444f4b31563443001e8bd60ccd4d1ba79573f42ea5f3935b9b189e3b279f0d0684190327b6bdc48102436077b94508072778ad32b629a08033ec871b5b287fa03774fa677ca6413b00c14c21685572505713a32eb255118ce10b65991cac0d025d02bb2add8e646664e680f0075b81cb9a4fcc61a46357fc14189127b25b1fd8325cb9f8360f6374b05465bd4cece228a8b31c4815b0100a081fd3adcd2e13e4e54b26a2e52b248b95e238c544b7c12b9a97b808053bc3384d2a3f853a305a59301f83dba93fdc5dd8f4f62e2116b5beb789b0de7661ca5de45152b95d29a2f2824dc90a8d6d3f0bd9b7fa97abe2e89f5b2fae1ec9c9ea973cf43a6c4084c0d51a79ebf73251e7a10dd45c17c40ba965f76607231888743fc2aea85021c839e638522de7ab0ba80129a8c4b6621ba2f95d06fff4fd079dbd8d96ef303176eb490cb7d40a6f770b7d53fe85d3ebb79877396f518696d43cc9c43bdbbbbec19ef3c3c53d4f3664799bceeafc9b830a3fce9bae4dabd97a8961d699c8027519ad585f2046550327907f7170ebc18eaf686a1926a5222ea67f8fba1141c4e74a53da61c9cc7b49150790f68505e7105f35ed715fe6672aec8813d62b8adc71c8d0dbe83ae759b4a7ae4c2bf4fcb42a1069c2c94faf68d7f25e847696f13418b83ddd47f6f5b9a44fb666c8ca6c1f8a968a4d7be1e15dc882dfaef549afb6c17dde0071524d6a4fb166b0183c1fd770f39bc328516642df96d403e6f590f1758a83be48addc092918000d5d9e34ca63b3b562fe5d2462225bb4224e730f8db4089d5f467f452e77c29f1de75f17fae00e08fde2aee3a7bc77eb6046f3c53e2be67bc2d67e9b2e3541072a471ea4b1d078a6efad49d71aacd98e838d9ac90d97a1146b702cf5c7fcaead469f11ab459cc6d254137da52e1e6d71dd029076afbb544d199d51d3e117377ad426190090f37e3e0d4f6390c1f1dd87cf4979390906f400c88abbbc494132b5fdef3e26edaa4f52aa0d63c9977ca7a597d23276d5aaab8f9b3a908440dcf478e0224e09031438b6b3c14b6c2411670699f4245979948c8687c171a66f734939f44158713c0d80640e7602c7f32c950f14b7f0922f34c290a79a30db17c9ce7cfbda8c4702a2764946d82fa519e7ce45106f4d89b8ec912bbadb50899f1ad8c08e29db8753b94fd81b30483ae278a4b79a59275b4606eb471d2131736d897c6c552f2d69593e6cb2b194620b2a900d6d870e6becb306d8fe9a9cf1a2fa0323a0b544d9c6bcca60bca2b85eb649b9d1d0766c6f42223fcd358fc47bbcb4824bdd0fc244ea8c2fb743a5f0c08ac9b230a96893a8b33d82394eae30f15bc0e01c563b0175a61fe1bbc3f4373d67767c7d10b6f79c4d66ccbff4961ceda5a01502ac95bfecd6eff2f9ff82a1b82fae33c7ac72d84a2a260b6060dacd89600222106019764f606df7fe3a6744b969fa4883fcc501aff911fbde280ca072a78271b214ac8eff53cb908bc7cd8c14198cb26433a392734d9d5c26cd1062a2c756c342c36dcf5959c3eedbc4bef507d9342d6b94842b719ac29a7a314a0d0309d3c8b573c265003143141de9956055d47cacae8f79d6950279b7d3e706eb8fb615000f6e43d7fec84aeecb7d4ff87cc232f21bb1768892b320f5250ff6e95e943cf8a200f9c7d552f09e5429415a1a4d8e938f4d8fc6d5227957352e6361195aaef5f3766d84c94be3f9093986feef753081a8249b7e3c5ef3d3da10417b7e2cee8af2d43bb01d2cf5244bc0273b2269d57743c819cd4ab131b089a216063d687925f3abbefa8acb60cb62747fe2a1aabdb708c28445d34ece36ee8fe093f006f5fe1aa3a0c408344176445e265b297a4ad9b8e48548c0e65f7ac8355fc0a21567c222a303314227097415828594f6b291787b3a3f5974c77b82989c9838f529443dc777cb75c9fad48bf80c0384b2cf1d147805f242f49e17b8591a0311b9091a6def6f7fc1ea238caddc4bf43669e3bbda4cfa532348551f87a3fa9870d5d7d1b15d5ae80499bc6bc1f22c51ec0f00932fa7a4adaaa412289964fe5c55484cf5737714ef0d40b8d7b838de48b35b1afd954d1f644497637ced0bbdf9ca1492a94a456227d4d6efc5c990479f6bc91cc58d2a57ae0c940c187e6fb76960aad915136d342d5a3cf73070d75f79e51514fa74fa2595a0524ae9ad50c2d9cc24de0a8026eba9140fb1bec1d46e9c4036715be00fb9632dec161e91dcaf50ea648ad92524b6e136ec6d30590e1019768a66e33b84f94dda6151da90cfa72b906888b6568a2647244ee0c155e5df0af39d205d4bcdffa6e324007af931fc57d27fdbfbacf1a8d472d6faa7ab316f33b694f51a96c3ee67fa6d5ae653f1e1c4b3d2132d662ba13c41a24d68f7c7ada480030bb828273009744ae02a7da62b298540813bfd6affdf774011e27c13c266ed499d4e6643593fd3985dd0acdf2a1f038e140c172aede4da581a0e8ae19a21a808d53d4c61aa1bf19f29aceaa86005e4377f2442398b0c8319dd390c48f69f64cfd4a6e29daff714a780c1834637299ee99bb458653c0056e8527379247040912cf25f4d5b0ad25fa4add6ea35c485ad281b8e4dab5254b8d169d1d2f6c0e90b83a1223ec23c482c44dac5e5aaec8d19096c633f1ee1ac0a867b4888d392664d8c7e02f1c3e0185c8626354e5fd51fbae9eda61a6b058f4ee5d24570ad5c8d6be78421d5b4ff9dfbb6912b89228f5be6b49ec56dc5cbf07efdf118013fbae20a06529aa11262ce5a7d527611012e2777a0c472d66ec8ec4166da6cd5377dd783ed069bc35a6b0b74b93d5b204d73bd24b00b39fb21ca95a15f8c5b87d599d9255f10cd916969ca1063514a7bda6d3156c08897642f520beeac82af46ad52018c456ada3786340d87624a6b7d701fad259b6f11a28280ed7d6e16373052d0dd3ea9c038429e70a02375952798a9ea3d047068f24f53d3ece4909cc91aa3e18cbc632c34b1e644f45571c7ff387dfe2d409d167eabcf5fce93af2fc712d7e3fa57e9864c10f58c0e1cc086ba8b4c68b5ad194d0b1837e9c8af684d8b60f0156ef4d72d6801e3aab2b98dd56ae8b258ff0daba70095ff674c45d46be90b693b9d19eee07222e7d891e5f27d6663885ca1df126e882a6c04b7e52d8dde07f33c8eab6c85cca97aa01ef95c074b204ba16a5d7fbaae902c5e17d30c1b14e3fd09cd9de553940aeb1550d3004c14b70750cddb00eae30eeca787495ac2cc8b839881a64ae2c693cabbebc6708a86e9ffd42e4c9dc922a35276fc49504c4e681f1608d8db6adb1ce0ffff7cf0c9ebcbb23b02517efc811d98bf9ed20e142e11db70350da71cded38b3613bcb4e13abcf823e7feaa0d801cd9d735790b2a27516fc05ad809bb1cc41f482c74dcdb39040d6f39b0e47d5230b64abe02eb8b73a5a62c391d924fb16bac7f973fcda0b742287235e4196f31853002483ff3a8d10dcc3bf0db1bc52ace0d73174e0e65120d320875338f33c0e1cf10ef00405aa75c600dadb24ccd90ea90dd357daaf23d633c8e80af2de35f80d69114769b43ba3903353203881b0b411d0cf708a8c46d5f1588fc46ac4e298b5d5f5f5a81c86517b14a92994ca9529d74c772a2dc0474fe79a2452557348c3013d79fc0816a27fceac41430d89bc3d26dae2305762fd3a4f6fe7bb54023a06fccb604d46e5f52ef2275badbf179c148dbfe60e55712f11bd7b74b81e74be1502d240dbb2244039e6ca965c3cd76295c475791d5b448468403d11887db93498331b7a67d70aa5d468a1b12987d92cc15783867832e26084dca20a725db8aa4aad1837378e71dcc407233354d7c93788fc5463f0868a57e744965680497ca3b094fa4f6477d698641f4f7b3c3e1302f07da4045155cb7a6c862a7c0fc2f0067e7d00329504a93b68aea0b1c6292d7e35a7b6b619030f1ca7d1ed63318ee44c5b8d2fd08d6660b8ce26fdbe0ed3ef3d8a1c164b54c3b8014bae17b874f7cb078556547d047ad5283c58719d9fe735b55058014090cc30049c2a602c250f29f1d300b03c9658b33bdef4d1025c7facd8025456aeb276407ddd3d8f1bbc84e558b08dc2909297c2fa51f8ca9d0ac9abdd991d12280b41c83ca5ae36194fc042beae6eb54646ed2c84ad80ee6b3325bca6c0f3ad811af29e830ff0b9ce1676a22f47634696d62b8be5c1c4adfa73b6574733fd0e7f86002b23519de27b96ba0a1c86ae495ca066d9eb9eba639b84a0a313f7d3f4ff8dff19b20b8ca2ebd8784201f194e9b6b2a10a9cfc5d5da2ece5d83462050438fa2fc599764b601de3aa0ea42b1f04f116e33f1a2388f1b50f98a8a7f2742d0772c3205ad2fa5e68d050fd0380947a74023b1ece24c1786b419d4dea359f299f84d48fbb71409d4de4e649c44f68d56667845ee24e3369ccb6615bc3960e864eb946692799233a9ef120cc784e0b37b52da5d5c49bdfc7e663ce9e2fdcc24918349800dbb012a2fca65fa42e11858fd4e35232beb4af5ed0be5862ca0c1358e82e6bc5be5936523ac0c3f3282c845e229b887071960a1179472570ead900285b668d196a74730f561195b0405152c1030695e9cdba45b3e25a943956065431adc8618517f12394a8485f00967e7e1c65e84c801830af42cb9f3b767710ad7f4eac0d531147ea12ff0b8410087b8bd24f17ff431c2ff79150e636447a3bcf4b3a1b33c7c30dafbdb26070e7927979c5220ea6131424ba4e6ce0499355311f3281344e4d7c87aa5cdd518424a1bd35919d780a53c7407a4987706480ac69639fbf5b3d4bc86a5f05a3c8c5f343a706e16c5bec8c9ffb0b54c7a43a9ef4b7e8f931a703d2a190b5defcb80f98760567b2be28c3c6e13a7cb5369850ed0aa091087e9db031aa625c3620a1484dd382bcf6f41311ee9fb4c2d46d5c7d6a27fbbae0bd3447888f7d635405a2b07f20f1693481627a50760d603a1946e410b396b6a25a501a3717f1dcf478904a1100fc1d467c53877b0a9e33ad0eef05147529a9d12024e27f93571a67ae9a61d3d143fa18fd1a0655c3fcd039bb92b36d81c3eebda9c1594e1011f94aa9a834755f4c5852872d9c543ef0dd1413112e43f4f33be355589c72912feeab99f6983f2e474d56b237f61fbb62ebfa91852c3cfb64c5fbd4f4d338ee76b94b2087678e3aee8b11cedbcad90c618b0c6fb3f4fa559b45c9f3f693d9c2453acfa7312b4921d3912b2456d0304f601c802e501bc57b4df9be91e2884a61e25333609b0b55189e066db609de9adce0c703eeae8176649d8ecfc1e9574e31fbd8146b8c8a10b2df511f9fbda947958af708648ec65e9ae1d8d7865af722884509cb1085e7cb8eb7841392aada3783d8196f528861bfbe671a49ba9d9c0b7649600515f859b6c055f323237aee7c34dda76d868b11139a1f377ce6131711d9d95f0c28c76cfc49ec29620204eaf780b0e0ad97eaf60366457b3132f7843460dfd00d1f323f639a01c21989230c728ad454b0703561121bc5760dbe17b0ceeb545d38afba9432d116c0f0330a3dbef416b2def67a8a4c28a87b021fadc1a0088a420f12af9f54288b249f387295de84897bcfb85963c2db3ba0b3cec49cf06c20d2bd9c892e6cd857cf52b229f1c7f95f470d038c2aeee134df674541caf1adc42f0f7ccc27c32b41e4440a122a8cd7eb36aaf1327ca912a175c26328e40fbc3345035d1e88b1dc2d6f21278a1b07f3968fdbbed8e722c5a790f6c7496a4c3bc19439346c21579cbe37e2c78551cda0668ca56898961981dfbd93ab62ea29f3a7a5084aaf6c6ed243dc1df61a41af17bb5ad182386ee155c44be7fefffaa24b34f5bd7e94283037674fdb82eeb77e7ad3fa77ef218d9f3242bd1335096e03c482d4b5a90e30fff21b7ae80fdad41656aedf54a70d0a37e5e9804a8a295c332b6c2b5f054fb348239eee69073f3b79e109bb7184c361c8224c2a19a2bce124e60c39dbb49f0e32440dd8eec658fdc4d33c3b3ea2e0d92355afadd58c8ad74e9eccd1fd8c86f5ce548340633a35f122d66246a6b59cd6df5b896033559b360ebafbbf7f54100cb8a192b20857dfbe2cb88938b295a755945e04d8674bd094190c65e47b730ec433690cb4bdcf2931d25ba1f1caa18c61eec0d2b578f08343137c524b7ceacda9dd796afd15bab5bed25bf8f2b79bf267a4592cdb9ed20628b4798a7c493a809048a8a84c47e665eb1c2fa45bfbd1f1039ef727ce59a056fc82cfc120edd0916ed6feeb6aa0fa5a9b411f91b86281bc46d622f973a0a4ed8c7da5ac8873efcef52c9afbef1dd51d3bd087cd33c1d36c5b979b1b9a80b93b7c6e133c0c0a40e9123cdd11343be816039e2c8a98c0d2d52887841780ef0448f4600051eca19f57939b0d17c2cf9f4ebaf86619bccfca5e6f688b7b0ff99eee6f51c9293a8e31d1632f7604fa95520195e1c7e180919632ae002999bac750fa0b29dcbc408bd69add0bdbbeb568fd4c3f86e7befcc7229f213e2cbbef83955425b0c2d1ea7dc3d7c01e38f7fe91a2f91b691e136a9c5423357ce6955b188274aba809908f11f911eb5c372df937b0ab169dff80e5f6dd18358b462ca327e802314a2770521f96731d39b7a83a47b02e02eadcf48b48c79b016bea122950f6a066c7458cf01ad4404c751178bb8f0ab61b7049418cb3fd5c13cc755b4670e5601f865000f105da0f19a9750b220e7df4b0301fce0c69f285549852e7ff21b43d20d88bcaebf15fe03478ca36e9c02600659a25bc1257d7b04d4632e02e098563640a1fbb4a1b5a5d992dd4928ac73b2009b73330067299127131711d5a89defadc984da7d96c090a9a8f53becd0e043ded5c168e58be59cb8fff032bedd6aede6ed1eb07438685447518691523a713c0c8cf2d4f8f7695162572198fc7e65e23a25f34f236b9939019a0d4c17f49a95317fbfda4a4210bcbdad58533b5beab91f7b80963fe76b7f06745fee929f673c55116d77d1e99336f1dcc5f6012d2ff1d9f82e3fab5cc2efab326f2ed9ef762fc1409f98d5e2b67c66814e3ed26a42d04f6019be4352007a6a59310c06bfb8af72ddcd512fc9df87a4f1cd2ab5ae5c4a135effbe6848774823881c6edd243942ae25aa185541eedfc7154d5fefb92a98f4ad7828004bfd4717c1b88c5f063f65ccd3770c6567d3980d40b911d087592416b2a2179d99cfaf0caac1ab9ef4ed2f0fa8375f26debcd48f91d2e4ff18e4ccdc83108154e07eddacc50d0d06054cc5ac270b799ae9aa8b629a48802cab19f5a005bc2f2c74d33c46db783f158e7ed55c5f2038a7df046088d3caeb3b30a50ffa2ac5d39cdb322da1f6d031759395ca14a2158dc3aff7b2c7c3b161ac4f366490ac27a2cd61ae33a6c23c1f670f2937b78379e895a1885da561d063ca475d76da5486af71698fcc0da05d9aada260ef3f678ca711e7dc5fd4b0250d2a15351b6e652043c99b7a35e4d7f48680c5c66c3cb2f7a101b0c535b1f517213aca3a419e07bb5e6c1f39d8d5a2d2e3d7d87f2fcc68a794487bc853662b8c9dbfed4c124e3a79a523e4dcb2d143947cc0b490b6e74970b78c29d7c19ff94f137bded6aae4c66fa269f2c213a4651eda46a7ea4f3cb27df225cf5eaa95fb8ec29da37e4b103a7a826e5b82ee5cc2661a7114b2455609e8a9b25f3be46b9b36f2ad5b0fb35cb1ce27edb6947bf03e7a6196b9756800e066f9bc4cbece4f56efab04ec9f86dd303ff2f7fa5ee0df98e30b3fb9104200a40da34075f0a38d87e61bc1b8f242aad66343f9bed4cff7a2d1028d58f48d1fa4502f036d3fe5f5d8cbf71b2b8c2c8ee1e15853434903216b118178692a640fe7f15f159ece94a4a88324e3e4171833061faeb95a838686ed46996d6f72ebdb16881dfddb244d59306480a9989f64762e1315a3ad4eaa83d0f040866fc29da09012c31c88f80b3fb864e6a5b46cebfc3c15a480217518a2c4f45c7d26ece0421d153d4c9ec26257f489023a68f9f11f31c89c9de025679815439212d105f391946e7275dde883f45bf337c35ccf239eca720344c4956f3a73580ed31525a9da82502a8a293bd07fd12cf7ddc97b47b8f428870270b30c2c65a6f35917669c4882bc0835a72a33b81a25ee84815f335262c4dc4d51b324d8a3a3c5ad6b89ac74566c63a6bb03dc6190894b84d0b0fae12f44e4fc0aefb1af33219161a810ba058db72db13d6bcedf3cbad019949a71767a5b2b6b2981e4b55edfd2fece59bf167c371fd9c4c20f355da414ddb98984f7a61c6f368f8dbdb78dbdf5971a0d679071c25234bb3bb9e408bdb1586a024e96416ecfe0d8951db42172779b6b86409b535e040d05f78e34b412ccbb4b2faf585f3f96f6a7cc5dce53e9093ad2b8ced1a6abd2638a17e5fd1938fb8f1878c1246bb5338c82b6b5bfb8049f8b7b7a8f00b4182faf465205bc73a8ef6e529183c8b64d592973f522305d74cd1bc691ac10138aa2932aee6efae00d439243e05a1626a55c1fff14259445fc7679c0fa3e4390692a135faa485596675accc363d1ae7eef436b4b1ab29911ccd86836f9180148b5224d6d13c151965e7f9f8ab14901f8311466fb965a5ca64d8fea043d297d166c9d68c907f46d4b645bbdde7eab4e1cbf63887ca295a8f60051232734fcef3b3d5703f7414fcd0a47431efaeb4bde138e0d358b10bf20e66f6f3d90924403aba35deababbc1d32f8d42fd0e2c6d3d6418777236e5e896375015bda51821cb6eb5c1472bf8ac9d8ec86dedee9fe2d73ef8763e5e2a63a714c82e12c4011f9912e1c0cb8b5bd7d9d2248acfed016b7d357ce15d0491b5808d8a0ad7763182b65a5a7179c463e7b75aa5c182ccdfa68114357d661badb72707b941c2b03cabd38890d7f586e316749048b0a2b6385a1b9948878d6071f284404d91ef759195ce1641fecb64986bbb4d1325be15df0b80560ffe5e5cace0d15ede2453b5c0988d369c131f2d4e8b5db23309c01a8726eddc2ecdc8233edd18923e69689aa32b197f9786f628709f896f5082878c8cf307467e74f291680c1653a190d3fa02715c50c7c8d7eae9400dd0a058151b27da5b4a0ea52c8dd2901fb8dc93e6cf18526dafb051eb391a0bcc4b652a976bca9bb84c23be90947a81c38bd1318cf7ea1c932a31307b4f701f665f39c0e410e6e64f3f8ebcaf6c9c5590c413180153134827d01c870c86085098f20b27c0dc8a9bbfb576e5009d7f20711fc2237ff49d790c2bf1667556990d05cf884b462b72dbfc78a982b48f2498d80832e8cd94b6fbc079df0b65d9a1c3c0f53ab77ed58db38a49548144718347cce148219052435b3bb09b20a3343c72b374bbd076759e6f7fd89064ab3c6ac57b2eef52b1c5ff1d21807bd084bd61b6db342dd532472ed0f9b89aa659c6ffb8c40163c3ddf3960ddb041a52ce950f7e44437045d339d071cac895426c7d23d3ddcb37ff27c06f2366c9da152f4daf789b0c37744f61cfa6395e286cfb61f40a9dc2640444945e4cdc089d9de2248ae67a7c4fdf42af51b977d57e8d6b4aa67a3be86f34b006e9f0e19456362329d0b108a07329e60b3938239765708fc2e3200a15d6b2df5cbf5a43898da8fc93ba2b48dd4274a842e4c986722381583c5f77b1a43ec717cb56ad3adf71abbadf19e6b8515f63edf20397f6e5926d44c468bf6b31efb68910b23457f14761a91dc624465612a50621a368431756ba2951acd7ea453390418a529bf653f36604f6c1261f82ff5f837c9c5efc8c40dcbf3f586a7a4da20e9bdf80a11b4012b3a3bbf1e5be7f65ac25e1f3a45181f48de85b1626bd37eb09304fd9dab7afb561abf9f53e01c25fae2565a4e66eec287a9dc71d0e26bf6c9b950ac5a5679266a0cac55ae885cc2cd2fb162c08fd26bcbd0e3a76f5eeb98210a20c2e49ffdfc552e6f5b46e200552d8b57adefb6284c3bcc8ef9cb71ca5149ccf73b8f7ddaddffc4d28639ac20f21419b814ace7c79cb0b0a7bd68eac73a15d7b6042fc32cf63e96f519c1d3abe029218da2853e18ca6a9b9e995afbea7ee239dc3cc198a3339680bc6a8eded451d3328436509aa0341c33ad887520757ac8ac944ee37666370ca70107a80840faa80a4dabd60ed7d9e80bbf5904c417d2609bee5a300494b7bddfc35f18d37a96d8eaa2afcf483934f587a4af65596c27a9d7fdccbe69172d6c284a98878e64777094d5ba9104267ab6ab6d3b6f47f045916de0af398b02100903e15342d1ae020ed31e895ca4d894c881dc618ef632163b52b136519e721ad1833ed5912c4f5706789cce45a777cb07de3ad16c1056632fc7f9961d379271449ff82ddc9489134057677a30d78ae2ae6d047a9195b2b7ea58d39a508dd4aa4e0941c0e356f57597d4cd5cc52331fa145d6c1b7f827cfe928fe1afd24b18c4adec310d889350fccf5af11f486f39df08cdaf3b66ebb7fa50d86f30a469a84462d23ba878654329694743dd6c75a76a91525cdd738dc26d79381283a0283d7dc094b514987057cba023d1458dc2d43755c5448520ab586db61a0562e4a4de543d21926ebfd0bbba2b44d62170aca46e11bc7e031cc5180491f0222d7292bac0510b9be3a33d3c20982e4e3111dc20daa46c491d242079ff064450ed220531260068d075bfa19ffd82b0b8731e30f3d8827548efb863de3382e2c465faeeed29066548c53f0db641e8912e2a91668c002648cf598a92eaf7a6d49b9f8e3dc55694b5e22fb52cf11bde01f43fbd8fd2a4d3b821c5472e52fab9f441ae49f8891139af649d22d76c987296742715d1954a81b1df0ebeafbbe631601765ea2db51fa60a53f1c12d0c163a833a54f250dd0b1a7ed0d94e39ba2f2c873401af6481e727ae65d9700df51286030a4e5dd19992879222942d157c42e8a06979f4641a846ab7030e9e473266f8dd3d4b1b8bf3435d2f5061b476e01854d16a306efb57ae04918f7ef678f2a89805bb006fe5539ac64d4704f5bcd4be65f9a7a570b34c81709d744de8b9a0c505b6246e0f11d93036495dcfed1f27af051aaffe69e0c28b25b6b51ef6d6766658b0aa0bc654823831e3f1a4f9e6fd790e296d1e9c66cfb5bad62d460052c7201b3292ffab9d4dd5be69de295713ae6f4a2b25158756e8b097cdd55e6c6925adda2bcf166e225f487f66d3510536c544cd21745111b1dac11c2ef316f0bf50dcd2ff0594b55d0100920c37850d33f75cec4800487de618bc22ab28e588791a57dabe34e87436a43e9fec606dd1033129a49e40e67f680fe2e5108f35fb38253cdd3cec628848dd9362c90c6334fe0cec9f3de9c8d7e70bdf272a171937daf52f94d252c6a2911a66dbaaa715b336b97d8f8449baad4db41436344080f55746c7e42b1352eee68c47c69aa36ddf7caec714ce95b6a41c244d27a796ad36a4e7bc5414b7a47743ad233a370fafa46dc212020164c12fa332f217d18587827070aad7adf28c70786e97026bb1864ddca153972c25a75d32f70828ea8aecd8b430f872146280c13b1b5e007467a5725f6b1d51b3025989ca9487d60c70b976b6c7061c74f5f16d0f914cb934e6b35fbb2874da989c1024fa6def3204fb5a1a0bf8d37cf8d683653b0aff64318682ea8f00f5ae34e90b3697da97441c76552c7adb4672af2ea5ba59c6e36acea7998bd53567363a77164a7ef29c62917c62460d9a53ae628d7f026c32f0180a767c904c4b7a0f02d3ca4a79b1b09291c61af158c5333b8b40e8887cb34354d5a1b1999690ef37989bff1c13c8811dfd747a4b2469b330a49e5f0c0223d62a9a878452de2fd49b177f42d778d1d9c2e4cbc04b4c1498a08768d43568197b42feb96f6589a97815ba2f5f51cb0a0a84409f0572eb0a47f2e6a897ff3f8a2cfa454da67f5f2c5a816d0136e7db1b0ccb4509c10fb1a29e93731c6fc0477d8b9afd677ca4de3b8ff6e668b28397ee03a32dcf9e76fb42118209c2973052e9fdcbd41812fef56f2768c3b212805a26b509d112d7fbef45a1e07407b93fe5b93e6e5d6e4b0e2ce71cb35dc615a22e598a208e493ee44961c886d687034b44aad67e1cd42fc4274134b926aeedbe6f9d9ced5a2a3c34532168c3546c032d91312680c2bffce46183e01ba7121ba835390f1a9eddd2e78f7c164942dce7c0d2e86ee093846613787618c3b2b6baccfa891957ce09fff28f666d2ea4a4321e3f6165f70b92c82449d3fa46364b32246133ac886b30f04918530da14418e2f1c7168b3baeeade5e06cb29d5a751800aaa7cf82a51d00e9640bc450e0bda6777382ff4feb1bab97f74fa10283c3e27367e522faed4ef4004a71d2f43f979066c5c5bae3406140ff2429b24fda0ed6f6a399de8bda3a1b338892140c539c510ec443b8d837c71f3b7934c5cf9f8bc4932c9febb6b8333ab50b288b43b04af8d1dad5451b6eca13ed77d47ea947f2e2a3fbc3f6dca8b162567e2d35b5b4a77e8b4855044cfacc7805d254f4bda2d0ad141339c011cd0413ec56b9947e8f6f51cd2490b42792fc220134849972df656c60175b4be248671f6258bbe75aae62d96c675085f21acada5b5204276b2d4853ffc3e4e08403719b218a45cc031aa7ba56496c149d645dd826fb205124abb0f1c433a37b5aa3ea63c3364398e5db3239a1b2540934d93b4db2ae274b4f8b75168766bce2e7172e3c4226d147fbcb626e721512e19ec9df0edce14cef953f3566271878e804cb220053e397a5aa1cf3f2e8e7d4948235eba2e6739fdddc3b65396db93f708330f96bb49058cc0e08255fc3315effcb599b9040026fff583f874850a4424ad2a035ef956603a7a1b1a42a43045efae7ec0d3cd5c0a48b8345a05394676f83b80a53f27c9e8b0639a6a044902adc1881bd1f6a796d57d0be28c9d04ea8be495f644aa7a3132fb33bd4c283b597636cf5a7f0c59329509db114f2c136813e6e3b0facd75ec7d27766b6e244067423e43b4290238ec884f8c8cdb37198567da27b17d693c02bdaba5ba612ab353723d889967b250c950e5ef5fb5c25a481959c305643490202ecb5e71417d0d5100e6f15d746dafa8d70655e383cc305744c9369ce38879272a22018aa5adfd6258a108c908b78ee6c3b4395123932c0fbec81411e0e12095e6a62987f172fd852e268749c5e1c3f2df4a6e9cc0bfb74b7e3a1153de016ce42db0cbc17abf2806ad1f2edc712fd42378a039bb92b58a39fd0262156985d6aa79190d8ec6f5cd34575e27f80a4a7670c5ecbaa3c6a8600ef69c96482b71acf0f87e1a0e2c186cd4b7019ae67737406c2089004797855473b6a5c0b43c5d2dd0765c2aefb10378fff7cc2ed4b917585af5b8198bf0ebed9d83d474daa06801f6da18e3adb960eedeca65d44bdfb8aacda8adf007391a6de9ead672df1c21adbdb0ae98c1f412270139af40637d886e1b4dc84ee25978ebf4bdbcf09b785c1be7cac474569a17e71ef656e7e163a35e1a465eaf866f0438de4a269d9f14d942f4a25d905fe5a8548c997a742a2f6513b1ba5a7b46f954dafa076d32dc0e7e5e3ced596ed074e809326822b92053dcc18c38978cdd1c0785452b729950539b31cca01cc16cef0d9111f58406516e1a58ecdd1e6c806bd12ee0ef498fb1e12f5364a7a8bc521c9894cfc7f06adaf2dceb8b855eeb39fa7d36ebb38ab0ca34be12a001638bd6e477a804a348e3c6f370e4807de8994d555718a400a71f003b2ee7523e0e8c6927d454bca252de31fd579c3bf581527cd636054ba0b9bacd796f81e8dfed62ef851741be2b4ec3b6a998f87b987cb85441314dacb69e9df287470f34cff860034be2892eeb05672bfffe8ede6b62866d8fb723524dfdde2d59be508f59c09c22e699911ca47dc6e6c375345638b25d3b816f9ff887463944e9a2b7525435af90e539ac56b0f41b0e2e423c0beeb70fe5d7536d673f77483f92ea3b48d0b930135d710245b1633ddf92dbbe562f8b4af411fb24d4cf90ba6454a53a018d06dfc23de1475f74b2dccd1d4f99884f488b49a96593db535006b4239237ed846177c63204adc14b35c48608fff87ebf51415c95baf0f2590c2bcdf3c4e1cd54f64b5c52bcc97c6b4bca35fd872cb75cae3594b0a457655898e54a5cfa58378beffe632e1fa0b8daf6dbd9d5285dcff81bc67d9336fcf902da286420dd264e7967099af2ae2cd77af6967f65fe5d453cd862ddeca4cd1defb7c9f7202cff1b7493001b5f92f34fcce57953da0de1b432f23198ad1b52905cd2f84ea61e85a5f5139c8737f744ee4a79afae29a82a2068a619ae72d62b7c0638c890233681c4b7c3ba81d1a67c7e06ba9a95d0f9abac4dbb20e336e3ac0ab6af8957364d9dd862352a834b759323daf3b08276dd74123efdc19abdfb81bb392edf2ab5f27ab2635ef4da77a74c3f06465a472141edb01152a75ab1060c6bc7f6a371549afc3a99c425e41897cfa00833a0519174f3502808de0dc9132cbd872a56c6af2a4e600061c952090629357db951bb2612f40c95cf4337474eab80ae6003ee63d1d6c356624116985fa24a49edfe5cd09f924f44efff95885b3b648f27191fa12171bd51a0771036d9ab8448b71107dc07ed78cffdb40d123daa7e3643675879e7c3ed1b94a5ef06397151472da9f65b4ba7a5749c47359a305632858e5777acf13c1d5ed5f7736c73f01f0b912a645a93022bd78dfe5c5a484829d3eac20268a07dc674687448247c47e0ed0cc2f4a53c93844c720f7d48a6ee9632dd3e8d649ffa5746ca47f32cf97a44cc68dc45021e9d4b730b503fa8a85288cc28cbcdb7a1bc3073007b25bc43187ff578dcb67a32fb78d61fe8ae665ed09b16e6f9972918f1c611c6812f14c27e346c3cf21b6f5a6410469f05cd255b83ddc7656ef5920e17f73e1748470b7abc18caf0c9a4c9cf2e842077ee987e8f542a680580f3af947d89e75c314b05dbfef001d41847b50e3a28d9bcbf914269a10ce4701f64ac05ee3d719c3915ee67d22a37dee69d59321a36e6ed8c9db3b609f928c427bda30f7ace4b73ff4213e4ceb7a30964f7490c99b151b0d14679c8126c4fd5bfd55b86bc9b686a7ef99c3b7239eb8efb189ed6b4463cc52f2fa4f48241a09ef1c16990a831a0a67863a7f4a3e98ece1a0a11f0899a56ec8544414cad688c0c309c77dce161aab9ec78a251a66c463e80eebddf2c4be02d19d4f25ad067d68a4534249f8ba1e75c32eaf4d69cddd2b1b65eac82c6a03426cf9b2ffd207303de92800acc4939fc8e361bc663f8a42bba173fca8aec04dd4fa764fe729753ea273b7674a1fd84ffb29acb7e4a61edc612c8ec70317ddc3a9adcd76c64db0151e3e0d9fd79c1eeacb2b03cfe177b05486d4125af2f91a82b80aa514e5cc4b70816f887b24a8c47780b293bbabc94a2e25f8004ca05d27fe6a8a1200c264d073ffa728e1c13c9c35f0c482616877b64c864393370c80a638131351948cdf4ed1f3793d60f0d1735a06d625367d83d9a24dc8ee2f2cc40df36aea5a4b2bc511b74ea61d816339744180a97d06e8b0054f162f7674f007495997d3f2e5026659b0d3e9b61093b1ce6dd810ad3b2145e672042292813a87af7fa79a7eb919ec8c345f85bb73f4612240b1b7c34220e4848aa83719d7bb198668f21b2ee475530f458a5e780bc6f54ee9551ffeebe30e8f591ec917bcaf68acc1dfb6ac0c31a127325869dec2469ae4018c0f231db1346cf0c8228fa183a77332cefe35b6e99a2cb0fb49a0889e10f4ab64c36e41128945068f9c6261b8d19423f4552bf21a8982cca13f39158045eba58fc6468913ecb018b837e293b023dd005b8539afbbc392d11b0947ef6e1aa23484f36075256a18e5ec4533f515bd297e8c1f97d853f813c4db3694d6cdfe52af658ad216f9e2b271a1276521e04fdb493ff4501b4c6ccdd06530c24fdf16eb73e642e06c7adc1b83af15defc7ab951deb792d2e112ffbd270439a703f22a804aac7107977f8cc93483811f775fc30cdece9ed8f858f56524bafc942c14a659f8d92cf7e56d45049751fc548d5f2a5eeb4518672b5f607a81c3f715cd303ebf460c6f244b3555c42c5a099282f3fdb0135b4427be7ddc086f9641261fbe227fc23384a3bb3bcee358fc62c18ae017ef86103e23d845c2be54cfca8a76e6ff8e26e237360c4cf405ce71b1660b548ca0aa22c91d7fab186cf65e04e348eac0e81be5fd588c048de80dce03f335a55c0f1dba3498ca2d1812510baaf6a82fa85d0335656d8df6cbea9c6d56c53cfefbad95435b11d1ed10a5551e38bc8de0595c406225bb1300109ac2a18b45f8228cf2035e589a37614e24f8761b0566db4f79c71608043afbc3fd7c98fa6f93dae533535408add91666d4d59580ae15164534d0a97c659dc9da1708a225f9df302fd11de406a3335b2a0fac16b9ae64b6d709fe76f6f360c0805f58a428b01d30bbd1ffea76a4f3b35fa3b4877a1d58165aedbc5fc1f1de79d0f7d9f4f49ce76260d825821aed6c8f6ccb6d95cb2053a1719bb4cf209446ba06a5f5fffb21c3785b8f104e9f06205f2c8c94f453a2afaaa7a1ca54007c1a37d57b40914085bfbe5146f3ec3ab0cda194918668dc7be1672785f41d4c863d24cb80506efb07cc72ffb17d61b3046c0c7a2d3d6da37dbeecec824102d1b4653b6df844146c2f9090814ddf22489b7d8d9f63306cfcad8fee814e69b28ead7417efd65aba50b63cd2835886e6a269de5395eca572a98ba5da40b180ee575eee768c54de9374433a8d62fc1f3fd84f2ded19e1cab1da4dbf66faea3fb7fbfcef4729bb7504257d7308e32cf2eb8db46464ab1002f551466a3ca6695a17ed550c45fc8e932878983a52f21eba7fc7869a413e6e601f563e33cca7e36a383ac3b2a8f6a10c0d2f1d5be689808b436139d06b5149e8023e6c2f1a42a1a6cd82a25a1eb44f7e263407264c9030bc2b2cf1ed10f0fd5b0100bfd5e9cedd75dd73b3e3d96920e3ea73c1ea87297e5ffb4b7fcdee136803c7e0f705190d49d8835584196aa8f90709f238f77507ad7f57073d8c8f3e6d02c5f591e8374688109ea5b50c6e2feebc5f5a210e71952b39b7ace9f9447ae2a042a1a087029718046e7f0bb7d09177983cdcb1eb3f5c09ee6bac4aa6cee3c4b40c3012f513b815fb0f4b733822ab3668aa4dda6b3f603ebad87d4c9abf506b32b7f7b9f21a1182923b4b73d4f0873a6de67efe80b4e134a5125e77cd1619b78196a95fc37866cb5842921974ed3f2117710d69ce447bc593ffa420f252a2f7b727f0653c0d4d6159a43d6e1087bff1397d308bd90de632c90a2cbcceb3398a21308be150199e19ca10a72b12e6c26f39971034b8c7ddf7f9dc8779ba3f309e30f7019699ab62eb12b8fa31c78611f923d06a2d35fe2c85c7a59c41fbd966a78a8ed7d7a4943c4f166cd329271817f9690623ad68e6b1d17a040820890b204ae293e6bd2817ec158c36718d44895bce5ba92e7d5dff8f27714d8f173dcc09ed28ca31a093cd327175a4dc4ba82707914119cca8d987d1baa3e0477c400eda3180756058322f88811d2b0a584fdeb24928b2cd58590fc36b49e92a0c0d8a32c659ad2d8163a4350454272d7dfe04529224e74e6392607e1942448c6bb38fbf7ecc91f1016a93c51cb0981ee8283ef5027ba4732a684b83928365ec0402379f12f1a8f3e8387ea10fb0cd3dffd02eac456eb1ed0bed707beafcf89d70b2c87630555f13db2ed104d698d0aad61280465fd04dd5f98372df147d9e6716ddacbe25702c2a96fc68604d2d8ed84aa8f438c9366e9d35324514495af1252a55a56ddf04b920689ca846c44cf73d5e44c68c583563f07fd950bd494a460af3a95fe75cf7f25aa7929e073adf30015aa49f260da29e911c327353d5f1e481577dd0908d192e4525ef20903387cb14d6b5fa02e1a2e9f59c9aaa283d436148c9ba894f6f7c874b538afc081670ab319c61e6dcf55656c25d71f031eaa40e92a4d555c58997058b1d30c11d3a29028e732203f66b17cda828045b59a1d3d4c5187d2ba4569b045a720c6b959054b1d74e704080993dcef13987ccb9837960919cf028f403fabba94403e58cc5eb8d0672767fed6a4f9c11a066197e545f13e0f63cb2531a24fc902e80883a34fa72ecd13fd5318093498bfa22cb45557df6a7eea83375a50d879933eefff9d8a8539c61c24035ad449496bdea4179edd9dfc34bb3f9d707a6b97e2aab1575045996b0badaffebc1a4ee8223183005d8fd5a99d465160564eba705d70e70162d3c83dc6dc221e3df547c71cb1f72e1c4df1140dd8db34956eb8318c384273866e9dc2b6f261d73ff04dd0eda09496ef45cc2d74e6d90affcddaf3735af8c18376303f8454a920a2a4e678218237c405fd50356d6e2c8b6ac0f18b616a4a263e28aef7a66c904003f4a735381f40347e680a9385c214535e75762031c24f622e2d56d15d4968ccb5fb6735205661b5c6b36d2db048a3fc4ebce3328cb82279a921f804b7130b848c268a6a631d7521699712d5f20564acd05c3d02d08340b2ade76da9e11c041f130042c994c97de2119ebaeb427e0fe8e6037a76204fc1718c6e3dcb2195ccb94b8524859740b59eab2fc9b231413a32682cedf0b860eaace162591d5742b2b95340aece2358278f3462af99b65185bd8f20c21e41d00cf3e06564a8b8105b7bfd2cb0bde4a422001994439f49fda9b226b3263770fc0b60695928b3b50ebfb87cfa9cf26539f5b33c64396b35712ff76d805742e9bba3f0e3ce3de7fd1023cdad5bdc84e686e7741617c77b415a4774b47027edcb97b9b7a98ffe181265dac09f5ea95a3dcc2492ccd9edc287f852df790b856fe64e509d777c0b408403c08cee935aff9995fc63316bdf0721eae352ca2f5a2040767035acb37496e46c1968dee0b7e8c7e4fcd29817a1146613f13e8bf0041a11a026d9903068f6eb526d4f7a58d1e3554ce7acf6b0ff7d3c5bd4d79a53fbfe937df8224c7e0850df35ad2abf348e6c6974cb56499da03d4b0aa17dd679e5c108878e5b16cbb9cf182312689b92b03f51abd7b4ce58008935cc2a1c184c3417e5adcaf8541975ade9275771f2d2ef760261f14f16a8d006ea195af607e6023031c80d2129234f32e2faaac06035a69dadbe12a128c251660d83c295b2066f5eac87db9010944960fff2adf222848230729641b3bd1d6652905b6cfff9521e531acc4c971f0389a3498f865f86d3f338c26198f6f94f00d2b82138100ee42d46c7ef9d645898583eab384fb249c80aea717a7798dab6c13de41fc46eff5b37956b70395ca608171d619d67b8493bc02af92ece183a6349c23a62aaccfc40324c9b0854bc938d6538e25dbb74eaeef87f224e696d1819ee470ba89b353a22564963dc98b3663276122c517abca38fa63dd1df8e2d4c366980e2ed915b5f7d9943e3643d52075a21cd2a62a16e5047641c241c5041554cc18ee766c0656b24f08e23c562ec2b1063cf6949a3231fbd5e13d5d7821541cf4a3891f6259e788d455a8bb96c1a14aa000d40f178bac12262d1c8c63e21b20957f3f43bed3c4d119e66f489ef9c0191487e068cb70967a453ac56323537a0464d06f67ffdc3e7e324a6a7e3fe8585b36f30b2b4d6563fbd7998f52955c40e5ca95aafc5206dec3952986bc76d969c358497eda3b6490d17efd5688292b6ec09fb3938abdebb9021e5c1aa898d4059357337c2e83791d9a9e701e9dd0452cff2e6d0f311161dc6c0beb83516b8d3ea896eb43d95036297114b59b6512410856d4ecd6ab9d9539944e2b6ece089dc178fddba6276ae61630dd2772fd1a7612bcdadb114aa74cdd72229909291581ac2d6bde6e49832f9132f564271dad688d212f65bbb7fb24cd8487d976c7a1d4dccff5db8a19651ccbe7587f630c28ff73acfacd994db903ceda461809520570fa071e7e2d92b2730dff041b942b025360a1e755c0289b88abc4113fdef89aede7fac6951eeb554ba92c7c0ec739955fd17cb49f52b91d11020379b542d2724e1da683797d6065f83bc29fd3b034dd82adb86d68a650c858b6f5715f444267a2b95257d5e986e384f1675217522ee0372197a7aa2fec6c8a06f49637bb83c9dd13c1f1273349764c828a9c2fe58d4c05b66a9adec24d632fd0595aff2337557f5c017ade3693f8f63127775ba1f637e4446f3eb84b595bd3a0cbbd2d9e51f4b5c9b5eafb7763821d56a1508d17d5e0a94c4e00e435887c26d6774e3dd7015959276b81aa4bc9ca1016e91b8f871a085d3910769958e619b382bb146c80419fc06e7e337595a28cfb785de0b1bdef58789793227cfd36878ac807e8e8827f5fc6b724617751bff9b5aad5b387bd7b64ec74b36c856c00adf063e3617c1db9e59c95e077bd408c955423b085d55f0f429a049e0ea67e4511403e23f233c78ada90f38c3941c83456e2465a0b186ecd7a305fc6fd5c7f7f271648d41bf7c7be9c4b6ea3320b0754b1a93481f9f2f465bd5640d2484758fd134a5a9489bb543f460a7b1e18fa2b9fbea0d105c9274e168f324c96ce8ac1c85bc9be9526addb1929405ea011b16649ca2540a515eacba7a3ed043a4970ecdfe893be2138285f4a0a1457bc9d27ec9c8b0f6d188527c32ce23aa18a795c153acc59f370c38fdfe5766840b7b658d5853a9c45d53697f59a4b44329c02764c29d95e6f310c0bec471f4fe59a0d4105a9377dcec501707db31aee893cadc26c36dc0d9dd7c925f291bf71a3a0d9c61dfe71fb4cded79321921b651c7da720938ee88cea2acbcf5e9c3af9cf7cb7789e18768f3c7fa62e7187798e7efabf70d386f3adb8c96e728b2e06f1f1bf5e3d4eb705f4d38d9921905ad5ca252672fda7ca1d978e59ce072ef89418b65b9b4eced66d4905d0fedf3212c7a44fa3506ab9a0c9fe118eb8681258057ad2e6ef9d2acc938085d701e2b7d7d37df43bd142763ab2d2193ae14880ebc5c9995027dcba683a490d2644f9eeae381dff98361318628c4d60cc1f6726f1baf282bcf564435a79ffeb33bf7ae12ac4d4fbddfc3c6491283a1959346eae40c94a1058adf79a3143a5ebda9e31044edfc8d7e90f99218242c71df2fc0d6ecb16376d76571e443c76b84b123d9e6651886e798c571a2456c924bfd0fdc33bef3fe49145fae4863df5a8c63b7c1e16fb1021b6c7f825fde19adfa11af57770143c85a07ae1788a5b812a72a068b9cb4d76f6680a3046b37e8dbbb88ed95c50510be6ac6ddcb76fcbe702384b70fb43b73e7b863268fea95df2f74b6d16e91feff07673b0d50ea7231623db1525f2b68bc1c390531e9ad611ea85241b34d785e3969ba96ad7c5d0ce0a334551081137684ee1c10ef41f3eeb946598178ffff893c0fcf6c34c4a1ae63bc51182c5fb982074e1d60f1c09e7112d8822e028fd9c824358ab9d56ed8d08ce0bdc42b8e976e9f9df0889281a8673a730362cb3e57fa4729de4f2f69c3adf06449e7ac7dfd1bf57e7f2a1472d39d176519eff666b74313a0e258c509d159dd47e7208ad5dac1f9f84458f8a1d7d59e710fd6b2f7fe7240709aa16264516b55bf3334fa221fb7cd75517ecb53f3d32a4275511de6353add61e779c0f1fd978d0e546429e6f1eeb7ba17491419f9cd23127b463517d6e1fc26c01022b2aa1d9c2b840734f4ef0e7ba08428f1f2f476fbf45d235d12b41e17df35e4d60f8e9359fcd4cbe6ecb3cf92925cfea80ef2ae0d53905b561c9fad832733196810a99bc66c3ecb2fb6c6cbd3b531b91bbdd97c6822bf2db0b59dc86c68c443f05ef40d749f86b357f595f3f0f3aff1175deb79a9a78eec7a4096488dadf3262cb65c6edc064a51b8a90100e4bf18ab6f6121ca29bed0d11aa434019a03320b0358bbec5fa1e91f84e9a6c762740aafc6c11c234a4db0cb8a7f0d4949daf1010aab9a205699e51848835d4e4840991945136b4f59e59369c44e0a6c39e53dba7046f7dd6af4648714cc3ff2f71c86e769972bad7c3050554cec38ca54148dd39aa6efd46ddba735eb5f854189410fcf916226e298c05b66c688c548a89ed99ea7a01da6f705e3c7d5588b5f418f23381b490fa226f058fe327828926f6e02b1af1802c3f1bbd93782e8769d5a88cea03867dc1d18d313857459ffceeb8f132ebce19382b9d70a2e2e0ed75f2f5feb92634397ac6f6a391f165ed5632f096beb8fb1e63f0b0cf5c9cd1948e492d58d05be20dbb4a2d7f6cbe2d32f3874672d6671cc3317bb347ef9c8ccde34d11a21f62735f4edc54d79c8ecdf17db4772fd475ae995be3815148b664d23ac1e4bad074f4546787a53eff1e948c1f0595e8e0544a85839693a2b6a3f024dc5d835cbb56f612551ffd7c3908ccbf47538fa98c347bf93d8742e574cf9fc9ce07b4fc4ae3dd5400d64dd84a091884d7aa74164e00f14bed56dbd0945e30fc39c3ef8009a30422fe740fc2ed197c4330e1a1d9ae3f1427c4cd70fea06ff0940e56e7e7a7a75c2f3cd8200701ca9570934732f0087b87c5657061aa1caf5dcf7d22fdbc05560ba1c6cca8329138474ddb712a10d2228fa10dc65bd62b60e244c3c7a6034daefb42d61a814eb44f8bc4d0908eee939bd4bcd828586c1c09fb0d147967c808a138ef8d545b1caa50b42c2fe3af71311fd1cb82df79d70d063919b15d7e01286c8a94d9f88089a8203d2ac386f9bfed4d0ad770dcaa6c2f367f4a5e082c87f76671bb91b9e6c3b8530d02e4a0a64f2efa2f7c8893d1e27f2226b7c40176979600369a24ac2fbe309298aa82bf3556d6a7ec0aeed11ad913419f3a3fdfee73c4b54814083a8a615ea40a6c43be26d35155767245fabfb37418fcc505a951a6d048dd0425aab2e52b8a7172bac1e3c22a2ee88816d3fdd14386fa699dbf6f1c9621c3135a85769b108c0d144cf6e1da0ba76f62a4d41df116cccbc1e441c95d89f98c3e7aaaf5658d4fc232bd4ba9b8518c7bed9f64c8dc2e599c845d47147eaedcf2ef2f8970d5db08d8805c7dc2603312603575d8b0193fc5f3cb48a57536eff12f18cd0f296778f63d8114f6b9c558b61757ac0dcfbe06296b55d7c0a926c3368bf569bb01c5c56b280d351e68b0a9a0d8b175b31e0c305c5c146d5c9aa64e6c47d04c1b3ee9bcc5c847a41e8c317d96b2ca6e7029306fc65422373984f6662d431fb5d7baf9717f5919806b00162c732e64d481efcec19ce299d1c9de4740634e3324b89c75f54dbbd6964bbd6fae2cc47d3239c1d41359601b089e4a0ba67c9c490d935580c072f220558ba6dc5643a697c0e9ead9244b603ec94022405b3fbc5d11f4ccb9f1bb7b006a27fcf3f19ad3f5ce3fc16bad939878d08e9c93a01291dfa59c1db39527eb9b4875a4cc9790d0dafd7ca3b61054cbf7eed63cdfb384f7198c4f07486fa40ededc43fa66b575d8939cdc35b3a5f0662e2bdf748f4783ff4793b4b801532dbd9f191a1995bfd29421ea7a1d012206a170e7e18d886ab364d3a1f157bd2b0f39da1dd776dec4b0a629f5780461ab34fccebdb89102582433abf62fae1d3fd080762b589367b93a57e375564e47275b3c6b344c3d8df48db8ea596e77abe3e11be6bc11dd48b3556632be97d1147cc262749bc7982eea446856a490c7cd4d0933bf7d6c3bd762f373d246571fc64cdf3888870f6545cb10177006839d66e06e046e92020a343889c2aae22596f7ab95815b7b28bac489d60d987e3be0f73f05513e6937fae8f0085aa1857ced0f71706877bfda5c5bd1dd3296e134f994be498b817af82462f42bf300d92553fbf75af0c6a66cb97061a741bfe4af056b4a69b63e131cc191548d895e939348889e22015d861eb1ec6c85b42ea1d907eab4364a239dba6dafdf63b0c5b491e935e1a4a19d1bd012e5c97f9a97b53aea60fb71e67c7e37da562ebf707d0fb0096230a1192af772d16f66a25abf4d8ad765b9efe01685a6e5370c9f34eea6ec28ba25b3eda4fe359e6881783f8a46e45c974ec447c4f2c8fead94bf9f95f35bc81e9c633b5f44a4ce6b48864338bf4cfcc6542aebc7c9ccf2eac80248343c95965113edfcdf241914193894d7402b361f042a13752376f7546f17ff188dd2bfc8caa07197fabb4adb9a8247137fbf720b13fcb4db89281ea804991f1c3f44d057347203c063f28ccdba0afdd23019a6bfa30a629b93ff9de755da764542306df7fca655ac293ec44a6eba23adcf1f580d7c22370ca85547b86f20d9ea628439335aab7bfce3f5ac77393d6092ecaa74d656945661475e38eb655bb87ad9ee081ce0641dd2c7ce27a7e213c97d3c88d0f0f1ba62da81b7479a9a400d031c9ed7ce10284647422977ca54190ec77e9158414626802c36a7c52ef059f47c79ea5d0bff3595a7547259004c5fc3c9680835b8d903dd9feaaadf25fd90e80fdbe5c9edd5adbaa333cf8f01353fb7cc1523723a233ae40f6aeddefb89fd92614c984cac7f4502cc17c3a89598137a0968ea495b85ba4ff4de03befa69f42507ad8eec988ad06b07fc3c0c8f9da4de4eb0002ad3c09363d8bd7c445c42429e428f205a00e6f49cc39b9613efa25108bfc6bcf610cfe00209ce418f9e2918f0bbd87030eb1a1f966336f63f3c99b570dab47b6499c2270426d77a31fb6b46343fdc7385e14a573189aa7fe9638a40bb3ce0bd7fd8417fd0a3616f9d91a17a728ae11d221986e6786e9feddd4c147a1089b4375c90f04715a84b4fe2f45fcf17fc96c2ec5bd369b00ef39f96f053c14795117e6b3463138956ed1dfe2f9fb7267eb6b0ea8adc4a0ef196db7637e5342c92280b2a75001c63292238f65b3debebdfaf306e35704fc428daa798c2ee7d21b825870c471865d4fac26161b1de32204c5666a8fbf649b6f07178c55a9a07c2f37ff23f0e63ff8e1ddf1118b8d41d58dac6b1a93d67ec247a8781aeceda0541d6cfb072fb0d40fbf23ba7ccc880a129ab49ead6540dec1f54b46d5cffd708d161dc4907048e7e66a904c8807da5db227e1ccaf4c4e14e0cd2535e489f6a84e3afccc0ee95d6eea8614475f638bc9b7984689add323cedc3c81f27bda6632005c1f59c5cd06d3d91c428315520f4a599ae18953d68f85368ca468984a1e8624f259d03f42a20894e47ddf230e15989009f2467d7ea3da4c8bcd9a1fcda61cd1df859a266eea1d0f1245069f53df4ca17b1d984acee69afb2b11cfa3a8d29f1f74d81381fdbac3dc0957aae924f2ee695cea079896e3e5768ced5604be036b85222ba0a975931394a89fa8b585a49608dcfd5e06a76d7d301ae381cc048cb09d36b20201615d25a5d03769951575db093e929da3fb03cc44d8dd0001b725e0f9f04c3af1859816037e9e9324ee7d0caa0aee59a1cfe13416074035f4bb8102cec358ebd78f54bb601370c34dbe32a2c0a6579a2f8816f7c59129601ca33aac05d1e3791659f2b979beaa30eec0477beec9bc64a3db7f2e0fb370fd326a09ad7582acbce525b05e623b73d7cb8a3f0e2b4b716494ad29097d0f3468085dd00f01ca47584b4b6b68bd7d9b0d7d4438d56f9e26b379d1989858f76cabdb65e0147a54f265744a82baed6be6bcf363749007f4a32bb984c138459c12a6bb6d5f271e207b7021bb2869d7ee18ede10ef9ff58c9676ed14792094693006d6bd30df603e4b3da1cd87bb203e1bf7232b878c961d1318d62cfa6fd09101492d0e4ffa6e1df78b51ff00fd7f064ce4cf90749b42a01ca89451faae5e514671b3ec7c029142dd77a0aab57a5b1bb3b7719b485244c82c21b9c77927961a1fd3a9b24293ced2613016675ee69a55b4b9e50d595933c3381853763f6d085035193e26e64a6205447efca07ffab547a7a7e6b6a1d8cf924344e7c76faf90fbb12da72c1a419469729a672583e38760e59dc46d17269f1a259037339bd4b2937f75fd6a05959e876b7786c9c77c69bc904f8ea11d3b9473f68ce31a6c9316a1f25d8575a5f514aa95352e15197472879c2781ce11249260d7c66a018cce86cf8b66c4a90b319ab30853f75e35aa5a101405f26efcf4612bc63e534a81d3e6b09c398a61834db99f76215333528b9a948bfe217eb41fd0063a7408df30cdb4a76b3562811652437b31bffd71ba65d79752b367818c85fcf2a4d6e77433af6f7df3400b783f0ecdfe7c752ec5de72bc45ff9490894af19b137b8f23475614a5b96e9179e9ab1f07f665254d6c7f2595e754728675a34de71286963e7e9bb7800904dc92dfaf2acf4815c7fe84c2797584a0508860b411e369a0115d27b10ce896f4afec13c3e55bba4f6061233b7fbd65404e8bb00b44dbe4551fee05bac00a6dcb96e271a5bcf2fa05625a3e05447819d9312fe91b0cbf011eaf34c83642e1bca6a9f50bcaf74f19fc5048f26cf8c46a89d96ea28f2314cabfca59e51332c82ba4dda3eb6e605cb79c0cdfb0698b65f55f08ba2015dd1dd90018955ce34db06b90e7a87199e0df62bda791ced12754472f291a0129540564fc274107ee8274f01ed450c9e97803501636d13d5b64b3826ebdf2f9d97432e63b25d792d29c0ed991e9810e7298b6583393b8b82508194a0153a380b2610c25d08d19e4a0ef0ec24ee6ffa44a0f4d688a42ed401f0911815d5aa32062ac087a59daf51b2ec1f35f219224fec555598c5a1ccca7c26a4988387ab715718d7a688e22b66081dffd78ecd7ac5bfca83b8d2207afa317a92fcf442eca47ec7013fb9f06d2236e46b7c794f16e85ed617b30c78ffc9e25367baf5d652f17a488308e906eb9593ddfb5c9f9e9e326fa29b54de8034f565d2413ff15ed27b120f32ec7ab6f4a5456103040afc5849ef77924e86bda882981d66b80f0f6241978ed364bd975d82f599f13eea7412816162b4c505b6771a001917183962c5b01004247eeec687fe7e1ab21bf423f142720e54f1494b1805f83aa8e3f25fc610a0591764f463746f916610af4da1381424f701bc2da7e4e38a64ae2fb4de6a0565873b5dbdcfc36992eb4e3d26c8845721ecf8f69b8a0dbd939fe39c9713727deda6a26e036635b3c30d3da6e1bdaae94271986fbc98fc1fcf8d7eb8cfaa741f5bd4566004f497b6bf52189a211d72884703555991b40e0dfc1840def345e14698633a30957d0368c368aa2819c7daee5463b96a62c6b00220ef1538e1ff8edd991ec9b9f9809c4cecad25a0a7d57d85216db5970ee4b264db1338c49a56c231b85b2a5a6808141c57e5df96873f16e27440595df6ac71a8ded5aa3f6a7c9d7457c913c9fb7122f93d7f33b850b899be84c10a049ff143fdfb79cc79494ccf6bcd2dc288a3279d165b55415a677cc365f04508cd848e98108ba1e24c2f04065c718c8ae5cdf19e23f2e66f44e80c61bed1e6d8eb492b7e307189a13d4934d45d2cd93bfeb29407886349f26dc1ae0ce2e93321ab201251bdefa439de47580c181c310f32471196bd20bd27d279a26d34c1e3437a5a857a32f365b03b3dac45b8f1275181ea1e0af79dfa35946e5b3a2fc6be8a668440ef33b3dae661382e7fe89257ca79017fcdfaa9a664c5e34f2f6d24b76a6f8a5b64d8dd576ceaabae7daef2d41ef78cd251dfdc185e22b2934daddc272aa5d90bf8e2fda54656487be7fc969677563c62063741dc362e728e1b888b005ae0eac2c9ea90b1e1fad2b8f0a47b74eb84d0d98f5bbcccce297d36cbbdc1e6d9cadf8b16e9777de47d125a59d71581a156eed313b0b6aa52c353c6df6470b02bb977d1d4ac004d1c8804a1ad318434be6dcf04d20efb726a9b0ab309d5dd0d7b21b8cfde720ef3404153a89d447fa1889ec57f6bb08b94b28e42893e79bbd8e60980cd53aa6dfaa21e0548091b515f25d03e2ee1e36e6a766445686ca37664e664904336a18ff8496965feca57b58664ef3e4c8d385e840b9e8e9121bab684a45620bca1eaf3898bf09bfa2d3d8da6cd4d77b3780057f33d046b78688133c3bcaffc9f9958137074a5b62fb8eedd65dde00c78353c7dcc94bec9f075acdaf6f418bd14ffacc5bd783288ec9c22992ad11f968c0a8fafec5aaa097f802f1ec7b3d310f25da170568c80bcdbe825977c3c04c5717580caeaa592e2383ccef502dc643e3ed14448993e9834ec7f9b17bd6ca20b9c0f630cdacc4f3062c1e3a97355dcbe9e161c0eac7f5b601c1e435fd349f58d4a546b1873a25ad4cc07ee3aac778636b8bbcbb242eb86a66e45633e446adbfcf727c6f93bd987b1aaac31693fb0827122c89408cbd3f367f294534aba6fd564bf590d47959f2a243f3acd5eebf6e43f93bd0d27d1c92bfe9ea4c9918afcd8890dc94d752b235c7b1181bc692f9d284c8678efbaa8ba0418ce9f1ae50774bbee3ca6b03a593fb8cdc427c323203f92d4fd294f311f162e13b7c06bdf8b9e8b6b10e4bd762fbb6083671b5a9c5bc3c811de328320a2bdd7129a0bfce1cbc768f5081a301844ff7ca6c26795ca526ab18009422ce1e90b39e6156d935a63db4f423de4349e2e3a26beb7e3c4595dd199b391e054ba5edb76f89adba59c38d06dc9f9b538771f9306145f3e5e54d4c34207cbaa948f3647a8bdc16802b9ad034257defd847c796f4e5dea83a2cd02a78d618ec02ba42ae1f1846ee7e955784c8ab075210994a9333632e99e5fa57238539cda96abb09fb5ab025ea608d5b885b9c83aaabfb5bdbfd936647e2af0e7a66f2f85e8b8ad7bbda6ae2b4749e38ed27858eaf9be2a831ebfb4da815e7ef251d69ff22f586f96c978bd51d32322a9ac2af5388ee6a5c2f3e5d1b7a333f226bfce170dcb97036ab7c561ecb842e4c25efd921de95a1cf38f5666889afa386bcb8c6835fe3adda64be64af3bd838cb34fd9d05f3f53985a8bf0717f7c1f5bbf0c227561b7ad2c7eaee4b7017bc14b64eecf8c4c73049bb4fdafad1d74843702c0984e7ecf992a2aaf82c1121438fc32292f3d196f65aee1bc8701a8d1f19647f9490857f72c29d0b6698fe31d97872871479cd2022f47ce041a2297ee94ad661c0a229203fd1e28d1479504c5fc88adfad95de8909efcbd12b3bc5a6073c433ed631ec5d328ccbd6a1571b3d7f0472937e6e543740e15f65e236eb4c810ba4a00781a961dbc6ed796654eb95302ae4f24fd70d11c09e516c1611ff0b197840b5b0efe9c8610a239ed379e5d9eacabe1dd86234b8e61cca7e48264460f623687e8b7f1c9b772603226d4081c10857dd165171c935a3319d12e13bd7289df344cfd1bf11b320e3cdd59ce747b4c6ee512341ca5977948b0dfa366fde5781811200b17f6b675f308cf3af76baaabd6bb2cc030b650ed0c01b9ef96a54a74f11ce9eadb305d2586bc25148536bd6a083158ab56e2a078319b9016cf8d26aca47605b28d4f374031bfef4d1e4eec3c33b4d164827eef4b23b5af156682a5ca4858b96d996b260ef8ff52fe44e1c3a4b2e55bb14ff8e76e0eea92abcc2e619270f230de2709c2b8d546d14d9e0dacdcf967e29d78f8f259b228b78f2e69259a57f4ef9088bb5e00233c26059b2af928c10b638d08b03b3643f1db9ffc5348cb9f062e70aa721b2f3c0e46aacef635f5cf25021bac37a11b10abdc21be84fc9b00783311dfb8a9e739d68eaf6dd3c66dffbcc272f56dbf93fa2e57bb9b3b738fec6894387afbd95c190798fdb7b42b0005cfa2f1c9f2e23a54c23d73863ca97c03ede7f4d782c1de6189457e61f3cf77943dc8bf7cb8849b780871d1bc5c881c38db079205ba14c96265717f820ad6b663c2aa13a5bf8ceb2545d1f7b47c3dceff614f33909ed17af63821b70dbe5e549b941df14d9cdf7d5e0ea63e22f9416d1f0ab89b374ea5de53dd69105c858cfbe69b557a92016e3805d78433c2a0f65761a3a16361e1c6276a17f9b9145297cdc5d9cadf9cbaaf4f56077794487e541a56ebef307abbebc120bab2199e329e84d8c5b5d7991445c1f4b6c95a9663f48924dcc5f1828cab54e290555b444a1367eb417fa4273f35bd8fa6f18fedef97b247a1f5036d41e5f5adc5af03ea75fcc0c25deb533964e8dd5865db60a73edbc01d4bfa347a5178f83d0149c3ddd7e756964a47e38aa468a985dfe35f710c5da1a9b9355eecc784d5ad6c03147f1de1c042f86f862a3fc9b36dde2f491b9b487a97df6dc6107fc7721a6423bdad2b1c31f8987c7f5df2608878f05703bc21fe9a0a61c580388aa27a101b08a0d7ea8a9fe6ae7d53e77685bd912017c0906f2888fdb19e5dd7bf33af7be125ac777ce8f6efb4c6fb6481f855d0ce0ccd099f3573602679a6e91e636714b290a289ae094bd74b0aebd3d8b729c6165849fd43ccf853ec01b80cdc1e43e29caa57c873e6d915ea9d87c8d1023b7a31e69717a4c0e9ada5f2cb46819d960efe9a4733a57904e0e831cef7e72a50eeb8ebb1f4c5e5abac95975ac67939b18532c7322bf2de7761b63d3af756c310980ab6a169cc6d610bef2108dd2855ca0e3d52cac7f2af684d24f3de18554e29c4993e34ebe1f4a215e12c79256d0825f95e1c814b7c3ad5d4f52d8590287fab81decbde87246421cdb1645a9c8f08c49938ae8cadfe053ced416a3f7bb6df4083b6578e4f4e76d7616f9d74ef490ca09df590810c6d8e56d7637a692fa286f603d2678a8d3d7048ddb7ae93597539c2fc686f731520f4355463b3cecb9ec4386d16cf92385d3f62083b6cfcfccb6390618f02658bbac54cdccbd35be53fe467a2348163088882755042c7b5056408295a739ebe315b087014cafffd6f2701441acae9946caa3dc413e0a4ef7742b944b0815e14d681490f4a8832a0c801251446f1441f6d79aa684f1eeb3a25a04db431a2fd30304ec01147503b797217e929b39ac2a0e282b0c66e80496504ec6222efdededef6b4330aa1e8f6e788818d100f217ed8a1b9384d34d4896683a2e703912b69237dce3413748fd8dbedb13e2b5ef2bff6879b65a9b52f2fbcc6707919bee52a7466387de69db3f38560c08bf517c77705a4627c28ff77f79dee9f9bbc390ff058eed2db3e3ceb79859d17df5476dfafba824df0fcb6ea0e366b4d7cb9ed8e3f8fef516a5d7b4475ef83e0d2a83cb915c3badc7afcdff432fc5ab7741c85e0b72fa561e7a44d00a9fcf62c94673796e9b3e09b587487df8024264f67e1bc004e9d0f123ce7400168e606fa212c595ba833a7827cf7570b824ab7b30a0b37a5229e8ffd54dd3c5630a40ef6cda580bef9219f59ee3aa9c0cf707288e4b3e9209c5312d47735f38e207d309e82ebcc27b14ed9bf8b340e0582f0f414a00ceae737bf7b3106b1fa0cb6760c8c3d2acc41becdbf35c24a90bb7c17ba5ab33f51ef49d31a75f8ebb8ba076acc2b2bbef633fd249fc5a83df7047a0ddd63deb35441d14931669df46dd995088c46fca1a7cdf76808a424399d0a5e2a9eed80e23b1590717a93acea3d00312c26aa84631d9eb3091c52387d68804bd0227f67469841a9e3d785028a09915f909875390812d2ad4901c4c5aee809bd29c43c0a600ad8379e100f10c2d2764ed6ba2572d791b8977431af2135dc62bb366fcaa5eb5dd6e07d93a9ee603696dc41e89f367413715529857cc3ae325db214d41e47a9e137b071bee5f019c302ecb62b88134aeb5c16bdcd9b990d5ead26db3e5e1c36928ff0c880534c6db35a1ae8a73abd46c725fdcfe57d35ecfa33447bc103fcdff9d21d05e66f7390f12352f427a6e50004ac31eb615954810081814a655ff77f67483a7b7372f9461217e4b893cbb7c742a3c89820cedcdba03a1cb9393b7774865c5ef27f65d555749ba3b5bbad58d89969afa5e15d6dd8ba775fc53d9479640a872f9509a16b9e16624d8f0c54b240bafd9f97f6af7540fa03298b1451fb4525c9da06398dbc2c6136b1c43bd5c8823bad7e21902ed3ce98a63f9da6c63123131f25bbd50e64c38a98f5d6c99a74eed60ca9c782430a3e57a9e877fca9ad3da9c46d6d2bb54f0a169685074a59fed5934f22d10d263f1712a94c4949e041e2be4600b1ebfd6ddbb3154a840dc6a7086e130391a632dd96d799f32f9a66eda8cf6ecde0066943e802b44650f8a9a84de31baf1874b4d5c39804cf27a5f4cff12acd4ccb7346a60422a0f6c23d2392ed6771632f56d7b0c8a526a8748ef5b35519b0a2f79e0a4ece0bc859874373b6a0c0e92edcc26df7b38a22846e0c8bd9db8c2c625ec55e25168285bfdc841d655095d66a592890bae90f4941cdefed44a4cbeb420fce75cb34a0442230e483606e3194892537bbf29a78b603d072b6e43f208ece8f88bc7ace03dff4e199a89cdd1947ccc9ad61ca26c62d8230721ed1f8fb0457f68423f434c40b17f306d9ab97ad17f9494fe5c3ee0da6f39310e0548d754caa768eb9d1490c350e04a251635b360e6816b71970fbefa31507c8a235a7305c2814109ed1b5110a6bbb759d4ab6c84e6875827736c46d8542c2979df793b4cf02a34be6784c2c4ac10aa8a595310f5d9b008711058c599658a6e8b792038d324b82dd4f98ae3ba62884888aa814fe44446acead0ef2ba983e7bdf7542068439f7aba52506879c3e5a5b196c0ed341643370c9f4ea37396a0dcfeb9ee51303720eb921674d03cb8b68031cc9484137452c34fcd6fe628941b66027e7d2897bc8814d8107e6d7d720a2cb46bb9c6975791d4aa7e12c135aed02de815c0ec5d1f4214eff228aa9391ee189f2683bbed37d193a2c3c62e619b08a01d664c4951decbc0d16c69b1bce1ffceaf025cef60f1fab01caf32e5cbfb1370b23002ab74dc621e6ebc2054586d4e30eaffe8391d4c518a302f85ddd7a346285a0b8e63f76abf9fc9559c7e133def1210de029b5fa74f71ae8bacd3d4905fa44c778c6274239fe6ec41fcc405d3123c3a17e353ffc49c165f7d65b0f4b184cc611c3f0d94a5c493d1e23d252b696dcd508915e4883e1a0b17a5dd3f7437dcc3d5a7d2c96517ac4bb48e95aaeb198ccce9ba96196c1cb8cf229dd0c26f8548fcb46bf634955c95db5ca80bdfc02a6012b385de6e196753822a3d3960790db7a5896694e3d4521ec6d662ea39f0133171b4d8a5eada88984a448a7c286094525806932d2fcad2f7e2ca4d1599feccbdd13017193b67dfb306d2c7fbc02d7e22c9dac6e461c42e206859a13129b19c3b6aed353630b9e2d98f6573cbcd499eacbe0cf0e48a5f219dd4db7c643eaa04b1ea173d9dab97ffe3697d59cec469686c3464292193c159ffeccb48d8a415ddd80b00d7fb4ff0c1a48df6f9bb252c678aef3db42b5fa770040802ce5b7fa4317ce28d861fdffe30e5ae02aba4b4ccb8bbcd0d5d388b6064cb3da94ac3435eeacf7017f54e2ba1c6ce1983e07b5309ae535ea9c4510c12e8a3ee37c7ba65844900361ea51cc94d67d2dc5c13c07e23be8abf3ffbfa780cb76af6165cfd38d91ea0eced60b35f9ba4b3831cfb53c02de759a52b9d4f49a9c7b879aa60bb8ff82e574d657520843478b4821ac27950e8438ba7a2fd2555f74c34057511d71531cea7ef41db8537d26a0612e8f5b6da5b8ad7a3a2b1dbe8b271f13f94a416006c72a80cfff0a95acae1ac65b2ea693373dbc39b3c8f5018bc72bf86407542c4ec70156bbae76ee5814a93ed13102c72dab2b88f07714911e9b625910f91972a144e29bc4a1159f9331779a715025b618bce999cd0e98d6c468570bc187ca1d0f350709eb0c68ed9c39b81ade6e612706747d1be14f3925a308b3b029e3ec17c244d7df7057db24a5d50d90ec91f0c02aaece637a91296f4ede6ba6ddb9bfb681dbfbabd9ee222173869097b9124cb934207ce3a0610eabbd172ad24c85c8a5734d5bc4d8b5ff86503a4ba879ab81c9764b6335cbdb3d648a733dc7f9265c76ebb46b94c2ad10266e34407181635ac3bc309e8b56f592cccb1084429ce87723b56e11cc252642fb2a1f91cb65f40b9548a6e21c0a530d2531f56f338954fcff72ffa04f74ac22d98d200587f0451c312dce1cbd4e93fe1604c244017012a73f26f8c92a721fac41832f97d1c3ad43f1b51fe02666a195dfac0c2badcf71330ed5a8cf51a0e1be04bd7bc0f1316b6b90451ecb884966a6692adebec6ca1dc7dcffee514c302cf8fadf999a11b56aa22afd564f7db28360d34f86e7487237bb7fe7f6d9b47a973f22a332012957e02edf409a3b5ac49a7bf2596a321abbdb3dee3e7f4044b15b63062daf1cfba7d5a226d715de437b6e7478612a74e62de06fe7611aff0c62e4daf7e0c5e0eb37f6339df5edaa835dcc6ce740bed35d91d3495a216ef0c4a1cdd711b3d8b0eb583d7a2e21d43457a31a67ed2276a0a90422cc1614cee8817d2e1eb9a0cd02bfc40f1f0f65e29be368a9462bea1954d1d1935e67680b4809b33f7daa18b5ea58d99fb6e446294ff7a20029140d3cfb7f109f67975f4c3f653f7d91c5e22bed268528c812f1ec54581ac37cccce85a4272cd4c5bfcaa9fb963aa3ffd3f47244ec97a11ef08d78a7526ff8b8881d0d964634ff1e30a80bdc030b2a3152a7f067dba5eb725a49320f98d148e80212c4bceb3b852990e99d43ee2885dde1ab046d7a39a057209523b6aef396475980cb9bed4e88fe2498468d44831787b2e9b9151f5338d0768546e8f013f61fd409cf56fbb931e169a681feeb63013e952995a2615f073ecdff002605f1d92499c25a3bad2ad7430734513daaf606b6d9aee7c684adc145ab570df7d21f02d44331ad872653e14ce2cb21f8fa9224a1d08012ed4c6c143ed3f7d6224105659116258e2e3424777e541f75dd4d94e9f0ecd97c0682691deadd615df76c8b448a9de5b5ac39689464645def666fac6848457abe1c8575bda594a76a369112992ebfef0f7e5f6d1dc362633bc987a73a59de0008cb78f9aab13b770137f2ccba5b664c313549674be2fc1f0c0187631721976e613e1de54f9a5382c520be86bca29b5841097e1e1c17f78e94f5585fe47b81a8a2203d63426b208b30b9608a2329233ecc0871238a9c9a34ab79b8409fc09e77517442976be050746e11030d14afdab69bf5f0d5fe3b0435f30f6f030949889f51fb6f2ff1b75ea434816183c159d6659f33199621fb83e721d4688355d5322157942005cc0017c926943ddb1a44bfa9c0a2d2f45f3b56d802f1e92d57517fa747bba946768b7394e260f8df6eadb41b45e6948c54c6a87dfd94d06f4b8d0d6cb653fdb6cdd6c63df8d4c9d499d5074141e6a530cb72ccf32f61df19ad38d41a812519aceb4dfb57b12e20977b0fc13bd40c51dfc0f96f6f6de1c7ea9c715713189a2d4380bbb9777a601973093e08daf4778424a172b46747d7a7146b36776f6ce21edbf57e02fc9cdd1f65c8f64b1226c125730b186218223f45dd65796f616925baf0a48efe6ba364ab111a72ceb86251f577ae8276442aab871eb735e0390419ec612e785907d48b972256cb75a20c896d7bbea82dccab7348a234bc564a643414fd1e06bee397a6cb74be9bea2bec796d53ecca3c730d93a86fa962b42e6078ea0cb95ea955e193b9ab5b5693de1a716cdaa1cf8a4f6a8f298d92131d0a797dd4ad86309934b08f4a109e081b673a6019323cf409f7ff25f31a711c246d3dc109b377c6b0e72a9883b006bd418f1dc635eaf673454d914eb4c69840cea1b7fa6c3227cd4e7625fb596d0da9f2414eae233051ebb292db55b8eb1d4f713efc86a4ee57a64e9de532bbe2c66da85fef627c6ab038a8cc503fdb1e90dd8319ea6807d62a31f414699efd5290086d5e33c58a7aa52d649574a1bd2e4dead61030cb2ab66eb097ca9378634428d47bd68a6b6d77610679f712298f81b5c200398bea25f3b318800cddfc0ec8cc60941eb98c1ec402e4d2404ba69dc444f22e14d46fda00588909f1361ac19b521d4f3f0f7a1749f8376b91669660ddc08d1676f65040de8907d5104a8fe971f3b2617909d25649d754bcebb561f9bd927cc9e74b345f04db5df9f2056e4106dde9e8abca3f338280f40c918bbd2a4a960534a2fa1799822d6da66a33091dfe6971d62b403b74ce7bef1bab91b87da5bfbb872a108f4ed668ea892bdb6c0f491166a5e5830ee5c6e09aeb372ce9cc7a2e6714133caf857e8d942e08aa378211a57c506b345a38e6311624772dee13b6ed28c7fe4d1b331c06c456ce94da5e433e375789b243aa22120c4500e656946c7c0c275ba8469b77e032d69f14f0d654a2856e49306c54dd9ea167ed7f37235404070a3dd07b325e6041d4ac04ffa0ce879dbd6e6cfd82ae88e0ea725a0655bd6285110bc94d542d09b4d287481aa65164d0d195da44f2375457e2ffd53fb8bda98669a210973a2d9255c9efeff086557a02a767308885dc7c4d834987eee6ecef958ee00eaf62de7d6cb1fa3880c95842299ebfd617f278d36a876d26f8819337209ce59740b0531e275e182693e51e56dd859b91ceb77d4c920b4f49f24f3e0945c328c1a1b88d1115d315a0cfb9a50325473c0a0fcdbcdefcef7652a3c0daabcfd2ddbd148f917a662ce00a76334b51346639afa8bb4757d01c8ff540c04f8555cb966044b659a9b76a5f30fc16d4aa8c1388502822e734d4ec698a1972d466a199c3c58648b78d71b2169964e599bc8cda7ebb8257eef9e3291da26fb158e95ab139f398bea5c6862b1359eb36b31743938883946bb7d93020e711195c616939b821585a27818af1f4d5a1b99279c9a9a6a9bb1ce873a2669ab019ef78978bd4d2c9a844944b38cde4ff68570ba00ef7a8565898335bce1435760887b5670d32080acf2339877c6432cb6f9874d919af765281340e105e23f4dc99b81e5423c10aa0e368847c12c876cdbc77dbb6d1334f391e3c338d6304e1f1b89882b9546b8159b2560d1ab88ae2c77eb6865ef4f89bd07bb98b657b8a049d9ccf2e0be0ce78bda2ba8a31fef47d2d5348d8b40c764aea21476aa74bc99aba550a01ffd970c3a5e8ee86068b6787e93b5d13ad22d1fa6134faaa4e786c799e2850e3b65236fb906696b651553f6ade153fecc0df3b1924664ecc0c492fd1efc14c4a165dd6860b81b88d568af0e01d9835065e9eecdd4f623928e4363e34bc8d1c57ffd1f78a3aa01b024d650681c8f6267167c4a832bdc64e651827108a241d3bd6498233231f5b5d33461b6d24c6c92222a839c3de7132ada8c0c68de35e5630e61af54b82721fa9b59b2632bb179b712becea8abeb1721e4ef347e1c52016df50d9dd947093061c00598deb7c6fff642c888cea898314224807ab1708f8ab03f1273f133e4a51938bfa5ac0f40fb308d8bfe7329812dffd4e2a2c706a21556126a3df92974f33421863cb3e16d02e612f122c86489732d7ddbaefc5916dfc0031a57e5834f51b5d085e56e4a76024b3b7be69cf1750cba2d724f80a966867032535da6f0073d0c9364b0696caecbdc47b22e9173cf5871543b2f780e67046053c6aa5933ca6b588517cc224330f244e821359e06f5f7c6aa6e6c39ec759df94854ee9e21be3dc51e4a40ef95bbd67f08bdd73227a40cbd5e8cf5d457b06efa23aa498404d5ae0a09c92506b6cd06d4bce94c4c5f17135fb9f1e024dd8af68fb3dcc8ffb4721b55988379c8a81cd902ab15806090bd1811679dd08b314a57ab4cd255c7f3e0460c4bbd4ab0817fc00220db77e0641d8acd87996736e7e61d9968a026358291dcf6edb4f49a3a58d307f103489e0a9d4201f5a6c19b97496f91098e0287cfda465c682c2a22a748f4d2c5ecbf817c4cc8837a079ccc9b05349f75c920e9254b4d4f02f5b7edc45a83b7618d0d12d36450962ae1d4fb0424723a8802973449a925e37e0f135ed2f04664a073f359c7f3e3ba063de433c0813aece8c9d05fab11f84c10186e3bfddcc1b9d9561f28fde26ce8adfa224ffe33241c53e1761bbd833344b93f434f4b8388cd785967a83b74fa4459bf95a315f8dc6c697df0bb5706d2434604c611f7ca973668941073c26f120ceedb77887999896073370593d9757d1cc38ab9168a97777bd17c314c9812720ab309f7a479e7a8b3338c3500b689416464a7b0972bf10d0e2f6d251bfb18e3c446dce8e2449826fdd96b9e8690c44fab484473928778524752f8cafe10c5ab8b28b0c3c9ad042b9ac4832c41f22e4c08bce271525d3de264bab020fad5e6999df0390c8a5acf52fff8980685b12e6e97deddc8dc73d3e7782fb42a46c71fdbf789a3c0a61d80401df09992a24aa59cc636f6c1d1558546e917d08c8751abd3cec9c5edf2522e9eabfee4edd199c840007e14de94489aef009f2a80dc488d7e1a7b3fa28744e83d4a8706414015e1c59961f768a0735929ea6d5c75863cc0aed1dd24398daa69ce5a56c0804e061a5afe70878c1bc41535a232e527e790065cdc2ac1bbd54f07d798e7c558f4b0d43b91eac40b73b1629dae7e2b58f20703fa4b4f50824b549aa3112613a2e582e110127ba27df9fbf8d5264a4750c20facf63cc365ab8e29f02db7a1f1e5e1e00aeed5bbfd089e133e5073b679b848705e2e72c06ae725af3faf24a3dc58bf21f40b0c9ccc433f428dff155d2b036243cf3bbc6319a3041a945e5546f69c2fcf0f2f1f4d054899f074400b68951d214520873cabff10483eedaebe81078ceeebf6b0229ed7a2ba49d32e035e73b01f3f197f7f57e9a1cb5fc7b488f0819d625101415a6efe9663bb30e6ca008845b588bed94b9f979ab3ed570371b41d794d1a30afd04481a7a53e29494c4c4ba43a132ebd56221f197fca7d8c1e9385601bfae6f31340f28f4330eebc3ea24f8dead245f1bcb7550df07a5af2dff5f3d395247663879832f98f039a832b74e2dee2ccb883cd6a8e416bb99cb2ab0b2e98695bf5e07120628576a6c4e3484a268ee37be6d15dce7d408b143afb6e477b5a9f276c0c0c1fd1c6cae9242b9f3e9c23dc4f2f30c7d1745d1d1c6745978b848d99647847d063ac6c643711163bb54a8e658850d846f7054227d6400f114e6a83e9273c35037ec10feb257c8429f69a4353c12dbbbb636eba8ce94979e0edeb64233cd0e505839a68ec54fd52eeceb49ccd3533c003a0ff719a75826f51267ecba2fcef3edaad6543e2bc41ecb6a337b9b0a3b003423c1e35e35f481becc2b9bd50ef4a265f0f11d2056a916674f89411ec96725edcd25d143098ec0b62fc4652ca374f71d80b2657a7a92faf32e5f16ec8ddc5685d31930e5dbe93ad08d6e53c47be7a11230b2ec08a0b5ecd1cd12ce1348c945ff2459aa98ac56dc1d89da4949263a759fc056d05516b242c54ef04843b9098ed1f5236810cf6926c50be40d343ce33e2207d6ecad15d72b33930b2e72e0379bcc4aa1078bcc888a01e7c7011dec940532b995be9298f07a11ed13346f15dfbfe8c42af169ed3b034606faeb5c1440282428fab2006ef5c1f5085f260a9db4c4626b814dc9da9731dc31419d13ddaeb868798b334b5d0ddc20ac63fa5e274bb99f71f97eb51e9f47398b0ef1e30c78f84b0a9dfff8be68bbb908fb0a6b7c61a1e48d46d62baa4df6df2171d05b3a0690f846301cfb16afc6a4080d13de88fc2761e6c93af054f7fdadd3d583df9e9716c5e149e12d5bc1dfb02cfaece5503cd05e0450be3ec1594471b9397697821cdb74a89537e22c2768214a2ea3ab9828f2f6e7274553a0432661e50697f85f3a506d0d340f7eb9e206b383ec144a2bb2162a73afc158f963080d639c3341fbcd506ffe84342251bd3895287668c6d24f372a2ad4a4016b2a45f82fb05ec94ef225ceb90772a2296cc97d569eef3184048f11340da699d4874906712dd9d1f9bc3697369eb8e05c256911de3adf5e14074115cf00b023cdd3c6c3f9183e88e85614664f430c8f0fee2307f39f5daf8e9182c337c9d0b67d3ba474e10686a1cc269affc5be06c2e6022c8b92ea588e6e21251f1f8c6fa36a10d65ee0e8d62fd4a1d838a186472db73b59da5c5cc1925f0a8933916fe8a81296abc38e8611f7c9eb3f776436e00ec9103d4d30f0dfd1d0d055976ad43463dbfbb9ffb351f11718304ae5b39c64043f11a39b6036e16b15a367cde52169140d28a7410c0ec1d75164d8103b57518d790e84e9076acc1421595727ef6d9926b0d776837c549e6c7f4be2e9dbd3ebfe6864a835a170b727c82290cf808228edbc04b3917301303a0ebfbe9819cb67bc90fd48d52ce3c4d985d74c37102d48fc1b9333e50a891fdf4bc529df76d5f43c967f8bf54b3e2890ecbb12c9e35bb1ce82c85ba1f68a772497b344eaa555752b663fd49aedd08f02185393ce84c71a31ade46e95a9afc3222867a2fcd39aa917258b0d6c931c7b86435411ab7a5e4ab7a102531a2787eff1783666a0302bf4f9e5cb140db8c971edc1fa1a1cc40af4b3f0f38435250b827a5531751bb547b397d9d6a690eb64f09300f76db2123b809f562437b305d77355235643b99761733b701a1bf65e4cad14409893a9e71a995475b13e21050f8f30403c5c04390118e18a736b0cf2869b7fdcd11daa8375bbcaefc8ed4e8f46d878f087548f6e7cd62d07f957634aab98814eb9c5c49fb9ba386cdc3d8b92d474b10d3715f59c90866de2bed28d549adc016dd81d889777af253f6f085a4f1c3b0b76e3376b1c8c1d51c46c0235c1ba30ad395cdb5958d42c9a86fc97ebb08715100aa2db2430bf59a101bbf6c606028b466a763b539b46f0871c2ceedf386c0c695884c2793d1226c335620b003d58a8c9cfa96239b0353c161f044d4aa841b18c26f9e605b8f6ff03a89a808ba65a125823277fb591d8fe2207229facb35f44a6283a4b20dcb03fd197aefc255ee9c6737b9855135ea9e690dbc4e11256c732a884657ee9589e279662222f1dea1a37630797ca4662eaec634b6ddfa62e0cf471f5a8e2c7e8d7f6a8e4e4cd667df3c15b7ad2c8a2a81ca57e43195f0ff1151b9ec867f68ddfc1a1056c567dd6def34f7d40ffc86d3b2b45e39d0a0d4927c1298a436a95ca54a7b86801adf0add01e101eb9e0e7ba89d3437f8219d475cb526307d04b68a9892b74cd47085d33cae7eb95d7554930d10457d7269e452d3d296b646e3900d8eabcc7fd3ec67082387f144a136d769b10783ae30280e7276540e7a434a3a21394077ad7aab7091208e8a8679c78f83a4b83a118ecb5ac4f8c1878dad1bb4d609a84de1d55e17720948572892cdaf9daf56f4b9ca7b55445fe9e5747cfc3b17a29960404539fef78b73b74d915d3768069f8b468cc033451f009efd8265aa6a3152f3089669aebe04d8a938d55493c84f24cce933f5efcc60ec3779b7836b5996cba6c78ec23dfb8e0c1eb8986499bca8e899da9348c656986b9ab04615c2ca7370c98ae6ae72c273e84f3ecbca87c835ea9870e465adfe3dee4e8a34fb41495f4c24d96e54f6868de7ba100cff2bd8abda2379037dddeb10453a074fde60ba8dc52c9c9963a067d5483c7871de9e913dd53212a63be384f4bc060b92bd57be200e365ac316af432ab2b380eb9d8c762b9f3b7d1dff304a57c9be7ce1273ba8fa2daf202612ccf7d2d0ed4f1485cacde284e2bddf79317d3c493709a24695220f96e3b8d8a03a3475ab2cbb9e6b31a084cd50ce34a6f282763fcfb030d6abe129e4b917d7b9dcf85da17eeb5e37c4ab1322fca489c418555965747a2b30cb0ddc6ad6be66d821d20de15145db13641b156c4eacc6977014778f7b2bff4dde457404a65e984d50416a023224eca1c23d9ecedf0a0a68f2ec61569ffbcc08bf122badfd04e82b01c10b2687a2cbad39795dcb0a0c2a6f8f7cbe43cda799bafe79cae7bb3a0d370f5076e9dc3c0f319607edf24929ab61b8470ea1407e9a9f9b6d2e3410157bbda1bc1042fc12caf8bb6ef315cf0969ad5a972a0be691b144116402728a1d12e6ae4c1e3ab0fd59ba55378bfffa9176bdde78a76d14f68fe9c2b6793ebfbec00b8c3fe5e2b0820336cc7c1c8adc3928a0178b88010d2a841c81243bb75754f8449c886aac628668e8d398e720cda2cf4707ff6b0e8534ff4d265d424e116a0f6e3c07eb670e475fffe9e96b6f23113819e637687860577f2d2fdda41e56e0b2ec7d6325baa572ef2f46d827091f8eeb4fb7286977440e82ca696f3bdacc23723406a5d8c4b8fd4214ee3bb47fe77fe7eac6e7ad40d53881ec86c2800c18001fbb78f80d74ebdd987176e9d93690f70605a48c9c975ffb33db52f70b93979303678e8e4c34579a07988f1015d0f0c82745e46444a5974bcacd07ae9acbcf375233aa4ad7994942b9b3221b32ce288a67780f4af329f3bafb74740eda2b0a0ed53f3ab7e0e0ebf4bdb76edd61fda52d7bed9c168aded4dfea24b4adf4387bde2aac7b1b90d31cccf61551b7c6c1f6fba2f0780cb50950991615ace2fc2abae04cd04e1e082b57222aa83e8fb2667addd8c3c799635b97099e382efe2e38cadd483b7a10d539656ad2b28def825380cf6af4afd208f463b86b4df99583319fb8e9124877c59083e5955ad3579e8c871237d6c22448470ecf9e31c8a0ac222e1a81aabf368a7360eae38cef2f3c50c05f12340533d6d1369b17a9a11c778d91d892ce69445bc6eca54e0f76d6e7ff608241d7f644a9a08eefd872c9c9b8b8d2667fc38700dada2f6d7422ad54af18345d016c0993742512b5014ced511eb818dea4f32a83097b3b5ae3fb6cd62ce5252023d5db9f6a06bc26e4302a9559674ece840d64a982fb50a2e2bee3d11a44b5b8f5359d948c5074bffe5d5372196a6908a81247731fcfe966122ba7072e4bc96d35410ef0861a5aac72fde978f3febcc12b4c1fac04ed39f1b0f0392422823d75ccd0e9b6e4ad474da812841f3e690f13c676ea5dd155b8390c5e2ad390206733528b6b029459f007cc38c6c23f28b764e0bce8b1c87234572f5f1921f7c9e9d1721f4fa8f8ba8a92b5ff01a96830bca401161e5ff35939beafc9ba377f7ecb31bdd0abc7b31179560dd6b567bda748db7c71919d06f1fb4a37c488ae9d94d82167df49eb1fb5ba85f8cf6d8b3faf8e0556d9b61ac237f42e06acbd7bf5d845ace7ff9e4a65a52c5c157b286910283ee99b8aeea82f1c058f8201c5184ac5b5a83be8c5414b6937d1d7e84b1464d4bef78d509e6d8f06f49beb1690b558902eb7696e76bb3c766f901ac3594fa717fdc25a273a7104a8dfb2a7b202bcd74d6eee36a36491b07852a3ece23dde1bff12a5423284b218164c72b37446ea995dbb948fcc943c4483ee9723a233181f16730e14f493a3b592ca410e2275929001d50bbe6ee59425ede55a60fef8d2c0391e0583670cfeff80dadc4f05c361088a79ff336749b0a50638270f0f20631eeaa3e89fcaf7b80b6c2c81777e0ab5fb2e305201b2de3cd1d20f737a082fae27d989e978941b9b31662b02abde6f25d40fc5244c27f6e871c3e9a321e0c531642a2a1676b71139b0fbe66f0e1fdf143a7fbd2a6b2948d584b91c5e8454f11271784d7f10822eab983257e4c079a8859266a634103064ae428eda7b9b4378725f32a032b8bfae1119c8a4a74c5a32b2efda8a31a04dcb30bf467b48dc1b8a92890590867a58bb66836c47e32abf9d2beb12805e6b9c00349fe35f9ba1dc01637b37d0934272f1c9b0478a868b9d47ac84fbc468d8990dc1086fe403be1d876b343e58e63c82812dda6166f02383eb0675f0f81b05d58bdc56bf8477e34b56108662e2c94e2e0d4fce6809768aa947ce0a14cc614c23c497e2aecb5a29882c09a11bf2cabcffa4f3a9f8f682c0fa57ecc000297103dda4bffd34bffe24fa277039b905eeb6546962c0acdfd744f93064e348297a21c1ba04b26cb83ec2355b423b4e7e5d3f821facbf64776ca26359ac496760ee8b32c83e2a60aba561f9860e572c5f65c80b6b02e1eb3324995fd7b9330d078b0ee6dbef7c554a499a7e9d09c64b803b61b6cc929b1b0c09c25fde595c3155fd02302a7b6b8a8cbfaef3b9b39fb23f13a7c15ae31f1435e11a70a7fa3fe1017b720e556b650984f9c8cd7dfa65ca9da4cf80feb04a8deb08ad19cc6526edf60483155a2d714bedb323dd3dedd1393d6088c828246d710c56a4f1a4aea76f66a6a27b63ddee1236a96e77fc81773423c0d6123de59abbf0e9231e9c21a2ce5a32b9e2493cc5a0e9772e57e435f3ecd8910104017155ff95472b45277656c37d0192582fc0b4064c6fc26f5daac47008612246d290d4638796ecf77ba72500e59ad25acce38bfe5b6b579766351c65d5d27ee67c33f69a597ec47b5f4dd6b9aedb06e42079931377500e56d1173396f7d6ee1410c3e1b66312c4d9d3847c5ca792dde6aceedc8c8be43255876f8872fb7f71b59881c7d699bd00b3cb7bcd5943db7dff8a91680a758d4bfe9c6d5371068ebc10bd88aa436e7d0e99f823b0fb2f56c4dfc039e20449b364f2bb0a7152940b16f5085e06a5a4456310fd5b1770fdbdf6dc767a06da1837bf2be904bcf69a5fc05199a3034a533e5460ca92992410142e90abea3104fb52a79e46025362bd6160a9f5c4d7c923bdd999713bfbf23186cf50e4a7156c2f212bfbedd8135cff9c8ba3f81abc0da7d85314a0d44a332cf05359003a15b95e2a1ff13f4b78289d3f58bb6ace114b506eafcd8291e6948bad2672e5e4c36d0606825d756e957b6894964fbd78b2289c65b7d42270ca9de1fc5eb2db2f3b1ac9bc8a38181f96cea8b6c0084370ff1e7be9802d0baaa9460230525b63b4145e6181649dde6dd4e64adf2acc20f5cacdd08e55f7dfd5ed90943324fa1024c59334ea52358594d2afe464ea5700b6830d03c427b1e66dc6340ebc784ceb7bee479fadf569fe84dcd4ab5bb1e7a4f186c67f9f261d747c0d2ea969dfef696a11aea22d55623544d19fba1620e4cad5abc147dd9ccd785db8d9f92fda7b5bd811550c3fc8351ee46354b481436a60cc46ef02c4cea9c860e44886ab7244352f0ea2d11b4386a535f6d82cc962b4f047a8731df10754732680776faa769cea1a860ab0c676277d211bcd5df128c36dc74bb7af63a20c3d039d6e619bd18ee3264605a3a5fa0cdce0f2da7d50fc25446e450bb249701506dc849d771b0531bfc9747d9153d659e47e6837b177017fd6db03fe2740b2491a228e18c022bf16c638bfb6173cc79e7b2518c64aef3ec7f90473b1c61fbd52bdba153b554008ecfe44a07d3ed670cb6be0075abc1c0e5185389f38c814de9f27a8b995fcb1c6bb0e257d0024a07790a763b0058d642bbf7ca6deee320b4deb13dde161fe698ba8d2ab8133e86b03c85dfd9e0fefc2de4c1dece510f66374973c36e30a098c4d88cacbc0ce909ab01af5515d4ed74064ff4fd12ba0061c0ca210d5a2b2213ceb29d43318d31480a9217fcfca7f24142f007c893d6fd21f1909d954e44f97d98c58781a7083f79b1ab1449871eca306451d56ada4cc7c3dc41fef2777ec5736eafd3e38ca16699a8b22c884f15bd68ebb9f85862780f889aa33adf870d4928ff6d8385ec5c729ba3d9a234d214c09f301fb69f4ee03965c1840948edf40612a5f9d8b075f7c78e63b486df1d12b05412545efac9a4f5a2fec86f80af6e1030d0f657e71b93996de156728bb2f151830e7878a9fcecd9c6f92474ee2b65cf3bd3a2e0b5c0e20214c3a9a804958df1a01d6a09a62544dc6d5d1e06e0cfb2ad1ca13cd4b00e79daa2ab7e1a410307d118be4f13c930e20649be51e0d4cc85e3a04b3829d222afbf69f800dd0691a9d09b43ddac659d6f779217037f6e09231103f6da98199ef8869c7e93a8a23f22d27f221f2bbaa5d944e370d5896405a2004f667709a5fc47664d544ff75254cd19ac398df7455cda9748ccab1f35d10b0468bd82f92ebf7df06fe1bdb65bfd3f1f2d497e241035d948b6fe4dff53c2f9228fea98771af6e3bd35fabc291f258cb44e6e7004ff768c33238d635de0ee84ae96dcc0ad2c30449bf8e6092573e0df93b65c72e58e3f14a7bd1143e7eeca4e5ae9e8827ff2789d7f65eee2cec1b2109547f3955b28f02b62b392eecfb6d1d76bd96b191d0b8cfd1ce614e27774c02152af5863193b8b61660eab98bb68a7877a0c0a564c8a2b0e5d3444c578e7c792cce0cf8887d5977620bb7fc685dee9df0da5d63d88c3a74afd9eae0cf9945c2f9f0b883e81b777d4ffba8dad83e3a0e204bf520939be4b9f632065c019776d2f8e4e2add8a3adc42d990d3b52f05599cdfa4c12a6b9b14faf2aa0d101c3025ead381528c2abffd0af625ac74f6860ad1218ccc4fac29660de04860600f77838d3066ba0d92ed3cdd0e17e5337451030347df9619e420b7517b0066aac39ac527a6191b6a50925376004f0bea088c9d54384d757f4825383bd33bf4308bff02a1da7ec6528046258d3fb29f76c9a26935f60382766808ad4a31e8472fb2e1b522f4b46c248674ecf982e15c9e5303cc8f8599d2dcf6ae7f79111ff62aeb2865aedabdab8d96dfabbd0bf86924de952e32f97d3033ad4490374522eebf91fa9fd910d71cc62e0c5815f831242a1b340dadf2998fce0ea0edf07badc9e828dbdd118a1ab1d75f15db2ee59c77dbfcfe2c0722700fc8abfceb2b4644f5589290ecb11271abc728167fbab2ff8ba42b02fc6a3996c6fa3590d73edddd4a34b2a5ab4cfd81563a1950924229ebbd32f5e6bc23b17fe524381f88a35d3b8b7deb7b7635167db91569ca32c70ef697a5f6d0c8526934b81bdd536630f57db7dc21341435410159059b35834fdc0aa71c996e371e04c57db320d86e79cdb0fa33fac32838c143bb385311d5a86fe3d67398d347dd499b8ad4f5531a5133934f3814d92eb430232db9d87f030ac55be832a7aa7eb7126b54136b33b8253e9203aa31691cbc85ba97010b65549280ac67b928aa925479c659929fd1e3c2006aa9d5f0c98c34ec0c14c0de661e19be3c775a601d1abcde4d5b3a3ea8052419e7b5f028179d7e36e4b8be40589693d233fa4cd27a0495affe51bff733454dae622d9ca9e4f804053b5047957bd71c345cf78f2f6199ad056e21bfe545098ee4cf8d6064937f6330a1ecf3fde83e6fc424d98541a54120098dc97369dd49cb8fc38588060853ccf47eb6e0b70699f1d14df9891f62712ee159072c866f71159f506d5c97af3fb063456bc314f94b7349fb411d8ec755bcfd13021e0c114ba710368fea31eea1d2bcf3e058a7102ce4d7f972713bd1a4566e5e58a383cd96570d31132fa5ca31481a5885ec4dda1aa5c36660431583b99c238bfed226ce880c55f3e6d805534fe32a165e0c662f35a59567fc0dd008cfa9b16dd8bc99f0d082ab8566081aea69835f49055fc1815408359eea4cc429a2e021abf1e53eb7f5a14b57340ac78bba96e2e07286fd727325a7dbe7345e2565eb91761c4dbfad8f3dc9c959678ee3b67cc309e575abdc196228b23604ece4f315ed1193efaa13b60f2c06f0f213217cea485adcaa97678d6fd9ecd172582f255ca8a438a5dfa7cb053920576bbf0cc42152f1abd826fa9e074a129f0535cfead9a829fcca1d8c95a79782d1882302f36d30fc53330fe13d6ab101251a1aabb2ac49ee7ff00231c0f65e768e2f0655897491081c3729e7bcffcdc3266a8f49d7e7bf6af809c1b0a8dc9422d79d61d58f2b5b5ed8ce60d9456f31f8f45faf202db18e5632997b5b26d0483048f417ec16d24dbd1909aa5491867bdef0fe8ae3931ed6c2510f7071ca8d869099882abdf1926899253f6a0a2e3f269030ff48c3736e92dd65e2716a12f9321ca2329de0ab7d014ad4aa749fceec790fa800ae2d62f988883efaeaf2362258d0788d7a097917f4ad244f3562673adbab2e9ee62fd2d3ec1116af5e23bc9d85b28a6006286e685ab8d1fc46c088235cf9362edd4689d0cf4abab22b37eeb0d6e3465f46fc403284be12ff963d56a94a84b389949dfbb824d9f0948d397f36ce6095ca005e478fcf7bf3d6bb4b77d430657ee8e264c560526184d69aa7a17746aee288c4fad2543de20c0bd8c4e8ed743a8528544dd2977436cbfb960c9eb8fe355c672a42a046d531448c3a15456a944aa38c29417021edad3259271629e622d55bfea7796b5b1178ca7e2f4de52323a1d78d20973e9c232a210747e194f46ed8624dea7e2a6be7d3cacb2b2bd402140640e5133b0b72121aa5f2db1147714c748c9237617e6f058fdab1362381b21ba0decad71cdf616523031498fd928a58e729b3e7799bd9a57b6caaf5adf7eb79c45816c1e47e0454020dc65db1b2c717fd6601b0cbdf1046185b8433e3c736960bf39b0099c89ec4f004f0cb75d34ecaf009912d0e881eb1518ed3afb2afbb30a124cfa05b257a16941edfd7d259f507312eb955c0461b48416b594e343fef30d6ec85faeb5466fde481f271452a3a1a09dd73c63be63b081b466559127e5e58a3b5accf028bb7bc9d1122eb5a0a5dd54ed40c7c176844fafa37a702abae6007a72a5397fa242876fa8b497b4d89b845ed99c50d394d8517bbd63d1110793ced9eac2a1da79730fefacf44aa172b611c21fba328431c9f80a63399d509afc1fc399bc76c0b7a5e444db656afcbcb17319258c0f700278322bdad591e9ec3d8ca3fa5ccd8e13f2da66390b7ef8d16cebe04bbb999a36f178b605200ad89a04595bb1fc403b73e95480f0eca6e7d8c0a1703d08ac0e4ca6c6169a57052363cc0006d773cdfb857a295e8b7e9eaf69b7e82c86b7ad25771bf1dc5e78dbf673090cf02014db5fa532354eb3bf881e4779960ade578f924ccc2126601d7d91a1df3349cf65dceca7f0f3e3fc54ac482892fed5afc87d0055fd3f3fccc43b209dffaf0fe253efd8d8a9fde50aa0debefd09ef445d9d1b6681551b7a72809c3ace93eb4b28b32287fb3833abcd3237b7996057c59fdf384dc77d603a6b3b2c02c087c6812fcbc929f8eae453d933030dbcf143410900d388945316598b9db0339f4307601b46ade0c5e3d80898879100f0f137c9d7e38f296ee854405f25477a8b918449a2352e56dda043016a4ca20f6d576236f30daa18639c28f70c9c472b8df9e2ac39f1996ea2f14f488e050d3ab62c8d87f430cd13027abc8f8ee402826b8912b9fc36582270c8e6e8a464b7dd502196a744901bbbd0bf00981522ac1e32c06a34d2baebeca76e1d64f5fa7e548a8a4505345f366889d662b4f69b672eb155e21e1a9428ad1a59dfebfbf848ab20103c13f55a753a38e7884d87ce5b773e55cfe151fb53351cf8693e2f0d5b34d61e359894ccb9f9ab8eb17376779aede01137c798577b57ad24b0df5069da80860e203def519987cb4d2875fec54ca966e02aba2a79554d4c4ce6c48b98e2d83da30af4e6d6af79dd53d18e8625b8fe65688799b9d8cf7e5eb5c54ac79abc5e7425313f553acdbae5f556811e3cf848b37c825569d282c05635fa5f5afc47a921cfcbf1d15a6b10526c103a7b51885ae6abd7c6940d64597c912d4b085df9ab07b21f8def0d804e1d2a50d0fb5a0980dec91752fdac1ba7f6b100ef4123b8b2d327b5f493c1d1e95f505b7f87aa8634d593f729d780cc10cc9ceb38b15f72dda51df9efdc5649620934a3dd7ee7d06254ac835fdfefaa2ccaccc9b6d43440cc8e4a2172d9b8ee188db3a0a532d56a864fdec88a01cde776c8aa7c6afd4919fca1f8c86640cbfb8f80af5d3829e675782d782e9110e3c72cc7507b0590e7565fdc2be5c13b4aa54a87c4d7967ba5a8f378aff969edbe1f915bbfd2d7aa35e168fbde1535db86c754ecca62eb71540f47ca44f9c23a877a2f0fad0eda1b8cebc0879b3c39797f3579cd90f264528633598e0f0ec067456e048007a1fa2cd3f7be804896ff20a5d315d75bd1b1bc47bd8ad97334839f089499e2b9a5f6f1103aa66839e3f656106091bbb7f98f523bb4553b1eb4f1890d6469f39c3adceef671aff27dbed9f93595943edee91bb0fdbc2339c1822eace3588572b35cc1d4ca56740f117beb565b6bba54377ef22008b8a61bf6ca4ac69cdacc9d397fd9e128db90b3fbc96f9b7f3b19dc433f6ec49abed3816ad5b4d1ca56115f4d48c4f03b3028a5b8e8e9458951e200ee4c2511bfd4ec371e72a0274dadf81f1388feacec549025552a60df589e92eca83dbf984d9fc6e764ee54c0136b02b624ae0a732905d0e62b90c050b9f4b52f30c6fadd652db8f56dc77258bc1f80c714730ca64b4d517915519ccaab0a1eeee6fdc1e395f337438d8c77c753499d5fb66d8880c4174355c999666f6c47abf18dd4979f61a6387701b99de720796dfc02de63fb54c559ccf38f14b3e9cb478c4b0c005c9b2f169471f731d7aea35276ed43b89c53fbd2901897ed0e48eda1e440747950c166602ef6c675f1841606c25db211fb1c5fe45714d2611400f5357bc7982e0e9db9ce7115afb9db9bd36961d7e626557a90d78df022fcd6a55ba3847676a83c382c8f777607168bfd414a372f98c47e744ef7a6065d97b26348855b7546d5ee964efdb520acb50e23a228baf591edd479e43c501c8a74cd73b7f1853da391964c296a692af0be660578637383eca9e98299185bd84845d1af891910071eea4a372b4bcd36272b646f056355cc8076830717f8faa9f506134cc84e731badfd5a0e59b4cf5ef958b2c3ea0b07321335029823f5d75d33646408959251b4765fdf8696cfd93997da148a294bf184565252e1d82052af1aeb16f6d8c5cb2615a9de82c339249bf8fe7f6acc59f3f4152da7e0699e9ed21f1ae38381e99c68fb2f2af84adb662933b606aea18c3146914019f028de99f47a8a662ea23ef8ea7d35e978d50f0a9d865b2df591a597bb2f57c2a00f09facd64836fa7fe6f3e4a48d8d2268e9ef4c37bf6d64cf3ef5e0e7a69e77bd4296a1e51fba521a891d44939a10baba17b3c5306729c57f9de861ed077e86159f65f3f8dfd01687bbe86c820463f4958c472a1069e86226fc81f6916d4f590b052c31a06d7ee5aba3decee8861ea9e618ec9d023984838a6e089ed3f344549433b4287095d590a0d715f8a40a898fe6f2d13a31bf97a988f90711451d1c51530401d63e6f8f5b0ead088c7a4d8db577cef3b62578d377a368c4b03da456498f24fd3c1a588840eb5e0a0b1f1f47e1fe3d0d2f2cdbe7bcb5e491ee972ca47feb47640c4a15cc9a1be2ef3e5f5871b932c850c454eae2dda67e6082869f81c4b5c05f3bb9eb75b1aa803870cd32f613e40a506fc9e01d9dd7a2f2280f6e76f5f287cd056db2793c96952a22529d42efd3138d8ddb5c1114613f5bd2eac3cf9d8060c05c81e3d7e9224840ae109561ca083a0ce937edf0edd72cc37d7b277ac25562005986781a07e49fc8a5ef9fc1129986f3e92cf20254c22043fe6853d11b8a036c2a5187ebae335d80cfbeebf83c2a13c8ef9db1c9154361c73c5624781178bc65204420b15ab8679ed9bf49489d4c333c73171bf9b3ce78192051f5c6c7e28c4cb4f6ead60b49850fb33c2387d647438ad4e984cb46f64c86f9e46bf9c30f603830bc7e0e4b9395e351e276dc01645f2d6b980defdd7c8a465b174629ff9645a3b73fa7b2192584fbbff055dbfaa033389aa707e972f7fb920154c2d612d7863b48dcfee444c8f5b662c98e2331928e25cc8d5b60f3b24564071e738df183b3d398b902456f207b22afa7f5ed7ab46baf0bbdcbf3bd41e4dc9447d88510b38f5ff81165ae0dcac774f1e7c5e0ae9a1d79c4d69ac0f7cec80c2faa90eb99cd39cd849218767b0eb0249766412739d03e54b4ea036e88f3761dfbb3eb8a21f549f1eb6e6c1ae752d7c8b8c2ea9d5fdac58ef7415ba31e10d6663da610dc5875225cc30a1c087a5c43bab8a62c24a138fe61cd5eee9d5b3e648daadde286eeb76ba8a39be60b23d7273103a114cf02a43f06af4a404bd3cade0c1363b0621ac8473326adfb003c2fdc02373226f48f68aa1b4ce30742f727136c727363331b2616462d4699b73d2dc46313dd767fc8cdedfb838583df6bb829478609c8fd436cf4c287718de9d6db37017cf00dc4355aa4fbd048f5e5b32ba15a2dc22835a4473638f285589999111ecafc1b7af80c02b1d011ec0d22a28e6ef82c5b36fd357d3f7ec83d44403f31dd832ed5a5fa85abbfc79c10ddff920b4987cd6922e1a066379b4325af303ba0179d2601a973a2eed5c3511208f8467471a5b2436e55fd583d24f170c154c3f5dca16ab64f96aff13f3d2ffe4835677800a8fd0117f02906be1c5a1eb4cb1ee08549a3ed622f73ac2d0c84e71806be617ca59b33a0c1007cdcebcc9759fdbf9c7b04969b19ecab56227668230d26423720ac5358840d984c721cfc50205790115dcf7c7164784578681239e1efa0b5cd2e2ad9656f7fe99d68de27ae36804f7508b874896f536e604110f97da3316fd6e08ece1bc117f8d66d9453cae505c92d597fcf3980d5e1d40c495f7dbcae218e86391136540d7a61297496cea653645a8beefac5051033b285427558f99aecb50107a343429d30ce7a91e3d90baeaf3dbcd5d875fdd1d62e535112b569eec86391fa3f14328301688d2c840c16a9069f0b962111c08f5fae50c202d61321b3dcea2b8e55d7df678a6d03a4aed7a74a7577f6f85841a27656f6ddcf1e3ff1813870ed541a850ba61a9dd9cbe1c548b23c8a066596efef06f498c4465e06df3777c99552d88188235c85287f4c64c9c30494b10b68d81db102492e1aea33e06f83614779f9591d2ee63eae1a46f6eb2dc44910e1d8f59285c0210d19660533ecdd0bb490a30255ec4edc49fde6917a45262774dfb140e23d4f6f9c98ad3384482a18e5440886c88ec95b9b0094d296477d132ba8febca7631095b1073f1aa3ed509f7e7980cc482e7bba218a04886fb45185c8a5136853d49fe6e974c570a96b6aec19b789a8a6b91effa7b12479b0c899aa9134c5f6dac90fdbeb2a1cf7874b200d7ab1b038e77f862c53ee851e7dbbbedd4a751d34b9721fe8e19d3d39efa5416fbcd987ada697b21a3b5909b1296131f0911eee0bd9fd261ce09a54150ffb19c31ea24deb0da68a965e8f69c64d39f1863c7aaf767de9a9ac2ee8056e4068eaa4bdcf94336b4d28c9ed96677dc480b92349c449e49e74691363be12a02fe1051307fd94d62d784cc5acd9de1b273d23ebaba1f198d4ebfd9b5ea598b8e0d3607be4919487bce2724faf3ef82ebd995ac88f840b1533ef891c22f34b7258e4fbe55246e13ad64284f817b2b079e2d",
    isRememberEnabled: true,
    rememberDurationInDays: 7,
    staticryptSaltUniqueVariableName: "87c09fd04e83b6d93adfb77771ae4aa9",
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
