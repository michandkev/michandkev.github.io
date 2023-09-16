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
      "62c1f3b8c89e174560def0f59d05f2697dd2131614c0c54eaeb9db0f9f40f5f8cb3e08e80d0342ac240f6c7bd266c603a63a33984cfecdf9c718d310f30602109604fb4797c82fe9377130864875e9e9202d2633d16976989822cb54250fdde543c2da5ab426638c62d0a686d6f8e2b4ff3ee40985777fee29e43d8a2eaf51c5f04d1e5036664e1b4d4d450d82dac4f0558c7aa3e24bc0d91d74cfefed8aaafe0b750660a0a64a19f20c629679d96de724765765c876619d587c4927e0105cb604dac1c864f87417e330fe59bd97bc61a97b5058cd592da9c3dd753e917d54f8972f4cd5dd5ac7198c4e0520b3e7d7d775b5b5c728155699bae7306ff1756190d53883e52a8b33a0c4538d947c9c287b9b00521960da4aaa267ac1429bd8d090668eeace7e86a3980cba8ff2246df71e21051dc2f5a8b66e182a972eef7e8d05035f47848e5add900095e4b7e0967d44e2613dab2491c0ed36cfb1baf28917a28e576a424fd1c009e5b3123125eebb50101b8949bd8a3b4291ad4357fe4d5fd082eda2ae01ec392d8905dafc9fd90748407867d58e3b7f827ebac4c03ad5dc04a687abeeef59b79f1e92e5706324a600de325b53490131b365de91b2469b2382d669ca917f8a87f732795ca2de91cb1f834a27759279e681e3ab2b4667d112c2b8c66b70b3488428fe36aeb98c3dc7d6e292607771a29bfc1cc097e2a6c4412e1c41d15530fef24e0b5d2ddb8fd23ee5688ad9c4f53ade819b2b4b34054d947dba8d4136a57f91d89ba5f253f82a61eb9bee34d037e844923a19c3e696da8fcebbc7bf6bd11b650aecbe64a39091628a38a0aba8ac36947125d1f95d49170676b3e7dcf2eb88b1c8eac2efe037f605d7bc85843bb4ffeb6fdea16ab741adf00f89b065c77be87ee181ef9c7cbc5459854a75d14e5b071cc757a17df69631d6362051572d2890d03186c6efb4c0a8d8fe13289cb14faaafb393160d2e9d299a0ce3ed934ffccc4f3b198169a720bf2e4267916ae00830681dc00c77f46836a16e4c600b801879e69332b63d0b954a0e11c16486b608d5c978122170a1edfe981f5d5f04fa93c4af218eb24c23c4bdd273fabd1b83117f4f131bf974b7a081a2cdcf6b2bad9aba0d2c42179ce84aa1b6475b34b23a5092e138fcafaedd200b5e23ba78c0389a6862d4d916d6bae98b4776a8fad2b4f77ec583116d3ff09cdb1ced2f3de47195bfb9eb65ede949ffeb2689574ebced3c7a3496a42c1048b88ce16b880c1c3721b5d37c5802ab752c5830f3ddb1496aa52845cc6e932af34fe5312f585206972f536b126998c1bfe9dc47c1a5419d46675dfd88705ea623cbe8f6b08719e95165bd78174c6f7510d15f1cee347c037b6a14dae2c69ca18d7221db0c2ed2a465c5d56de5a4cd7c1509ac25ad56c4c3444065918486fec4e5afc59e4581118b476dcd40b3a0710d7d0b443fbb1e7bcbf25c66d6e788d0f67a26f196e65278cfb8031797e07e6f12c1932429d2c8f33d0344ded4077b361bb3974997d038751f540639080bccb2da8438cc40e527d01d4ec15f641450352e5da090431d8481b58ecc5c63a5f79901c7329dc85ca0b08c4a286e98c7a1f5ee1c7e47ae50bc85b13a9cb00269e85acd13f99c4ab3cabeef7f5b55f5eebc89c0015b0aa2f330cb41fa4fd09e8ed043489715aa779f664b26e9bf480037bac9d10bee5d60a7c9325fea861d732cd5ed755777ce71ea1adda3a3dbd86a50bf78e8f0e9bd3f9de7f9221ca7e05bed08b58d05a8a720b62da909fb0b3dab357d354017137b80b860df231dd1aeb827db3971d3b1fe492a64d04c868a5e6eace1cc83c6d12c5a5b0b945eb31a12a51b687abb224fe655311f39b916c9700c876cf7ee89b3c4b17864d718ad6e16ac64ca700cc05871bf8df9db130e8e81705ca75f8a1eeb46107c33415e4519c0cc1e394320f4c9b221d726d0f1113b85940eea2a4f0c6d2dd75f2d6419c93488dbaca98768d8a785e57f9b5f494310843fe8a01932e09a81b5b49f063ee23881363e995abc7f1492d2ac2b1d78916e6cdb85f6d86c2c3f0e8786030df5ff815c427086da518b7d605460fc6e5d9f6ad85c7a620fced9436b1941c577b1e7d6b6aa9773586e45b4e1eda0101c11de61edfba21e194ec5252a5e3ccf4431ca44de7a3b858821b3215e45758d478eed47a4113c8291fdcad9a408486dbca9b20de4e305453e23abd86728971530a254d00ca4fcf00f8c26fdb4ae54af7ba63d7af09e1a3ee77959391e392f1076f174ffef806ec0f9f3b7f2d3d3ee539afe547d395804b0f9bff698c74e1c05574d8f9610b9ee82b4ef819a6c5fc797b3697c5697e8cdd639b067d778847141c7069d281518032550cfc5b35a546600e9afe7ee02ba3e53122c8415d6ab369e3ad65e7b8094c4deff9c8058cd7a65da7572f7bf72473e08d1b8ba725fbb3e2c3cdc29540f83008474175eacc4d9631fc033aaa4640cfdb95d5e8b1f02df3997513a76c27c531f5ad5edfc68fc54818c9999f5588d812c74f5340e7cd620cc8669ae3237892e58d87cd2193ce6f0b6020b8f52db3876c9c3190693df9950c7949dc4b92edee0735165d8d9769eaa291657cfadec22d7ada37992ea4e4d7b6682e4b90511411cd79671779521d888c117213e0034b1c8f3394edad0863aae55abc1eac214d72a8599274f8725870408241cd2bc8e16bc77b6204dbbee6ffce760c58d15ad19654b7fcc439deccd5489d04e371bd54c6cacd1068cc2ae06511039feb807692b0827eb80756a3d3e05e30ce38fb4dea573fcc81d457e5b5dc21de7072653efafac42ffc88cbc9208b48849545ef7165782cd6798d223d0e2c2b48268518b52c53474b06fc25c6575a26e5d44d533abc46e997b9bfb0ee4d5114dbf51bacd8a57911096b7919ae82364769d7d66ed6c85b691679021e6ed029d32630c087034e2aad9a0205c08616c4b5fbb74a050f43e32b1f74297943e3a05fba0da7dcfd2dd8a9e100ff6fde73406f6bc2b11679f8c744ae95a490d9be259623d9dfaf2c672a7c9f89dd726a3b4646cca69079229ffd146207455eaed571b11614875bdd79c614332ccd8a3170311987a2db725587ec62314964a00b0fb3176ba2fb7209163e092d0fda9c8781aa894e5972935a966b8bd0cbc2f7a86955358e9919053347135f29406fbfa772ac7d56e0a44b50dba3d2eb03d872b5617c7a35500ab68357cb54cd67bbce3270c63316dfc25d604ced68d0ee4ae168202791ae7de1224b2517ee9914e80f5c480c4400ae29414df2b136c04bc5d70e84b6fe87e6d93c957f4a20799c6b9030d1677dc027ef993948f2f3564a1c137f944a190fd687f454fe9957696566caab084da5122ad061558a2006877b285dd493f3aac6782ce9d0e6fa40b27d7f2c015fb030dcd20a7e54b7c7c4ab0562a787f4f1c6fb36893bbdad2e6046d9be9cf720efb9bb946a8c3fa7a7bc9f9287e204407662810c93e69aea8677df1390d5157232bfe9a4de21cb94bff16a631cb63a1e6b35be2f7a1ffd9a5a18f4578840f358f01a9c10582dbbdbe336e6b8401654d7a193defdbbf2dfbfac60c3b83c18390da266c70d746c6c596d87cd91381e52d6d4d52a4667804a6082d3a645a22094d60a0b0603c142a28d031e79d96beede1d6a1f85d96fcc55118b053e559bc7ba56411383a91cd4a6b2adf9887145f8a269408e39082e204bb46953ccf7c1a10605802f1c13181c856d30922ff7c2c66213f690c0d1be15fe22342d7e07ac9b27bace5942321cc56acab7bf3b2b39be8f644a75923b375f0f3d606d2733f6fe9be123c6bec1e66c80e7b812863cd1725e2bb9493b48c5110d28b15e0a9ffc98a47058e0601134f8f6aa5678e708f1456a73c15e17c0bdce28d99b11f40a36ae8c6c3f6ae69cf5fe3a89f3cb533749212227d3a2ce3bcd4f36437ba65d6c46bcb4456110560030a6e893b0294e45db803664412a5cc97e0a3dcbbd018242d2aa1d59822e51cc8d83a0b5e61f3f7bfc01c6d7880e29f2b9ee11f41f23822f3270520666e90969a89490c773936cf14044be0949ebeb0f4179a3c1ac97aee5b4c3b2a6ae33e24f4891e49cf2da8d3a83dfbecc9e74a8be349a416d124cc742257f73121aec11afe9e36ea8e442d43968b0cc68596ad9a869229513b1f7d32943f6aa2097a8234bce4ea6b55e0f9507d6848a33fec0d85d88e9d80532af58b4479c9853cc571ad1f0cd2c81018e2bae8ded0ee9fbcfd87b356b2d50c73961a51a5d8a54e094b3422736f45ff3443cdd45ccc63db3d1c2aac18c5f0191043e98841f6f195cd9fad526847a93f65e9dcc3d473b8a50cc6eb5f210718510ec5916a67ec50b155899beade39d7cefe020c3e19e14b44d1ef6257d8ca94ad40f0d0c666f166db2ac69dc29a51a0d40fe1ad385626250e827dc7a50553509d648ac8fe6cd12b81f74942b3aefc159aaf8ef761e5e5098397cd9b0235b79d6909dd410a7df0046553a72d3aa779b3bcc78cd5414a83ff740aef7432d58c25e49d745c26aca4be3547c69e88b0a822b70f82206094e6ba3aba832e15ac7479748edab8e6532f11b5e34ffe24d8a19f572dc89d3e0c76a232eece6f84a9a4baa66d4e2381d1cc3d4d7f7ae88981ddb42572758fc6b5d2be4c2550cd493ee6733c09c31ef5247bf362c54d6566b35d0946a36d3c60aadaaeabcece717aa1d36bc0c6b909656774a8cca467be890570ed7a77dc34baa5a78e731fb00639b7de919da0f9f38e9c0506b5905740b9e72860761f65be1dfb2b52b86c985eab56175465746077555e54e2aff4a35626190c68e94fa46665585e6b46bfcf1582a72e02edc9343cabf3dc39c879f2c8b7e17ba399c9cfc8b1a4ae6b2e68c0249785da45547f29a70ac93e96c8f99afcecf7f55e58530e54eee897d609c77b7bbb8ec2815366c65f51c6bbe868ef301b459390839f5c9879d8341461733d74e7b101b030e77030d08a876312789ce150b9a3514da2e152e0b03f46b5ff172c3bf8aed66d7ba0373ede92fd3e33ff1df4b90a45fb398950ac871e5ba4110af4def78b938a07932b85b4eec5cf0d6fdfa9abc8f49a7f6b178901c9c05996564bf0e758bc894a4255677b4362d268053d62f47b6ba10888ddafdcb9fca06dc2e062f73ea69398b4dee57b08d3f5cee7dfc68eca8ecaea5a714522c63d263325fddc1b5c586607f9f5da316b65693ff3f0f132248920cba70855d07de8d75645293e574cfe34fc761a6970f57096adeea13a4247a18f376845e9c2a95b8200c5e1efab9ce7077f6bdf68414d438baa5cce7da67d894c6bddf9241fd447aadd6432ebbd6c6a91cfc27413e1b1bedcfcbf84b80b5920e9ec92467c66b6c9ec7556e1fa0a3198a541d6fedd299f38b7b58629340f0e76eb6a4d9c209152ffd09aa6d479df1e791013344452c234203ea39207930977d85b03646a9c21724ac0fecef8bcc331ff3a66450b2a63320e41ba5a52a58f8e843a734fb8fd6030a3d088ca27e27784ace9c3724b0cebb1670a7e2a26bf49868ac8509afd1853bb19dc16a85b642bff2cd5e5cc46d07dacf470a22d719efe695eace15f2c5cdf7de95d2b5c29281569fd48ca727668b9e1e759c4167c5ac099400f66bd17b8b1869202407d93f575a3907f99884a2dfae98a4dc561052f38b285da04edcd51f268a11aec8c0c0f4e6468ce56c40f9bcf30af71bd757aca37c3828d1fc1f9e6738261375437bcd8b601c1a68aef3ee418e3a69758d1541477cb2a24a24c598e6e4c20448d1843e942e9956abe0b49323de8714914f1003af2c57dff8715996c10017a4bae88220a34a09c29fdfd863e16cffdeb251ba446d885c8556913a678742d88e768e401594e4c18d6dd6e567c2911b5757b425c786acce79abb5dd8de3308519a9472d1c12d5f0802b5578d24182035a089d767a8971be73e8c1247d09f0f21fde5245852281014162a4c539586b150f611f374a5ff01be27ebbc1f25122fa06123ca5b4fa96d060ce436fa1abdc76ab9417b1697ea5da2612358e45abe3f2d993c94fc09bba413351ffd2228691ab0dab591346fa6a48b6630024f695d41aa906b19bbba3502d0a119ac77df8ed88eb3e88a2640f5ed9300f6f54e65f9fb4bae190805a6cdda6f95d8650f642ecc1f5074252584e504e079af82af1233cfe66135062bf7a5d651b2477be48a4e7f5c52e12ad50c73d469343c4c5850a43c90690acc5d094346b1bf746911afe93ebe19c988aa987e809c73b69ecf8923de506f604ff847890f32176d733a554b1665edcb30766d77e68791c61727dfef5ea097d297928cf08eb7b59cce8547e3fe648fdadd13eefd8f986b60dfef6f9e6282ff97dd67acb0f4cad0af21f07eebb67eab9f49ffacae2f35b0d252f22191ec47645380e3bb3533ee6c59c42a0996511bfee384951f7b0b234404a033cde18246e481ca5c73b5e06b9fe2beaae7a5a0f614b18882d4c4db7869c460e3a63c479d1bea9a3935dfef9919b22501c3aeaac07ea8e47e6a97d996d7b2d8d1a08dd6ef567d624c2911ea1a9f197c90042bada9dca5c122e5b9541bb8133ea9cef087750732adbd0eb8ada55ed44f7ebb2f3c9ee1b2d1d0cf274ddff56445f9c6544f8f3b88fb08866fd5cced7ea8343fef3ef11619039a8a0d5704f83a5f56b2378aac93ad22a4443610047d46560e2ded5d4cdfc78b9a470aafd87e8b25efd42003c390bec6290b431ec7d025ad29da38e327b71047ef7313ea5f295d1b7b1793e43835b651928e5e28df2fd7fcbb57e0dbc19d7af7e5f1a3751493d76f1b0787fb20e2025a03897a93f17204137a5c97d6034c5ce8c99eb87bf62a646a7bb070516c8226169655cf6208a1f1fba7de2163b23a94483b3dd21f120f1356812d3ce8a916be8e25b4315871c926375800ab22865a4d0994370c79155bbd1e365c83736feaed9fadb73e1a3cb8eef3ee7c0ad7084c9f019b6a1eb25be6351fe5ee86b72296f6e104483d1ab190701f93aec82b79e73610cb55e5b5bc7286e5c6878a7251e5a9657beed6cdd62ee9c40dc8ac42d64261d7185b7a4f81f0f4b002bba17b66d2abf57c28df29ecac8c0107f68416ce67e92e7b104714a35dfee158d36b7bd663bad590f16183bed50af6b24d2aa678b8e2503a7051400b39b501600b5eb39eec3d3da41a13dbcdbf229c00a7bd3ca38ab7bd250c5fa652a6330421b59b371724cd306c546c7467dbef171c5ad8ee3ddc3c7a385a9c6b790abc9fc3fda3887cd695ce33bb385e2c69b2125cce7f2dbb402bcd360224cbb4af4b83541a1812f88f165cae3b5b3bc00a22be7c5fe3f37941aca2a72731265d48cdf15ca10e25666339c783248bccf76a4b31615ae6bbf48e17b099fbfdc320cc27698557d00d83ac68a3288f31f05a0fd2a25ed37c79d321af4d558fe998cd1c75d5499d7e245f8bc5c02c2966a52eafdb690a156271abf5237dcf77f6462d4a2e9b6bc67dcdbd6468f9beed97d6e5679a600fc7cb9b4d8051774be27d2b7b86761f6d531935584b74b79a38f4c1fc2b1370a508bbba36d08cc190a7553b223cf2a3b70986f81b78b64b9f67d4f6465a63c4c4fd975e511d31cf7f82be0b07c80833a5c81d35bb3d72c0cca547339bb77fc09f69db3ddf5f0f7ab473b9ef4d50398e45d67b1bac5d2614c8ee8aecfb242565aa5d20e04be9ed2d8a80e205521de7ac348ff0fad4b9f9354148b66d5a166cd835577104c2a60356ae253a706dec6c1d389f6635eed1ea78881566cac2768b942db3710d5331167f4d504a3d98e38168283093c32f2363dd13994d0c62d8c396daf43598327a4fb3e42fc1fa53890c6d69a24d19be6e51108d5a2e6d707ec12a77065420550573a29bf14e1c664779a49ac3809f930e5d30aed4a7355925df2a04dec4786593639ebfcc419e3f788df8bdaae8c535e9a6cc93eed429c9d049bd5381cb4cc345da0b2452162d023ca692a13cd8f6b56185501e2f84220dd707cfdb9b131c1445dc8e868c522969f96aec6c066d7acf35fd23ce102b13aa2398c5c1f28c9844df0bdf75bde589ebbf6e7cf9dbbfe09016615d92bb44d5c2d84da89ff309d7c34f684fc434cb9d89526a33345bbef0f93a2acbab82c572a92274397732f38ea42a34c4660513053f112406f9c31b7f05b51d276786cb3eb3207e199c71dcbdee034e7f7049180e4d59804c1f2dee08e5e54ec9742d65395ba221f10e79b7f853c7fbcd134623211af658489a2c71101d86ae51ecc94dc92e7400ba0a29046376bbef24888233c7a886b356cdb00cd126047f566e881f9a0766b9059de22cf8b234a87edd2069da4d0a530dd9e244a6bb97ea23e2bdb10d6469b91b2c4efa1723668f35c1832f4440bd9f03093cbca457c4928d0c052bb3e39a4e6cd2fddc92bb2ff36f161d5d98ffe8ba37428d93d6312a23d8b3f4332d167675324c3a8d9bf62e44a0e6155ff5521db08f3cb9e38b26f83a614d2a86ce36d283a73af04cb97b32e277c755dc4c4342a5e4c242b8063e867068c9889a347a0e935e9094b72556cd52d1e4e200eb02249dfafd243e54181dd7fc6cb818bc3cb889b46114c4cace7c74398717ffca13befeee2b334700bcb28c1f79a4b4a1445687a4000f826694ac209d2381402e6cf2a1db90e353fd5e57e35b9b265621afb15e874d95a1fceadc331d93b049e46ce50900a60c23532a9a416b3246ddf8b1742648f8da54061417ecf175ff95f0cf515b7724d321313cdcdbccb4b236618feaf193ed9bc317054908818060693985870b09520d05e895c4aa63e4a3c8952088a9027e17570c84e6aeec7ffb5e7b29e36848eb54d7694bdb313ece55f2d349c3c14e0883f2273beaf108702cfc56ae75ad61d5a37461ed0eb171fe458a02bc7a4c7ac50987a4d55edf1cf021b097267d2ada8b3ea4cb1908f920acd9ff0e1603e6542b6354b21ce0efc59b06153310af0c0c5c7105e0376d35c2af1e8ba3a6adb7e8b54d6cc5dacb4b4f29922ecb87ebd1f5143d9dac5c146ae111dd6178c032984788c72f89b11fc199e68c140decbcd7878b3c035d78d4e4ec86e93967af215c1f34216fba871f7b65de5382c7f7c6093846513a0669e726a8607c5210c5973a275b5307e882d4e29debacc02b2703e393d870fe9ccfa950fa70c1837d4c155dd5502aed7b92325735dc223074fdc8790d258ed31345a6416d7dd08fd10c246c0e48d4d207268ebbdcbe202b3cb2fd5c5739dc711a39e23abcb057458768465fe169bb12f22ce9bbde0222f81e7658259f60e8caf4e0068926a086b90be235c9d8ef231ccb37ddfed67f71e9b59aeced1a0692aed84da71bac9d8c7bc2c9693e2a480ba2d10ef5aad3e21cceac3c2ca83dcafb50f0d3e708e1a6d13de281a2a380cc935aa7d9036345f8448bf0cd4939293997f7a1b47f2999d108120c6c61f960ec85ad4e89492ce5a8c507a8a3b27957397033afb48bf4ad29f7601024b7e09e35d4e7165ebe8933c1674464df2ded0d8a604e1b3050f84388063a9a8aecc8e4146c0da3ae98fa94e787609317f404de6a1c5749533b8514d5c83776a5e419a7f75e12b9f5046d72c143d1328b42d2d62fb36ad02da10fe48ae4451d36b674bffc938a8248ce173ef44e469bb70f5de6f090fe5cf030e873705a1e2b05e763446339991da4e2334542be18c177d87ad5508a1d0422e19a4a7f5d37929a837d875ea8414d399b5344fcba92fc088ab26f33172e15ac57fe6b7b29f61d5a65e82c895678f200d9c40864611ec52258c2d25b13db5955f51a6897b790815464949e6e23aaa95e7ad0ca3601577eb8ead80c14d1637149ca29bfaa430c03f2661ff29afb96557080fdd09789589b8ae8a8ba0cc426d2d3195dfde6aa93e529cce795599c862268d707b40109ddd06547d28443d4ce7349b36a09a8739d3b7de6aa856fd4e21d55bdf81b2f4361d33a267fee6ed967492f38c385911bea889cf1db8e317f556add0b1245e1331ec02e0703e558085b90fd14de613df8440d33443b21b3f524a06c6b03d366c81d4354ef6703cabedf35cf932a203fa6dc2ed578766a9c9291eb300593a15623f43ca00e7df97c3a8e6b675d7ec1936d0c62fd001d65838b8ba14d94fc9028983d22798062e5eed49d5e407f71fa7dc9f9e04d7521aee08fab7542defcf65b2c3fab8125f4466044a3d3b94959ac542a6717f6f75af31809d217eb3f60c200bc54c1de971455f563835d38e5579d714924579db3faf2fd0615ea7727ea69edc9f4d4b41003bf863e0e3fdb0b30f0d585b0140e013661c51f54523ab620d477fda6c63c7b7d14d52859a1a662e72e002e7235f24c06ac1b9c52106f61e4b4dababfc085416182462cce175016a9c93578debd50d34ee26087f3d13644e659e82e61faa9197d68ff7051a61935a046a1810fa9ec93c6bf8532c1b1fb4d14d09a8d4b81de642f61a09ec7139d358a43ac5bf96676c414174fca16a10058944200920a97dee41eaa9751d6d076d9c64a15780afbc5a1c4c6c375e6d0f4bb1da6d82552d4fa21da5f83fb85ae5ee113c1824868115c3a38a2c9eb7c3b681295e8be9d9291a4f068b2d07ab9943fc579e4d1b66806d00e8a0e909a2ca420771c794e2fd1ca4102f6fd9d67121840cf9a7e253b18aabe4acd325a8306acbea4e393d45c9aec688be06dee3d6176b72f62035af83fe52fc5b84c97e420c775cacf25a0fc6651c22bbeae703b4a00e14cbeb3c52c95322357611031df86e6f3b4f1c26dc2d3f28c587b10824b3a0127aa4c7c381e5c3b8a275c300fb2cf2e5937ae3aa0d5393a3e7ef45a7fb452988bb9766b1d931a96519f7fa9b511bbeea4bf21419407b26c46e89bb4e7e877756346ea0ae65262b67df74459ef0acafc9dfaebb0703d480d289d75b4342ec167d46edc4c3e7fbf7796bfe2d30b1c782f4f20139e2cb1ef25fd27a3ae4340c911ef0946c0c618bf995267cd8f83a23a29695b7366257433c472c40da5bd6559382424b95cd37e14a29b5066839dc01a6110a7f634acd65560b49e66b00d10f600121807e16d1808d545d38fd2e05a92ac2eafe2da40a14b6b5e1b3148959bb5c84860fa5101df7c0a3f462afbc71a5da67495a99f5ea2ff694f854971704875521763735ea8aedc473d56ae75bf56087801fa6461f52b426449efd7beb75ee4a1d35268dbff3f1bf799cf5647ac2b9f152aabbba87b2c30eb99fef1b783fa096fca792051fc39f6064bdb1162aa54918af76041216e7706e3837dc8fd12aba9c4a920e43d4141def6e5c8325b9a99a755669f85c89474925b7886ae0bd11f44a04676ff26c19fc23039a7ed983d11bc40010dad9bb010ff4487c8df723c41ac174c89cce31ede9940b3390dc36ae1d54d0a6de038afd88cd75f61b618e24866d784562ef0684f6dcc4ede6cf9d2580129f064b67b120d5e28d56297fecc7f10635fb86a66b9cafcce0ff352275543dd54b139f9d8b77b7daa27ebdda0772aaa1ed11bc64bf3ef938456c73cdb0dbc7a8c280933417d78378b73ec269c394a3a6025c42c2a181a5a0e47e43cd0d82c4406313685e77187857f22e4f50b6f58ea56c776172d55cbde4eb6caee59217f675a6730e6612d1bfcf0e621e700610f2c47e3f2ea8f60d9f65989324bc1bd241d18ffac63962aa99dfd4ceb7649be2e80e0d09ef9957842adbda9056502cc304ec694c3f9a3351af975722ae03eb5977f33a50e3f6fa6d87267f3675a79d1c40fa889cface432a93c9b7fbd1f158668ee6d7b797269694e4d8cebd84fb22c1709884d5a99f78d21b2b4d504821e49ffd399db47639d0039bb3051d1b751dd72039c18ddeab4e2178e480c52c100de4a3245b6ab679e006125b37066a7f5711429feacfca88f60b046552cf97b7a026713312a3bddb1a95937b6c1763ab96874c82e5d2ff1771518750bd650500e9e0e80b93668af13c9eaf46bbd511f89d12809bae11370e3189fadfef88c9704fe06d67fe884fa3c6fba3947ba58ce7d10c15ec5463b943b40e003ebac38b148e391807ef8c75b748038423f783b3f29d60535b34eedba2571ba2efea9e6d283bc0534b074987ceceb9747315a15f4f29843461a018a88315d36de888604c8cda12005285d75468636f527798aa221a546098fc9fc066a06dbb482790c48eb4f3028697da1898d2ce5771ecae182f3d1886c613323c67552bc2a6e128c05141e2dec40bff965e32436a1b91972a1f7bc5709b5199c51977a565af3edd6b59a708fd0622388a1740f96b6c491667f8ebe2b3d57bd56749b2217b895440b46a34f8cba28a7cb1274bff8aea7ca10a0232547db948385cb616645f773030d4b15cd817ac081bdcb4d2d128a83018ed6917d31324f4b9cb630a2d8d04070cd455676d52f4dff949de5ed33614e24332e7eb1c8e7b22d26294f39937376058374981e377191f3c72aa519e04daf31e4e04ea6d7669ba9a220d5b5acfe41f646e21158dc127b2068eb7badb250524aad4866226ddd6441275fa94ba70d821fd6df6ffe7bbffddc2f076e66dbd71ec9f656aaf4a8630442b27857d95eac92f4570bf22f4b1ebf403bf686c44362f5fbc6f72c5ca2fb8b38d5e5c99457005a218ef9e6ec5d4a3e2be8342b4467af9dee1327c9c4ed02602743008619adea1782bad528d0aea8493e0ef0b7784051cb742a84f934c1809fbfd43d3d694b5d5071551977d1a9f2414950e37bf6222525536dfbb63980db1899f9009485e056dc7deac6fb49af657a297657fb56af739166b7139e8347ae7e43b706e674505f006228ce39b7397882cd4d5720f4ce98e378e88740879b6973199c7a4dbf2c0660db8a1650eadf1c4c636a3e761778bc305677bb3213aeec107a941db5adafc45e83869f9a4db2701389d8d67b4160e95fad0a29d7354ea5247b4a1fe25de3fce1708e8ffa27bfa3476eb6fce2b807f681a0f0ea0398a323e6258329e47e561614062be9f7b7c629b9cf668e3190591013a55a9b18ae190b4f267b4acc5a7bfda5d80e0564b20bde672f387d2597d58a9e10e557c7979b5a1fc256a06484e1b593fbd6e8863fc9862ec4951247daac2ed630276f077bb62a90a3114fb2381b0d06fbc9261a037426474b1d1c450837c350a83dd27e66b01a84dbd2053b91c3d01950708b8f5e45b7f27d10a7af753da1ba8a832ea17057964e60223bb00c2b19177b9db2b462799fd4b7f57b5d2663f47174e85a507313d38f85a2ceddbeef870dd12c82ad45f850444a54d33a3c61b472b45fdfb26e18e4ef91616ce1ce552910d52f95b62fe8efe1eb7269af8d310093e823254655822ff2870bc9a8ee26c9a6ba9936919227dc213fda7d12eacc6ebe417660933ee1200ca57b4eadd873c6f69aed4773957baa5dd86f4d05922eef582e5463178ab954a7b2ee1c63f8f674a7e8bf0fd459b458131ef78ab13110ce70cb78e2bba477ef4855b3d783158f95bbd5069892df0d04e564900998f1c11ed78d4f9c13b4dd783e029446753dbac2ad5dfc41c9c383fd247f1a2e208189bf6cc3eb1afcb1bfa83ec9a120a2c99fb334ab832e508d970860a30ed4984eacf36373df6d3f4d22bb9868d6a1b751a2adabec7133168a70e88ce5de0c0503d3011f83d558441e66fed1d6588af8816698fd9f48b79c91efcc1b2943bf4c36eab88d9f29b6842528b7cb8b75b212b928c96f4460f5d79163389c3ac525fcf90320cf14cd67ac1d77680b099c5ba1d3a29285f453e1dca3013fc1875a140299e922046bef168a66492bd6d9c7c34917818f93fcde21e726d756148ec30956b1869d8c032ef0d0f91e886bd2aade62b4249ba2925db13353c83adb8d7af76fcdf612c9d48deafa7d999a1035a13c2e2adeaa3ab46a5b5ed43d74103b7da54d1f5d6f3aaed7e78f67816c447e33dd71061a73a152731428a212d70126d98a816307bd398f23cb3fce56d25b38fb77873c109125d4ccb66ab8efa049d24309e1c976fa77aea82e43ab5a8789d33b517676fd61905e31a7e1237318283c41196b0e86be8cc2756d8b3bf43fde1a705a07f27a1201478acf9709d14c3d98e914176247c4c2a104ab7424155ca743674c4f0c126f8e0f7097550f8c1d3b82bbed1b8e7c323bf79d8c698d8692bd83809e75217253594113e28d4132de0f0532b9d030b35e6a583a9974cf9fffeb1b4f07616f84bb228ffea5b96a90c2ae0f42bdd34f6b8b0642c21ed2d64f761cb51c56906a371be0815a052aa6d2737b7343020a4c9c57cfd2f96aa100f5d44bf0eaaf92518da4e1fe542115e17a685ad520f4d03796f51ce2e7aa2db42bfd2a8f0d5c13062dbd5821f52c927654f2c1b3690d78b10b19da4af1cb98eb66232d067b585e774b1b67a01a7eae01cd3b1bf0f10a24a86f2e1c4bbf10a378c02d9da05fa549406a1b31e1221591c11a259aa207ce4180fbd9d55bde6b7557d251d3284931082d3e0ae4641c7a2ca2c13735ef8b11c8b59440716b87fef8b814894002b9a587e63c2b55b4e72be42f039d608f9d5981484c523362ef8ee78a97fd5348fc179d574000506c0c5dab36e6d7637c187243d203d53d752cdfca7bb948e82bbef3efa8d0ef30d3065017b95e6869b2e4ef96839086bf120ba815c5c183ce35e7f65843fb290c6d59f0b4b071f0aae36218baa2437d729a892358a795ed98cb4e6a5577d8977d4ed61fcb98aeb36a9ca592e5aeb58108c39cfe86d0bed018aca880e3966e69230da6918635f54390e1de5c6219adf932a44600cf502335e6306e550dd605663451c0fef9bd8b9029a57b1025dc8a2dfedbcfe4cc49471325f26bea3070f8bb9c043b5c88d8d542dd8647d595965cb3c02e6278866fc5fec532dea6fc0c4ecbc0e2ff83bf5ee13140435b26dea83dd4372f317d26f6a49facf0f03d4dea98afdb02955b20f421b3ccacd3e41513ef035b9b27de2b282507c45bc17657ab3950840d551e372ecf1730d7ff534e87af627e7c42a89711a9425deeed1b62ec181d20725267b1c035950c67d93b291d87fb78e5153829a66d1608789079c322c9c2b6ab5310209b206818609b105ccbc94885685331719bd0a579ac30de14c9736a079482d9939d981f88410a41ac104a44851e34f872fa2ff35a1a0562e368cafc3a102636b9c922795fe35456d65f10605bbf3a46ca467ab973913a20afbde98aea023c21fd9c200871bf6bacdea748e49488e11752a4af0ebad722c1b50342aa34bff5fb49ddb4365c37c7315ed93a5a0c027e8445f78fbd32380422021b31ee74c818c15d6383d825eb8d987d11fee4d053eeadaf362e059f1fec7290d2a2170abed5165b39cf97ee669eb49c35f745145019959513624305cceac57b34fb75a76e6803e3ed34ef17750088eaf991cd8f8959434ed039a70b4ca5751dd858bb8e036b237a8e97d74cf892c4d7ab14266b275d32926b72d10aee4ec2b7eda8c9bd7fab17926ba3ba2016f20cc471a2ef814963891347ee4cdd241aa663b87ec3b6b3948599688f0c351085b22f8a3d16c644b8b5935bc9e9537af03921d069a81d7d8124d78023341803f339d691e5f2f4cad8838b059ad8303c0325f371c718ce8a36cefacd723ef6046d3b1cdb114551d63f125b310ba1dc944ecd927ec185a57797138852a98590794fc3973d354f00d7569f388a8a8f071a9fdc8dc32fc0c8af6f21c7e664261afef489c0a8ded9b7c142d7519cb099f92751417fd6a9cfff8d5da27b29f79c9a3d5ce0342177aaac3cc1a387593f8af9d22813c1ccf9e637c97a3eb6b71aa299b4357db56aa34bef79451b83b144eff4f5e1bdcc05eafa34fb63e2909ca5fabbc2c7588ffd3588a9caa49aef09a1325becac09c6b9e651a29a20cd842251ed4e16684876eec0a225604f2202478fadd0bf9079bdf4badc374cb63c3954c57efadbc2546a193806812cbcb14235fb3bb447790193df03ede2b449d75ae232aa49c8dd840bf63b3504213d96dd4ea8219d21e156a728450f59afeea61ec662c60b73d41cc21425f39be75db3856fdbb52a464e5dd1c88f3fbda65a0950703261089f184e8870fa3349d8fa71b5c1bf3e394018a589560fbb3c2431edeef9662e85b2541ca4e5f26adf8c9e0df308198dfa5a649f62545a3f585f8445d23f61ac7967af05deb7c36a60cdb0a510c790f10b58a76533b3c445cca763585c1c7c1eed91ea4624feecc5c82c750b3519e5a2de08b5478d51bb82cfd5a527b06855fb375a5fabb0e6afe35de4d4415a20369575d51310e1e2fca01f417ddbb8d1eacc87b48beeef1511c9e042c18a76cb6c10c4df217f973afbe353d7944efa5f2079af708406ac2f7838fa0cf43ab21cf0b691417a89bbd464a4eb8ba450e9651fb275c99cc6b69512182bbbe9fb870eecaf69723c94c3aa9726fad731511c07db7d1de73182637788eccb6747a1c2461977c14520f29302a819e34240be53f6c7edfa43cc706821474b6f05cb6462b69957c2170a2c760e7dfad74af7f36e8afdc2e88a3a0178b0358311febaa02838da53dd750c86a48ab351af7cc1c87a7e8eba18e15a946b04f9fc5aca6f9abe4740f810382fb3b48cd57df94ca6ebaac17b1c6e7125cc8e9bf640fa10540e1f60e9c8d9fda93ce68cdea431c85ddf03cc5dd25f7f5d26bd51ddafc9729d26598e2de167333ddc7f7057299b4ad6df72766f3ce64b925b4a94f911b102ae363c850002684e424ce035bd8d49afb8e8f5aeaa26498a3e5822a28588d3efbcdb21859fd909561e4c7efc36c72fd2a03c9bed6563f9e44ea2c34acc5d18e13f28dda0a32b06a2a0e4da77accf09384c46014603d1df28b36bcf3a71e25cfbb9be6c934af40b7f5240819cf99fdb11d91df9a7cd92fe40ac48c73f0bec96d451c244c66f7614af51c48e1da3a0f30e5b8cbc590bf53f65f64ce39b8ba407d95a948fac9909ff72e9af58d362bb23a26ef3a41d620bf3692f010f9c3cfe2aacffa4e1f1625bbcbcc636d526585677e0b59bd00af2a09a30c97bb79a1ad2aad0b719dada27430a585d0c210a9adecb28adaf8c8d302e61cdb5a9a961833b54ca6d5deeeed31e123b852ae5c232cc21adf50f6fa649d30b49b9fbf461ce9f3d064ebbd444df0ca9115ef8af44de2e1bbf938ef40754aef4fcd023b59f9dcfec0242702ceb3b013cc294a211f70af29757c4ab95346f3239226acfe7a8f85472c5cf70d2840a5bec2c4e1cd5ffc6fca66847b9b3f8cb8b6dcd844cc685fe248da6ebafecce9a603346bb8d314069bb2767a1177e6a20700e377088ed99c1e468b863b0fe53d0066138f7898153613698d05f86ac9835f3cbe5b4c2f6d31b9cd4ad38960262f8721ba298e59e597a4b783d6b78331a33544907e8c31e86b0e4d061e93076376192ad7d316c1a0e3773c3333152d3c5321771fafa8c4c19224fac7101a1152a9ad0858c0b26ee4056b5d8242cf05f7ef17edf9cf4014ae68a015d12d8c81820fad7e0426b72ded86f71755b48ecadd8d7d861ac4497c7aa50bf3613efc5202be3d4be28cf2fa48299810079cc006f7529815d8f70a1c34ae8aaa4354d6266d42114945b44270778a5821bc13143d6100c34b422902c8657ec9b24cff737f51e9353b1cca34910cb5d353feb15cd9affc42568d16a74f8442c03e445f8f6fa18a1be30b69dbe9263367a96d455f1eea9d79fb6d4156129f7d432ff28b82b3ae15d9ea1c914ab7f84a363bfcf993d685c715a63703b6080917307c607be60ff7bf9d2a48122f169e0bbc8d3df48985488073616d7b8375a89afea8b752a99addb44ecf19f4c8c991d85568d3b6d046c48590516350af11f1c43f8e8a4141ed184c8f9fa008ff4f992352424beb33b93ab843d14708f5b749ff55c777ffa1ee8f33f73c82aaf4e80e4f1d321b5697e63c35931992e74c132fa34c29e4cb1dc8590b6a8e28063cf07bafc8d1759cdc6cc8ffaf5974cbfb109fe013353bb7c4287031b782fa0ae7c0611e85ab48bda59237ace2eb62880111235f5779e8f03b6c9cfa0a3fa1f890894ee5e65368eee027ed189ea520eae6a70130ed5f918061b9267f0fcbaebb7ff063275ba1850095273ce90f2f3978e62bb698c4f8b90f548e6bb72552ea823c9c7b6cb08888353a4748c50d34ed8edb842e42ef0790b5448a5755a87d8b1a2810826a39ca4320db97d394641f3ba6dd317f15a2aab23244478f27af39421f77e75613ebfd87a01e39f16e7931135928201a027dce8c84e2427d42e06f5a95fd5c1605e752baa0461f519825ab1c20948f2b24e5fb03d14bed1a2eb1308b040e19dd689b989cb69e2ce9cceebed7640bf9bd219c57ad76243d2f76be1a6e12c7a234b2c1831f75974ded7490bfc6982391fb599ca10b0b8dd37858837218f9f4cffa12e690594e6f347cdfec7b9a0ad1241c9f2647d301da6947d913e56f9f6c2c55251077a14d5a81896ba2e25f0196a65c53df091547a75eed960ecc8816a1cb9d189e3f5006c88961ea31c9fd5e57f8e8d8573d9791bfa261d9bdfcc76e98594a05a34d871798e64d619edb7aee5827d981aaa8abfcdbdd27bbcfcd479bc249083f43af78faa8cd37c3f09869b1a6c5b10a009d29ec9b51e4043cd483a3f47a016c2b898b22d475500f7653883d46cab6211d760ff2d691e7114834ff91610755e0ce469fd5486919beef81ceed9a2acdd0e075901c62ef55329ee536a118273e9ab276582e3a99b8476324f721441142d0b8554ad0a9aaf356646ea6a80fe5903ef3f554efa967548f2edbf94aa39f416875303c0a0104f23b397bf64bf47b6683b478a813a5c77eaa985f3116e17ca94292d7e61ee222120180e98c6663a6015142a4487f37e7a00e755e8170facdcd9c3cc0e6fb43d185340df4661351c666f659b43b6f72cca8d41eac965e4f094f8d3dcee87304abf9fbc7f6e8c78e7f4f2979b8002a571220c0e3d665edce46eb36b4e6c4d72665785551b6150a08e8d65a18aa9416078df18200b2e979a131b26b976c2d1927788db44e5e2fdcdcfe67826e3eaa622d088c952be6b5b392a70531b830904226525273012e4e583f469623ee3e1303d5e8fbc0072d2217cfcb4ef69957b2520e9456d838799f8465386e27b0324dc1cbd43649963f1abedde61bd03c65d95c9bdfbd64805ca747f9562dc410287014f3701d5185df4231d48004522f7fefbc68e85c4e7be4f579429f7acea29e877e845a1800e6551a1aba60b5f8e55abd2fb94430df9b157f1ccc42ae1b4be3fe278cf0613ce07e06771b795e03550a1894bbe8ac88ee57f4ab5462f9ff4d3c9e25b76eb18d49b22a255fc6fb1eb3176098f3ec4c1e23637ade6d6822fd75beb22fab9bd54556f3d50006bb802e397bb9f63762429eb0e3d024fcc744a99f4e174d2cfcf8a0bf43f9e6ed9398b7d4082465b02a8942a9c95db597fdbceaed8bff2ae556feca5c51880c8a57da6b2661016d0379c358ee3f94279499f2b0dc68f9385ad65c23f13d14007d09b01b3b40e7960950eac02a15bbf4031163983185b3ad2ed9a2154512fb2e2896c9aa51f8abbc978e21687818113843a18e9b762ea53bbbdaac41e9d9ce113bd4491644425e2102b03dd3f8ef654dc03e96bca5d503da3e3dcb73a5d7a29d1b9900712b65199493929123c6cecd4a7110c68a61db9922cbc7d9c80b980ce22c776c5e0ec479cab450430a1e8314de5ae1300fe55a855070d5090df45197cda9a84c33fc9dd9b45fc87585dbc973971ac5029df319afedfb894ad12064b2f08958acc33b8420888237139af18e426fb5de66119bd57c16a61cc059e0e53112463161618aa9c42ca7c2d9df9831dbb647f75dc13a4cb7801601a3c92443a3e8b3309a181d3eab3b03ef83d2b457945efa45dc513c8a98bef4a24238fae38e4880c89606421cd062e4366fd26e00860dd09d9a4a4a12cb4c859b00f87da3d4ed91c51c78c94273bdbbd36a44f5142a62837bdd9f382e748142f54263c121adbb414a4038f65f64aecf7f0ab73076f55a01d132b1fe59047772bdbffa8909ff3828632829a1966dc8bcf796d888a3c0a9c24a67643b92f1b45eb129204c6ca0e5a36e73484e54a2d328992eb479009725aa85d7ce18b47d5122024527561e147a28b397759caeeb12e5eaa635e44e80c66672973c2caae3c4fa25cc969b6aa57aa3d49c16c5acd3d81fb3fec7f84098026b6adae6013f13d0c88a7ce422be409ceefca7267fdc4766f68b4c42228e0128e14057e8876c34aca032e97b11d0a8c2347af5a20dab8db068cd05faaee3a041c3f995bc64022e0613298d1d93ff404760c38352d4234593e3b7a1e620b3130ef636d42ca46a6980ee0d097a50056a2555cdbe5e8afe54e2f403557019c138048db20ff1ce98c3cdb79b20e637d23b59bcf43826792e93d046789cffeee0065e303944f60a1ab6d421a11f191fb1d30d062c29207dbbac74203948e793cb99a38aae927aa1d3761a570e59f8356ca77bac80d361a2cb33ec201990b40fa8c7a3df5c6f1b223323cd0ad1d18e651ac7d7c62be5dbb3dfab1266db3965b3acdb773acc9053a2e4aa814f0d346f5e0c4792932a5c86117eebe1518dea5e315214314130c4d54bf01692631e2f4a850b65e6f6b82803eb167086bf76b35ae374803a3da995d170dd3531a7a57438a82aac36c6e9bfa4666a5ace16e16b04b94cc7067e127ea4f78a29633eacf2332e2d1598091f4dc03d7291f37f74303138cc848bf87a6f15ead4d3a27e4dce3a4256e7873a19082127d5ffe0e7d40e02c5d3b6211b5941d8c035a1ee591f0675718d52106077f9a85ce8d6973cce092414011b5ab624532c47419a3b649024d2cb5b08d87cdeeb400d70bfccc597c2b788c05e1317d9e594d69517a05d088b0e2251dffc203a38a61749c243aaf64de969ecc25aba2f83e67f0a97b323941b87bb9b55864e8d650e4ce93781422019d87241f1066e9d4fc5a5059d98dd585f0af1b651c49f113b7e024ab720084f15873c1f79601323a8ad64a399bed3349f02640efa7adb2e35ced470f89c7901176169b55021a600fe2c22008fa18642a374daa9c90c5097369e66ddd19a34dae2ce679e8742b4f2c2bc1a8e531c3444aafc97913642108fc558d296bb47266da539935c80efae41fefe365ef1cfe0649208d001b21b27aae9ad0321d7cb0f49b9c0ad4314c6139c77fc8ca22bf942adad2c585e36d16e052ad6f89817a36bff6f3d67444dc8ef4426befc87c5fefb736e933266c5c309bf5c1e5c3226d8d10c8ac82a60a80445bd10397b917f9c7ce9df38f552b3dd11ed3a66e0ddcdeac2794501f05d0d8b3b20594410af80258f067deb858c700a3518c36506756b599723012389b2d78f70364aea0028ca27de5b671015b6c2236d3ac25341d009520dc5e595095d5375cde9027d0992aa19261c3f9164ce69b392793aaad12237fa117cace6e61ce1786201c61904bb33507cae2016efb0d1f0db6bc87471400715608ffe62a0c6c11b7b53a11ad0ef438afa9d3f6bfac593c957594c12edcb43eb9eaf227bfe8f875cd83458e754927579fc0d1be64d2adde36a351fdc65bda1711067be790bb39eccbe8d9e09f2732947b09bae32b03357fcbfe49408107fc5ab736fdba2c3487b333cfd290007723b704159683aadcd76febb44a7d67138d66d7192637d1dad8a8e04702fdedba8afffd42f0af3df6d556a6df604dc8979604aa1c33ccaa3279b45a2dcd593ccec1732948fd6aba42fb5f4c2193a607c48e20886a6926d69249c066f413b0abb207c78c6b237fe24415a59bbb0e2a4c9bf701206256299189c5a7f5299e8ac8ea4a5a4cc639717fb10c42af8bc4280d8ee4566bebcf0533c37744090ec41f15ef7d2035ce6b1f9d3445331fb0a76631ce86e346e90b47833428fab94d9648629829c706ecbbee500483c5cfc7e8e643b572edb7e74ff17441ae67524921e08375fc85932f14d73c5fc59d74579de34b129c7252c24ec4a1a63f1082cde03c04862aaa30ecba6e3de165db8cd171b65010b1366eb1bed0bcab413a5506d1f5c38a934751c7021eeadcc8ded3c7a98e13a8b950d554a40af124a313445818b0ffa3bcce0394d8774b37e9187c568853177037a73f10b51ab794415e866b3e451a30c22518622439448c152297d1967e8305c9b53243c5a612da9f913017b6c8cc7b94b36b724cf32629de4c8a5047d402705a0fcad93581fba7c53a28d11a1d8b4ad8e22785176faadc8bc744235206210c5dcccaaf3300b4b27819d5ebd1a0cd021e156c8fa983db7d291299fe568594c972390d901f48005f3b83212165344698df5d926bd32dcaed096141153a7aaa4aab6a1e4fd5dbe5bd582b38dc9a7528ef73a5fa9875c269182bc4b46bb6760548840e0c49aa0d6676f626dc672dfe5c455fcec5ab6c4635239aefb0eec3496158378ce7e468d4f7144bb266e47b8cb8d4ffd6e3dc59b9d80058f4bf49fe26636b965aea586e5204b94d13461e805b5d8b81a7eeae7ea886485d8be0dc7d8adf7e281ae243ecd456f8f7c37a9844839894deb38f28e397f4733a21dc4e2caafce80bb4933cd04c51aa411c48d28c48101042b86f3b59f4b7493315004dce37077c56ec13af081a2962c8279525768f7594f77b901aa5e18d981ba343f4b62abd623afdb113b7467293e4d95a8316b4ce4bfe447feaf9ed880c9245eeb443d1f556ba099f2a539be415ac21d50179f743a27c88d93f17c5e6ea63e2e31932cb9a7c2f1fbb548ef37c44ff5680b69f08680377d7f0083e2ddb3c46ede8bb4fb26f198d79715048366734e04fb65ca9e0e04e29d94dd9ec74dcc6822236c331ace175912383ad15e61369bdc1a8aa1c38e07f212e480e7450daf151a3b575e319fd1e544543927370509b8717514b74482bf7789995298be83a0176f60e8e3a7abdd4ccbad8252873b4b85edfea110f7141b78c803d379de49268fbd36432cc81a20f5871078cfa7ce847e0256c8e1ee919eb2d759075b17d2005b5318fe2a0beb510c69eccad15fe472df648272202f41a8d00841cb4fb04c980befd0a2420087eec97fbea10864b795ff1bab41f4575c8d69b7b4cbc4abf3e3a853ad5d2203e13fef34a9263354a636ce480ce2108abda63e9e02d19de251bbae253ab4f016d9e732e36a88304b1a325c0c2ea420632bb76a31607fc5c75334b36c8d0dcc157f46025ae8b69efcb9073daea9749a340365fdd5f85e83a068a9f2c298029bddf1884cda38a3f59ab2387149cabee6bdfbfc8cd3538ff9237a3f7cc9907d0d586fb31bbbe83ddbcf51dc567436c078004f4abfbbd3a67aab298e9c4b34d62d1e11350ca2dcd800175634e357c036d356068ba2786c3d94c2f0d69d257860923a21f597bb17c0265cd657b2b5c991dd004f0d1fd5e80d36a9a369a5003f25fea4f15aec6798866d9c859e60998420e6463d9c9894a29a3ed3e4197c0b18c1ee5a819cb8dc3f12947e5a8f8180a8339eefccfd5a54294df1a7add84873a07e459a042c2ce28e94ff070780eee4878316d33f494b2d868bd0d12c47e5f266c061cc6ff8152d019196f8a4dafc3d8ace581ca3116203960f6269f442a2f7c10499d281dfa44eaedca711ea7c09ba71d85b9454845e5775a184ba768836c351bb0b53c4ec7a304127ecbc4cc77210be7498d8e5ec739dd30b2eae6fdb15ed8f503f8a97da63628cc1691956149caaab987db3f30768df259a0a3610924f9cb063fde5b37f9a583c5ae43ea0c7d66077c2326aac8ed460d35ca8eef9e250aa12dc353c905e82a299960c0d8aaaef9806f261f9ced59bdc7b333463820a630435f73376c5dc454ed4ddf97700e864b9fff2168faadc3011fa8aef25edf11ae8aa927e4d7b353fe83df75bca091da3cff7c0f6ea8a9c3b0be0de5dd2433c00d9338289451a3e0c4b60ad8297c07cfda07dfcd1b0ed00511a1c5c514d1e75240e07b7cd8c653316142363ed102841fda5b51f4ced82b67d8cb2ba541cf29756d40a863d7b5c19f5e01545d662b66642034a3821da1f1886e2e7ee76ca74c490154333af59538047629e25dd4a4ed8c175ff070ee4294d1255159bbc0ff0bd39fc8e40d6cb63fd6a013740f9cb3197167bb4ebb793ebf1e75444e8d68b1099e5ca2411b2475b19df252300dde50ba34c97d69e289208918b760c66417d93f01c005a5cf38f9f4d14f36c257cf62c3da3ea21d57c22cc2484960cda9e712db8cbc46e9285811dba955099c1a122b8eebd68efe52c0215dfe7ad185de39b924073ca36791965b6c0126e46cadd94ce5d543d6e5f8ecf6825d10e23fdfe2135a1daf5a9faa85d1325015db6ca7ffbbf2daa2668b881dc52ac212337fe03c910dd11cdaee7b533998f39ca546f348177f1a9802ddf5ac01624e2e65d10b1e4d7f622cd59a508f852235a8e518fbabc8658cd485990c9175dd86e311d4c93242d1e000b005d3aaa45ececfc34184b7565b70c40b7c7d1c584e9771397abfdef379135092701a1b540d1f28e403d96db1980d4126063177353726111e0d33b0512afdbfd3dc9c5de56579ae66e67629463aa8ff27cee49dec87f327738994f0e380c43f9331ba20f0945bc68ebf4085ddcde1395ae200901dac5e2d86b8692c6101304ff5afd8f4368bd642a73225537722e6921a31bcb872d479f5803c5acbf6817a37bbea4715320696119fe3788e30d1037338c32e5e4f87a2054b5ab595e9c49bbccd8bdf70ff2aaffef73ce5f1042e9eac20c8f85fae35d4dcbf1cbf8727709c72a350bbfdcf318fb9dffbc4e082b430817f4790191bdc5d0444b692e956d841c2b8700ebcf52675e46467ea668ce5ba42cf52f713430d1b45d4746d2069116063a9360e750a274e333d394dcb31d5767f093a3c5744995f8fed88d1a2d03fc9c69b3e05c0421ae7519064075822da6e6b37bce1a659d7c1aba2d0788ead25b63365abcfbd6dc8f7694d5c0d93c57df9adbabd11418271ba60c5433ace87f53f6abb8a00c89ce3e578baaa18e17fe341353b0986f2a4f5dfa36f9d2a808ed518282baad044f272a57731c87311cb14faebcfead81679afac78b4e9ad828f580ae2f1c52045c7199e3a970256d828a23c81e191b3b0346c70b94b9828e3e875f213aa6bbad29c5afc34a287a299445d3883c833ce59d04541e9825ca2981429451619a179d5e576654a07dabf7060ac1678f1fcaee9fb1831bd478a49e4dca0edd339f61501f1b0e87f0e426bed94548c321b8f9bae916be614110b52fc9356305b99981ca8db5e6e6fa89ffb4b40c33eaf842738d5b2f9027e7997a0dc00894b99539fb041656e5b4f29be7f87b47005082e89a9362716ca0fe7a0258faf43b2696c796db3b022691fb83fc4873094106b12cb72a8c4b48dda76e2f80ced1d9980cd575d7927a2d4cd496475be82f0d2ed73a66f605ab00ef32aa0910c89b676719e2beb9c03fc3fcbb08ac27ceba0447e716324ec9732551d80ab850ac5f04699ef1c8e10d87dfe1df08de56f7be0389b76ad62edf580a2ceb7f0b110bcbd7bc5e61aa30a0c08530562325088aa8b32cbc907635f51b55fa25a5f7e8c372af134eda7e21c9d0b1f28ac851cac7c6f7e7faf85d7b297e098977abedfd7cf33bc8dd0bf54471ab45251fbe8d7d562c36e467bd8590ca26e75e684c1a9d756041cadb8f12310c8f34ae15e8bf6118a5e5b625eb7a9033340b108e54a39011cad7a2ef6a9965cb225dfcebdd19ebdb23c2b25fffee59fa123f53df994451d92ccd40f570442a33308bfcc1d5a20ff404c2b413b65a7480adb8f2a0ff2d880615920aeb871fe3e1e20a63eaa9e3a6f61b34a587a646c20d7b93c6fa7d22bda903710c3d7747a0ab43e2aaf11c8a7c35ee9b64ae6ce7867d13a44833c70946f3638427e931f3488697d6d91db64a33f7d5b4537c5643fd4a3d8555d89291c31755d4621487b185232493e2e71fcffbc84920103ce03ff46fb1d9137ee7dba0b22af70f01da778b3c9ae6376d961976d4f561a45e40f59beba013d3db2133c4f7f616bbcd7ff5e71b5c7788242ef23895bc20b1a4a8916304862a40414e9c81f082b0453cfd638d6326b803eaf8fca03dd0d314f6219daa53639674aef48d6507fddaa0aacfbb1de23fc502e8c7da13c7c1155dbf679a28b7303d361b47b86dd22ab0ddc840f680d088879efe1d5c5e4b0afb676b6264ddd6ff6c5dd5aee32c9ed1c7db14b57cedd858bf0767255db989fb430c7e3d208445d32f9a7817adff4ff1599ff2468fbdf3b56475fdb00c2fdda449773bb16c6fe94b33c02a8943610308b7b63d4a64cdb23748bb3b3eff6790b09c5dc8e099702e177c639232813645eef9c53dc75e43c4695d415ac155cc6664457ecf794693ca9642f9d6877d94c4c5780355070cb51d0e77e0a76b670b7769c14cdf6989ef67e2c5505e18d11a365fb1eb2b30a382921e169275e85098d109255a591b6bd2c894b109fa81e4fe30b432fd221bd91aadcfef83abb007b8fee37df158f0dc6621d002a9a05c2a4361222072e222190502c514718a8d689498db9d78eb046b3f1cb3ddf135fc1568f425d86a68f8fe145fafb8807cff96a7d1cb1450ca5fcf8b7a9554aa407d539f7057608f030b3daef77738e73061e8f6573e3547e78255eaabe2df1a06eb6268850a0a7b62b6769dc4e3a4e58739d5122b7a773e4473b14d6bc1141aad77a522327131a0ffe7a9fd50e7530294f110cb5269e44057a80c7c723000725890ea0aa4610e2c42242669f1310ee3c05071fee95e9e18338cc190497316eb7512a8f601b5a6a6124f705bfeb325817aefeadd228fe9e6fda44b2d358e15e0f024357a53cb6fc77bea28e2fbdc1e1149002f29824c8b34e8741e5fb8394a1b58f1ada94f073736a8e0b03fe41b0c4b8b9fe0cb0a0df1e21726572c25abdba0e5fd3282fd09ee7d6a53fd41557fa36678735e07bfea7fdc9f30da1e8bb8114c485830684e60bc4800308b1258c72336a788e0837c7c221e140db374dfb018aa1a4f8af2e606f4fe2b7bbeb46c6a5afd62509e98045094720b49622528a5802fc9b86dffebf963c52a196b9ade2570ea62d6eb503ed4948361df38dbffa84681ed3673f1f9e7400f2866b02ac7df5e543454d840a64a60fbc17d66b3b8f27b1ba4b87a76a21ecf9bece37e380198cdc8389f3699205d36759984e33d7906112ba35946c6d9020830d6b7c23934879e9de3e2b04727b6d0be48d43f3d90ccb5f79dc56cd88cf002a26ccdff28ba5afc7e6719b9fbc287603cc461e193b283a777cacc7180cbfe6f7654ebc7e84eeb0b740deee5ef70779f2b9e633278c173cc2617ba656ed250dabc258cde57555aa5290b5c7a7cb83251f706b1bac3a23a63a37bbe215b2cb35e1b638f535e6d8f7fcfdd5e360463cc5566e92d39841605f074d1eb4cea889bae5807648ffb6c825855931f103cf5989c4fd07a003db0262bb8ddd1b55e8d0c1257c274454b69beb054d6453f437d8a382ee56758706efe60dfae7a30daa5a287bc400760011407e4eb747d952dff6d5615dfb2c61f76543a569fee26ff656ff3b8596cb2c0c59e2a6ab0643d3f3f65d93ea3b822a02505ef3013b8399bfe2687429bfcb6fc519ab235773d62be48a968495d76892865aad53234e5daf5103471a59903654b12a26290e60bc83843f199bb256981e6ea41be3cf938b4e6e99610a13b7b1c800733348c2ef701ea232b14e4c9c778c75625cbca36204a974d7cefb3cf5c2a3b84e32ae58e86401483748d6e361b39529888fedb8173ec2104eab0bd4d9e8955fe2d8ec6682da504458dd93be3b83272f557692c23e2dce21a57794a2dcda55fe2ddbf506121a7a6941113fca88544d9af16a9d8b6e9dfb20d9cef9128dd3a60e58cbf400d3967e5068e2071108c1a0a95c9e745fd083da3dfb8dd6818a43ed192c1d996bc7e707eabae4f1663b06062940105c498702d8a9099255fdaf7fbe16ea140a32221c6a8a1b2e4a8e0a3affd688b0e9f3b5e8cd71e73e952326151f9dd884b113ffc4e40186e89d380d2dcb188eea436082b2457fd2c2cd1c866ecaef37da8bc964fac5b4cfe248dc5b2340eaa5d9f903400d69f719f9d045738d66e185ce4e0edb0f5e3f20b031fb6f915d5233476047d1aa26ec8918e26cd8c7e157396884af3b6d8374cc123e96d071448785e21b058603b5b9260385e847de3769dae2822b7e283337b8800dce9155e623f73006e904f12d7bd8e9a835c5049ff68401e9ca0638b4d20263d2452432a9523dca0fcc46a54df432adaba07207ecd93ba2992bf60adde11e6d0ba1d2349dc12373c313b638c2810240a3c641c53dd842e5e18a40c2c4639883018261d733b969f4b9827514b8b6f6479bb3c645358002381fbe5e6ddfff95b178f57a7e392d7f17e4ab110f08f9f5a2cd982b88207a850f0c27413aae34d0ed1e6efc0b143439905cf167d404ea9ad44198183269c8f3e7a61922b631e6c1a527a5e7a200c5f3ebb32fbe1071828057d2ee204bbdad9eddf81b57d1cb8a313de896fcb48d4ac2d9805d20edbfc8387abc541e4f3c633583e7011a6f7e3b4fafccb96e98250f901a4eff06e6b72b442e619eb708567b0c38ebb617f25c61ab920cdd7130a7ee0462a230def5d87d3b9c0c0d0f0e71890cea9aefa2acd3e26a043e280b4a1b2b820bb53c9eb27ee7a9e164101ed4a72a1cf01b23498f2e7177d3273e4f6f0055b84284920e76529a855d4e2dfb10d3532afa533a23f32c30734b8123d309ab0fb3a658904bc721e54a8eefc5870a288da3e1039f28df38b2cdca0752e49ec2e8235e8ba80cf6a17f079bbd8ab3a124f1b00548725c01c571be1886d70051fc3680734c82991704032194976548b50912638ab82d0a823fbcdf654cfe1251e72760e617088ce8fcd37476f4c81808f320f2c534d52563dd090b255a3356ce9e6a3b853fe4c74d56a6ac6a910aa3baf9ab7d0738a6329942f7cf14b55ca9f0be34a3a0db0e37f26c2dc1254c701d4ded55c71ad34e31aa5aa6832acf62724f3ca3ef977b74c28d5f6ca28a13e08fcf8f87cd88f0a40fcaa9452cc4ab577ecc7a1f59d36f5ac5868b417f97f74e3677b99d5abc8c69b2e2ab13ffd0365fac65112014bffe3f0890de7e7cab007562f46c353b813cb543e23b5fe826bfe972601a6300db7cd55081a93370240796f51ca841c9f0e2e6b6a3fc0943d6aead5cfd08adfc03060821ac1bbae3a51c6b1203af6249b86cbdf6aa15e347501d7685d5126846948af718d758fee4f4819a72f9efa2bfd85bf6ec846b2745cf529de3c8f83c4d984e17b94a030f5a86ccf76bb7356f8774ce46c749794e51f0dd7de3aef3f6818871c4087e9e0796d945458833c4347468a43ab5d1f5a05623473778091c00dfddf1ba9863b7e9dd49cd038271393404f8a08f1b68485455129200111569fe624085872143ffa1ed96efaa4bd45f55391f98953ac073d33b852aa2fd19d9584f3bc3d387f24b47f9050bba9539053630c313c99e66f5023900eb335f5d4c0d7d591b8a3103ee092086f4ae3c68a19883cea35d44f5dcd0934bd84bfcf7b924ac89c5f3fa91c13ed4c58a532eef858113f41fac6835f8a956c5a08b60eb27d9d8638fb0860aca7a4e64410eddcc4d901f8f3f150f5face6bb49215ae07fc5e7a170affe43f126ea5c8128cbc327fbf5435b411f7ffbd00bd0a95fe4185d1615eaf9426f68f5e952c5c4cdac4ced8c1f035eaffb6a9df2177389650f53c3244c10ced39a268556857aa06ba3321b742231b220b488c3c8ef9fb86bed2b905f11ccd68eaaa6a6acec2d0a4f5360904901f47c221c945f31ade05597a1fa5bd571f826c797b0e3117a6b077c63356955ceb8c4c21989c844214c99c86b224e96d76a6b902de302752bee0ca7845f54934c53710f58bdc4e225ae4bd6e48d9ddefc7de3a35ccff328f0d0e870dd87b3e48bd34295e9b7c900899f8fc31c7a8b5c0b8e53ed2ed66d18157b8217b2cada282f29dd5db1b2e738c279b015d4d0af99128b62067fd3c5bc4999c536ab095bc936b89b235408ed3dab78194199f46e3d2fb199ace9b87249d1401e23043137ed22686c5eb9de8def9995dfb5e4c265e794f079905dc73218406a164b4e69d6e3b75a519fdb957f606851a315ac6c62f8cdd1b51d1ecaae2a8197623e677b158773c3ad2c5922a3e9a06d94f2dcf1c292bcd22c50abcc6a9c22e601b970dd5263372f7e93efb975a181fc015ee6a4d7b410990fafab4df9ea0c73433bdfc2f96ab409cbb32815cab03a8aaf38b79f76358b316c8e312a3b39cd686d6ca060778bb9f572fac1f68df1ab57d2c8c75666fe62a8ad0dd2e70c92e465e6a1bf955eacacf2a2065c907f430641aa6610d89c88523527a04058a146cd09242db718a94d87917d0beb203c04859f42085bb35e9e979be432a2e90f7511f8c0aded8046b62836340c94660a039578fe03a51753b312f84b265160ba1764b1575385c52b72ea1bd1f5be8d5ab06daaa211e87a9cb51b6c308091c8a268a4b1e96a5e5ec90896b7cc1f993cc80dfff5282090303b906f4d6e0af3dad89b90d9e35051ba7232d883eb559c44472ab464343fc70568160e8bb53474be75e40e0a2eabd6dd057d2fb4b331e695396b464c0974d84c6379c88d9922279d7cbad801541f763f4a98e6b4ac7ffb43836173debe4d7ad03fc2114b835c114b0886862dd66003030d3d2c386f8cdcae4fd280d3989c238718d6b71a4bc7874b0da521fb690ac61a695a3e195567c69256cbde1f5e59806536597ead996d869103a3509618403e06bb6d7edbd86512d2b53b9c530b9a1d3891f0ff802a64872cf1a7e3405fed46b2f7ae8f2a42ddf527a64738a7aa42ee1eea3f0556427474def144e655308abde878d05dec86640bf27f370f5ae655b47b3cc208a91b5a232b8a6769073825a49a86e8eaf5c177315e2f9392613f8cc5a5faca8c3c13e41671be9573b708f436b4e9deab0118d871fb11fb684dfd30690923ccfab760a4de0d93a1701d9a1d4ab8e0035ce931f56cac0969cc53df3a6cb3239a4c5467fdab4a84d760f65e287f666d28408863b28ddd1270b1e5f53ea0ab4f21fbb8dfd36b1ee41696339995ed5e3384916ed83ec94946749688b7d174e8aa26faed5dbdeec1a1e7244b4b966e9d39bee7d96e7f47f58aad2462d560dafde4ad13cfe08c31d6ea4b08fb24f29f9179febe38937946b40e348e81048e86a737fd0e768308e963afce358250961d61d44386c41b9dfa40e3c9603d431a3b8fb1195764fab3bb0673fd9e47dc965addc69924233460bd6a4d2ddde3b32805da32b819757cd2f220aabdb05421191e594de4e809e3d3596592a6ee21810e73d33634c800f223241afa718397d827fb7ad24f83798f737a978ff7dbd35b30243945b17417ee4f9136aa88f033241f84294f4280967f66b8cc5a7becc00b6499defa67ce6b6a4c99fc53f98482f9d23895c35baea1780b5a12d79899d903497b380b6d87a39e1c9552ede7cda09f1704aa7b5d937c09773e90e5865bd406016802e84d31171a94f304700d662263c08f2eb13df203931a82d0d01a49956b861c7108f225a1306c0ca9f45ab41669332de8e46115e59cf69661746cd7d215c88c8ccbf7006a1909ee1941c6cb4bf12d595611e3a3ecf2a3cc9071d858536b22e35883854657ad78966a4d21ce75fea7bc4a1f8b28c97fe7fc4f969d3b5c237125a628faceedb5e1535b5051873636cac3ea467a4c36092f5b892206def876726f50cd9ab251d7da326e189b0b95ec7076f4f1d7ce8fb552b6b7608d8d393c851d13f37c75fd683d7e3f09fe073454a6d858ef828b08efa2024d4cc40c9ac90fc39549e5c2323e9ff98db5a82d76062fc079a3cc5d6cf24d6723f8195b514ebb92b2c4ecea1dfff3e516257e01ea5304b6fcabfaa813014494ed194f0dcfdba55f4f918fd00b1ce8143a3a5a358f3b00fe3b0b8bfea340f7bce5286ee3b780b37c52984a1570cadb3a67645eaa80b0937ba4e49c044f04ab4ced04aa986a7d27e3301629cc826b5de31b98185c6e82735aff6d5080325784f48109d645140bf745411dcfbf4e4e6cae74fa9c86c06730a166bac46a3d4c6bdeb8b76932bf21a53390bc6a2bffd62d86b72c69e9aa19918985178935ed8a6f60de0a1970b5050eceb25778ec7254d393d1233808ca31d584aa354023f5c7ba46b29717da67e115b5aeb614f92ae19791fcd1aa37dd8d2632e27a23f27a8ebee3d703af1ad494fc5fab1fe48b17063eaf05a25c5a6a3859383ab56ba21e7141cfd0a9d5ec70cf06cbf70c077828c22e85354aafc394602a15a2c0cdef69703427ab038ac17406187bb0ef38ccbfce8e0ca7d48e1ccf67acb631d7575f4d81991ef83a2f19d6479e51a1c3b7dff4822b0079ad776eccb0c0b82ef8d716ea9f7c2fc21d439230130990346159b6f7bbdb8ebb0a2218c1b3ac24cb13bf5d60ec7f524748462f955f73b2955bd6710af8b27671873f67136fbbdeec1a8628ca944a450f7d761726b226af40531c3703035aa8d2be27ecb44878f8bdac1cd956dca9897bae28ab98314d2aeeeeae1fbe31be4161d7b4a73bfe7f49fb380912f012cbdbf99b413a12d727dca4fe909a222c3c5fa5b1964c6f447fb6e3aab15011a13015118822d7cdf071257576f175fc46d779a769c84a5579e824b2fe3c7a3524abd83aba13c27e7241a56abb56e6e709589ef44ae81d9bcfad4f1d391ed89cec6d4e12b308e2e2a48b1e9af8a6bf8796296aa687cbfe45dcf131824097fa09e1a5a1213d4573545a0f5027fdfc32ba6bf5dc24e887415ea074a74dda2299340e79faba7feeb55ad8156c4c43a9dae00db31abbe210981efb0e9e28044bd981a76794c90435d1f71e77a298ffc7875667bb86a79ec767c6a3f99d59a34eb8c6950ed90177de409b21a49453467c3f675cdd29ef571311606c295090f58016b4c3810469bda04bd6442325ccca2dbd3a6531ae59aedcbbe82542afa2883b0c600b253ad6f7e9d74c7dde747fea873d6d85c38f0fc99e2d0530d4ba7172ba84a676aa7c9043419153b765942ab6c99ffb3d2a9a6a755f23364fc599d89027109717f27bbb9c563e96830fd6b624105aa443e3c603c201d4309e4266e6c1d8b7580bb02bd242578e3631b46959ad71ad2a26ea32756dbcf879a12d750866cbc642be6056570a8c553c1e848f63a8b6e2d5a11b6df767d53628b46493d42df676c730c8c716f4565653acbf89879dd01a4287e7e15f492efba73bc105aa64db72785535470724d08fe9593395af46fd104560cfbbb0258113bd6b6e54754967385db253c7d177de9ccb3f3a0679a149aafaca3ab9bf0c9a9098fbc129fa97fba771ec92364f47399685209c9369f6a314c3da7b57c846de2d995a5ba52289758a54c97b14a0286cec02e30b685408173cf0903fcc643f9df1a3ebd125ced5307a426ccdaf18bf977fc5890e2f08059898b0a6d132e9512919b1ab97677ec2e082eb489eb6e53bab8329f5d6e3887d4e7ade3b2bd7f03b8b092072b0a042f896de60d5292aad76e2e0cc602972057960cd1c9c9af11e5ad29802ce699e2c45da86ad85ec438be7b3d97733833ace05f4be7d9170d16b100533fe5ca087903267c65dd8da86f415a494011eba41587fb3512a81cf68542d828c7a1640431ce76bbd757598a8d85f443307330dfc0fb405ae86b1429711ac8a114fe85e2dbbbfa8f313c224398a9b6304993d52142ee43b676a71fcaa3b9bef2464106433c7797503792885206e78ddcbffa06402e866eb9f3c769c7e224d146f1ca4e0e42c8690dadef8847bd8f661f6ea39438c9b603ef281a2bf6765daa6b691b5bd8a9f0df756df8d51ba551b71b0e730ce33acbc320f61db8e5bbb93dc2f48c43a41d3b76367fa0916182f6057addab43582d2b0fa607eb1cff5f5281f46fd2bf9b4cfc590ddfc45334e161e39d0f6d604d8e3b45b7ef63db0f3fa844afade5944401abcd8da330687407be54a4dd5c9509abc805c6bbb268f4386c79b251963d803e69a10a8b255eca5d658ab733516e6470239a26771cf2221dd435f3f34063e7b837a7ecbb9927a69c005d4186263fc6109d2ed68832b046e1300b0a78099d388784d8679d9a50ba0d19b9fb22662e0b7c1167fbb5fd52b4d72ed765ff54c93fa8aaa3f6bb169a05f7da1607a6c31fa93cc5949d8eef2f5b22c8c21a969fca4a18646f3265e9e8e1d99a6388e2cb4f044e5d8c630263dc2c6dfaf08a269a7ed304fdddc5127e4e9d396eff4c58e2c0a3189810416399746118db3a3a23860d842563eb9a9409c146dcd7972dcce7171c03ed2cf02b9ed32f1be09e65673efc23ff6f66f1725066babb449f8fe231dff8ecfd02d160f9424d8e3f1fd7388dff1f24f20c89299521cf1ca98ef93cd20611f82d3cfa2355933814b040addaa79a76a79709235dbf2b2616c52685971a8b94130234451f1ce4f2d66382d0d62adc0f223a0076fbfc7ffea97b7e2bf6326bf300795f29fe9353f851861305b342eda11c265874d8b735cd82b09261108afabb942878396cce2ab0c78144fb9a396c882049b817cf47cc4af0537ee3bb6165ed98db132b2f00afbf78ae2a68fd9573a6832e8ee33d09849a2c8e60f7f59c3bf6cae14ffa2c000005358f99aa7e54037956f7932454db293d468106856f28e6ee28e7130f56ab06cb98c4c818b9ecfda23aba30fb3325ce662855912ca70f7d40d44714baf5c19c5d7b8df385cd8c3e86bb1671986282b4ea0fad7c4b6923fee3dc890f74cf5eb2d1f8e34f08e7cb82a5502a25925098e172f9e0943fa5ad1a9c5d10906d438b5e473a810e386334e2f76f00d21b2eff3528352ebddef5be695f554e3cd2f3cd663a3b600f05684dadf98bec582c23d35491c7a8c6e368ebdf969bab91cd5345c511644ff47d66af25102eb63de227ecad781c12f91d71b731f020ec242e0b621e985d5cbefb3d32ad938115352e8b7aa833ca5f90f78d41c585a74d4142273f6cc38021f92979b09066d5ebd766be296a64ed876eaf966405cf5313c2838539f1324aa74bfb4a066db140a3c5ff77c35d39b980f7ef3cf33900d107f82f7db95e17ed9ef2e5132e93c90032127ba7e89fe77e9d7fd2f87293c21670386d9812cbd284d90793135fc8ede0a521d524156f3da4770b6c67770088b6b8cf8043da06a04efba85ec9fa48bc15a71ac6cbd649b3c3e7561571be5a71bd7059384c681fe0643e52cd5b8461b66abd73e2c6422e969f2ebe92a1bb8addc285215746ef3bc5746e3fb1dafd2abc886e47f9c26aa681307a7c56bb5a3eb5f2a55ce4d2349e8c6abae41f0f5507943f9fe9777fb01f92681e09c01198288574132c4a1ccf84d31cd4046ff0a1b8b46beff8d222d3939acdb09041b1ee4b16e2c13fa18ea271666c504286edbc03db0d87de5581bc1b19399ca620bc48191343eb850fca58b6088d09913d2ffbe0862a3d141fd363566ae6385bad8b28a005f2bb24fb4e50e17821fb626a044bee180ec72fb2f6c6c24282faef9fda935d608f58ed9d962459c45298751a2192302029ef463b67c392cf0b206b1d13ac4789a5a517be64f7874a80116cc348368dce72560ee4fe597b3c3e811bfedd47e6a69cd641a541a458b5b15668413419116bc595cf32f22bd7002dc4d1fa9ebabfef4490967ba010d3357c4ff7cae3217acf436ff5f27bd09120c93c6402e81434e73e305df61ca23368659bec50b3d4724630f6bd9a0d2fdca7c08f9aeaa4d6607be6dedf487c076f331faec61774b42305ddf34fc740c3a6d45d837f3152a79bc685d262e786f169301ba53122a73bcc17aaa27427faf71846d35d79b2e7e6383dafeca217664200a9aa5338cac19aa833a2b31e1e69fc4aa81e8ea992100305fb51fd32e85ca551fa1f2ab7b9035eb28b96072ef1556293edee4d217196ee7c5bac312df94feb04d25dad95ad5ef7bc848fc5f14042935e71875d08852c7b60219d07b82038066f7b1f0b37eb01c3635295cf9a177cdaf53aa7a9650b4f46e7f486e43c825ea553671c42d8375fa567e3a53dc26a47bf03f60efe2a3fd8640ba38f513be7ced56547991dad0525703fb7135f03e8bc49c27b47f3b870ed67ed07990b0ec978da6b9bfcee08cc4e6a0c1c6f665af3679b5d96c0ef4db5cfe81484ef870a8f9b68858a439010469489e16cf7f111adb0f8e25bce7bd78fbf9f0c6ab18d4f33f76bc0a0936023c6b14f7d066a88f571a10ad228225d8081af76264f02468a5227e30c8d12ef18e360192ab84e1f889de3ab7e72f704772f6092b4a4b9c495eac24d14cfd1ae5b26876b0f5bdf4376a2180f061e2fb1a28d5916c931eaec446b47da3ffed9d7f6541c50043e92cf91207fac77dab69fbffe94f37f1e2e68b6075cf319ed3e0e50d25f69b614ae52aed26fb61217845fca00da8a9754050f8b735030504513c539ca1dba660bc39932a3e1e4a8bc5f0c63689ff7fe65de9faf55d3fb64b892d43ea97abd3ff4f5cb55249e5aa291330c25181e0476ce42565431e75eccd08337dd02848641972033d2dd867e68e1badf11dfd055fa46d33921b1524180a65e7706ae147e7e3b566f931c6104df607e7f101a5105283db32ca4ffe4bbf96b41d56fd17602f32fb43a9d5c90d04c098019a6c3fd98f215b1f8c175eea2fcf6cacdcc13203052c382056040086003e538aa37a0a3916c67adac4fdb2aae3f57b5cd7dcb8a4fba8dc5f76f1c8d75926a2a81e1d3e11735367c73a55b9f81fd6d6466900229df4a74230f4e414eb72be59dd4429485dadb5c20565fb8fbaf9b29b0f8656d35e386944ef722d903f93324ac35799176c70bb9fce83049f61fd7695bd33c8b6ae5f08cc9f23534245699422834a4440887f8b3804a4e9d3b8faceed37d2dc89771a375c169de87295619950afbfdb962b753c634e1c3570274670735977343f0e0b75aaef56c6582dd9c7e21c97d400e5f3e9f542b40d7dbe20d30d70a006f4bdf6baadf3f2f405a5baed0eeff956d915444ab01a2be58e53e358b808abd8f8ac4ab95cbf80aa913a7fe0b2336a24f501e7077b0878d57e569b025afca82041cc2626c701d8ddeb1355ff28ea281eec750d4e06935c13dbde06af20858eba789bce861ab06a912048bebd5752ca6cd2a2ae46609b4f32c27f076988e75c3f8865913ff5240db785ced7daa30d9b7613e91dc436792cd0e4cc9f04987244549f2f49bd079c3e55583e92456ab3c5a089817dc848b4032011b6c0c183b26e7641c416c680e7b977d5db400a2d08532731916e1feb625d5091d71b92fbc42e1284f12cc3f738b54257d0920cedcb96fa4abaa93a1170e6730864ecd1af7bb1d0bb8644fa5b012f180239e64cb8705c3cf952b937816409f008e470aaf23ae2755ba5b6fe3022ba79885b73802dd0c92aaab147484e9b389733c6d2a38ef7bbf5476dc96ff2c4b8d8d94aa183829c46e4b7f0fef6c0f79ff2a307733bba616f2bf02aba5ff2786361a7292505f53da326ebb958553e639d963f0baab93cd7c9bc5f6c1a3056200ebed310f3c358db894095e9981187a330ec74f091a0bbe80f51d2494f72d80806351a480f24c7907704aefa7f2313f3ba955c0039346f0c71a5a2dd685fcd3d5fd6861e79edf4c8cbbf553ee8bad95eb3404b0b30b430cf75196796b7023f0ff8a756e917ccab3ba81fbbc44caa41360e0270ed43b2192b84c06a26414c91ab5fc92a48d5254a97dd4be2ed3d2d9d3540203dc2e177cb815a6d2a2c7f236a5c695f511054a0d6d8cd63915771cab7ee5c74e52b9ed19ac1455f98f50e3c80ce63183c0dd0266952afbe9b346b26f4754b7bc6c4629e93b548a51d3c8426b6e5668c0e383f80fc67dfe2c66af77fa48a975f98d6047f2c215317b79b7c3128f2afb0828611ced591add891a725442a8cebca9d44de6af6ac6dc3f7dd9a7a3e3e80c143aa6e40d1f1da072272a046e00d832de4cb65ff97125d47e28c8fa6ae5d7335c99310b44f67c28cc51dfff089b760d01fa7f8e8375e7ed1b011a0ef77af040a2be7685edeecbace49311b263602d1fcd24979e0ea16df06a0b05d38f099f33ace112606270ee4a2b7be06f3fc9777fabdb443e9b660b762323a0c236ff48b4c89f39ef3864ac0d6fb736cdd844b80df90139ec81da9675bc5a35f3bdb1f01d0454adbd322bb82e4c828e0d856e61bcf86da310ed09d783de9183c1866abfdd80359e2a903b75e41abb6f75211c51324b6b11804a345e3d7aa1d884a3e354217dfe4a31f0783a28a2eec63f0ae68f6b1077fa4bea49c6ac825dfe440e5de970821ab9b89956785651434046ecd23cabf0b520b5115bcd5f6bd329eb4b40ca1caaeabcbbd7f92a7a229395c5e6ba758f7222411fd727f48c54f536f3dc04d215253c1a02c58ec4aa4f6f8652714ee9813a97ba22829c50190cef4d75885eda72acbf06391d974ab5af2c3f83c504dceff70646a07079f3a179f5b3d66c4d5b7421b3fcd2085d10f4dd96dcaada573724804f32aa73b6e34790c26ccd22166020e7fd81c7a54ba247c9d4f5bc8cf572f05bda811ccdb4680e59506de35cbea53eec321fb9a163194a9a8dbd157eb59a04b41427efe6163a0ded37cb8fe74ec7feef2f57c9d340339f5372278691248ce3728894a771672c609ec7671f2c6e5733671137455386f2bc63fb8590cea69d4a0180ca900262c7afc3d9f075cc92fedbbb2271d19a23dfb644e7e141729704ca44a86b4e80de17b1b96ce214bb21ed1bea5c7be710363acd85741d8b6a5b8415a7a6fe9058e4ba64ac4f7e87331003290bc16b3da3b591908ef1867b63d66c79d422124397ac55d5b64735c0a6c7a404415071ff7062bc14c64417db574615a559d2f2c21c3dd011f79efc0eed6a2f9fd26603db845290d5f1bc43f246c84e6b674a39f9ac15da9e2a799166047cc4db4e3d8c07fe706088dd86503d0b8220ae9845317cdbc9ce6c4e7568ca8ed335113d153d3a42e5f2937601ac21cde0322e1b12336a651c5255619534649a7ec0c9c1c1703eb3216c3d02f82f33a6b425a21c7ff0640d4e58ff09749689620699a38ed8607196ae6cb781f40e4c2e34f044710847d1baed8ec9645ef4904721a5260ffbe060e48565844efe3b199c6defe39b5ac6eb6dd3fbf14e94b3474f5af5e76336d9a4f9077d55ec6e56caf77fa04ec373fdb68d092382cb35b6cc627706bb0e83a32d346c9872a338eb43bb9e1923fb6d842a135acf2a7a07becede04e9660fd23be6dc6aea3800b38bcbd6edb9dcaa51ecebd3fa351da1877605953516b1b2a2124ace16f1e4e56c9746d8893c5b0bb70150e9b3bcc6fa59f0db61bd0313fe19a718299b3e3e1e24570be5e82e7c2b85f183a7112fe46b9e3a57754ac5b56bd83d64734bddc1574bf8ee5cb58e6051a67bba978852cc2fc3d693c45dbc7370cdb168f84eac5499f09047e063f98002902cbbe13d288fac01cdbde29d88209ff0dd5e2bb3b9729636e9babd5d6cbcaed8808edf596f8f21c40bf31a54cc2f92d9d089dcddeb9a2a2f607994c7fd00be413d4224f4680770ad2712f52f55ab75e41cf34e584e7c5f233430d5f51cc2debbc3008e1c0e081f17600a73d6d3640a4199d1ccfc635c20daa7b25b5b2d968fc2458ecd89ad34172155ec26a3bde438ded5c5e2430b2197c5feca1d810f4eeeac63adfc30beca5bdef3b0a60ab4dde8a12ef9ded89de292d71ec7840de7236c654f6526f1ef94abf2b172676af622c045a25c6fb79a7cd8235af2675750c7210a3c6459807db04ad1060ca6f856c62e4c80eb39a12da6fb9f3abf3831f493b72334bd66416771085a85d8b6833ed5fc7bece10d692df12cc183dd454e324ffde97079f009a2c0014bb74467b9399dea171d9f71079de8c52fa2ed24ba1f0782d461087ee292e66780be537b578cbc982ddbd9811eb641bed64922b73509a56471298af30c8f57a0993b06e5b6eb912bd9bdb83361a707f0cae986a83b0cee5a928dd7f4d700c34d614c210d7b97419b01124b6f5f1203b0b3aba2b42628a91fbbfc8d2a16c12bc9ffecfacc6af4366faa02dead29fd57544a1a232e0d9535666460e51a825e67b9afb9ee45a3698564ef497e0565a73165b167649ad86f0a51adb359e82b770bb7f59ce37fb2475fed0aeba4c038fcf8402b53da4434f9c75d50fca5eec4dd19593280554c7b55c33524399e8aea25b164e452ee26733ece8d58ca1161b18ebf82c31b486908bf200732ba066547a26835d5028d2c4bffb7c6a089311dc295eaef8a3647b3b935446b67d1a522ae038f51ed33d09e21cf461bfab67dd375aaababe7aa1612e5b9ecf059ec29034551ed5db6c9bb3560162b5c47e73901ef3843d190c9e9e4d6049dca2160eb4d9c205e21a0b10297e32592161a4b2b3a94c7ca11f853ee8c76e92e1a62bca9c125088d1364c28af31e19e0e601fd5ab3fba4b6623548f899084240e55fa4b5b240ee3a38604a01fe3da01a44d216b2f70c9cb39e37d29e350ca7abe80ab03a28f2df8674a045c0e7bb8f6630a179741d601dd42ff4527c7ec2d3ae50f7e3619985c25486b50fe4f821c736f11471cea6060a9c4b3581a389b0bc6792786006dfc7fb4fc5caff8666c6555b253ecc8314b95a6e0d11fb2b3dd0387da82446a7b5fe0fcc31c9bac1055f469c7922bee01934925d0cc01dbe1933dc6621ef55a5b37062c80fa9488f5188b3c95528f40c67a40739b78e8a44099a735a6154c773b878a56be580ed0be7b94e4bdbb5447d138d87a94d4c60de09462d7e60b01b56b334aeda0a338d29486895ec4226a0114975ef578e4ad2182fe1aeb6fbc7cc0cfe3ce84c0181ef8d6118132853c811e662411afb4ef37e444b886200dbe1efcf133c934e08bcd7923e1a2ae280926dfa557292e5655b9aa0abd608c36beceedf09edfcf58dd2aca06351464d5ac280e356680c9c3c6f24a9a2ec8e7ccb05f35c745407c8647dbf595032f155c145afba90f35fed4598e1505754b38d88c569f6d49a84373a65cdaecac08255da3f742e17735f279261801a7cf7a5a112c868c66df21b235a97be87d1eb9f267b161b50718a52a2b98f6f4a0f8e970c3638a55c57fa25618dce0f3857508e43963e41b3fd4f67e1c18ba9085dfad066f46a17505550c5bfb3f9a8e578e99b521f9b5d96ec36597fe468bc6a1ed4d3a01eac34a330f79066994259f10736702707add7fa6412cdcf7f6a581e585d157def0b64cce416c9b2a9df2d158179a89085664a8b86b087f4dbb667ee9bd7c752f1a8e8449e12269f12666aa27e8a32ad36a5bcfee0a222ad6205016b2a4196ce796a4c4f5ab843e0a3920cd9fe351d213b57182cdf69af3f7bdb1ab534ef8dd877426839396186c3d33df7c4918e7f79876f4f4dea88f02eea2476e592c14372780160d006b849d33c00b308744c96e7b8fa86c9f3e4e03e22cc9089eccf660be30bf551b80f8d9044403da440987ab9df111a977e0cceab16ee98a45bc96fbbdc5bd9d52e4067622357845be9fa16bfbb0eb5ad4dbff69f99fe3721459afd6f1bca439a78bc2f54c6cad8f6aa7f500f4118eea0ba51da3c7f82809942cd894c089f95be50d8281b008ed66906b577646ad24444f56e78488ec86aa2799229d41d25849bcc72cf7139a9ce96ef29eb27d92b2b7d8e4b5281ae042e189f8628245443b562b7ee907e3f55cc66986417438d41bcbb8453ae305f9c0484008c9b28e943eb3c9601322758b581d46706713ecb2ccb9d6d6eb3044d1aabc4eda0d39b3dcbf2a03dc8e6d759af0b5e3f65f65e01038708aa1e8a65010efc672d71f0e497ae5499d50abfca0dd7869727350014e7eb97c9a44ae924131a98acd708d865ec7c706bd87a768305fc89eb8ff9d22d19a8ae4f6aecd50e25f5b22d7c070661acd67af549d869998066a527d49d116ad8f49b626615bb695e470c4102f3bbde45fa8b9be9244a48273a63af3537d61f23c8f5d1b1a37e1833206e4565ace80f9f5e9ac084e62fe91fe282c4f340da185046860568b5e37b8330410a7f3e83a09077bde5b790e97a425ab4d507703beea14996b5738aefda6d7ea848a563c7eac94522812da3171fb2639744587ef33c346f4de82c9e60bd5a3676708a91bb8f9ad0e45b4b388828966f7f5867f7c9e4e86a06e921bce9b6076e98086f780b2d5ce94e7c88517e1fbc6838b466426319269ad928ff66b140eb0028fac15e8a31f1aa3aa3ad255783e1469a9b0bc9ff4aeaaf680b9703557ae8d6a4bf00ccb06aef40e0d6a7997a1566fc8234465b79666c7d10705957091f39371c1a39981f06b2a52f576d8fb82b53a642905a23f2cb4556375a9fe450ee68816f6d601039af2966287db3b65d948e042d4d65e24aa1ce63df9317f513954a9bb87644e3f45b39ac9d14a6b0d2b121a0bb08aa5bbf1a37c0aa42f3f7cd5d092d374474722048c22a76962570c07a8936318dee13dccbd547285662a1a4f945ad42426dc1a9c6e4210e4a25de57a9047a09345a6b56352d2a3cdcbcdacfe631335a8b506eb07a61ce0285d60a429cc524cd49db55283141b4e9c8654e819a73d8b15a8c6d205f2913bbb23dcafcddaacc2b79679724f6ad0990f2a4f8a8c94c3e7031bd70ce2c636e4ae45d09b1775385ef5875fd93d815db3a867597d98351693394e0e8e9a2586ee0266e31e18ef2d86f9ea75fb99c391f947f983985ad41cc4e935e10ff6ef439c06869f4d8e42b2f4ad0a245e8ea2ab4464cbb8b252f2ff087ac1fdb9d7c9f2d998d4e84b28c6a82ca4f40de08b105ca923948f4f7614e7b264cbacc16a04c428db7e3da21e664b09d46913e41c2b324fcdd593bbf01f00fef3dd9da32f4ba2750ffff24cfe93c9366d2882aa996c9c83f579f86e99c216dcd4d2abba6ece141c03ba0bbe4960697f3cbe7a1c2934578b6f113f52d0b5797d3c2120a06ef5505a3dfc4a7608987e399f76b1d8ed7d59eb8ce458f38cc3be5549ecd5e5e1ef01e0f509c4288a90673c4b414df826e1dc8e14aca6d65f52a344adce8d8516cbd6e37cafdc06ef0c6ba8894330237e618947dbde47a2911bc0fe312a26c9f73667391da1b939bcbfc494ebc32d961647b5d9e52751a992127c78822067eadede5f87e7e57e43369501db1c71933d1124ab354aa913679f50b83ccac57747e2b3d14d307409f0b82b8160d4375acf0f18087555eb2beb8426c814a15b447af610cec6aa3813f0f1f3e85c7dc2c61d2baa47517f0655560c5d561f3afa4add0d211e12935dfdd66ef30a9b238005a4b295fcbb403795ae5a18f2b320dbda5ae77c849f68e6794a0bb48687e26a0b54208045dd85f0e02a5c04cf8b61a497ab46b2e5d9de8078c9b9d479616efd2a5f71fc11079bfeb8ba6cacf49c1ca3cba3064e68394455fd9e0200ae668812715e1cb64eda5f611858b12fca5c295ccad0f9cf8d64ceb1832d3b21dccf230b920390e2c2bcb2716a164c89325ce50537ac38a9f4c99ef15987944f68b887c07aa9574f2116414d944f30b49a6dee35e42f149a6e770bd8a65fc890301c60ad874f5baa5d4adf1ce00b224cb9ba6846d744dfb63598e73207e44ab0798665f349b94a2fdfa39a25adf25eeddc306538b95edd1e86fe177caa2063a94c58b65f0414e538c7f55bd24b31debc423f22af5d2c50d65098eb21debbec67bb66779f4378257b3749e2a27b6a01396882ae6e3689fce5a4a6e039d1619b38aeb916de74732bdf3f6a868dc44683162758fdcba89b6da57ae78be32f834f1236dd9aae7a561a62900e4b567a931d1a7670b031047ac37bf412d479745a4a5ee9978898199239e873ff13f2baf5fd4d3c845f96ad11019064b6fb5dfd458877595ec6dcaab452f91ddf2220da2efafcd57b0a1cb3947bd4541eaff45131986eced771eedd4cfcf2b6a95236effd53d3285bf694d20793a2dbba6900767d1339653777e8fca54f76134f20b68cda44345bb5f657dab56dfcf567103db1136d953b91450ecc1a30a413434e907d851b1bf95b0c554f5a130e847c54a8c6fcd9e375600cb89ac17c8d80fe9582276888a4ca48017198af64ec8c614e1b5ec53816bf6f67ecb6d2e3a07e229061bf3898a4a37da5525a75fac6fa90e3805723d375732e4378c409913bedffc8cdf3f26fac7407d9877fd778f1644099dc4226b4959ab3eb3cbb85a924e7a13393fca28e4ebde5ba5c5432dc92e9f30bc0f57fd641128df334b48ccec3c01b66fc4c69b6cd7af24b339950e0ed65143f687c64b16a43b5f1638e0f07561ac53074824165b4e78533c820af854ad9f92825ac1d4bca25b550bce0c4094c20d4a7433e04d8ace6c84738e209a83e0a1b2f40320eb8ef71ed7fce9cd8500cf1c87f6981369f6f2efc136e4fcf76843c2be95010367500e831d2f1ffc76efc744e64b8ee24037db7c7efe9b8c2c031135c37593354855affb7e18c031450e69875726f420bb589629a586ab2c31c0cb37d7df83110e4ce9de3edc9bd5bebd42bc8d3df15979076a85f8524d1cba2b7bed32fb1dee1d318cda685a9f2193bd1c14ecbfb656b3a3ea12ff963af0b0dfa4e4587fdd8b27d4e0b181e59280efae1b706d8fa482e4a7f6f19e9a75cd2e484081e5b3b0bec2f2f5f89390eafc98b1caa39bf558fad5a957044f7a69ccc57f576395bcc67e4681c5acb29a3ee36755ff1cd126843319a3a6a0ab76d171942b4c50e4ec4813aa3a01eed6915d9bae968163f99e45636f6828b357c24372a8462079b8d21050f489ab600e4baca158c2aa4e190b63edd543dcdacfe68f32b305530ae836d0a26a053ccb1b092ca8a69ee20b8cc0cf87fc7b76a4c09890286843cdd66b78c77ceac4bfdfbfe88facb91a8c085bc54a2bac13bd94345c69fd9b430781c49a958a6b64fca2f16ef7fbecd64b79717a8d19eb3f35f270695ecf8e7fa68cc26b5e352f66a5d935e8b2daf507871e86d215a37df4d4cb9866a99e46037aeb5d54555c799eee0fcaa376f7f6e63cb710fad3595071ca67df8181541780bf281fb244ba05404afd47876e2ddc2a88465a29fa4369c3264970c2fa13c0e99547fc498354c7831b1542f950a2bc2e2d5ac86f08fe5c5a97d2420eb3ce0fbb3daf21cd3dcc54f21614ca118d764604ea36715e940a36261903301997e516ecd63c72fce5dedf3f3980822dc64b6a3e9ef8d13af0a487c545b007691b07fc7c1b78a9197a48f923a6b850274f2e1e948123723518d665a7269a5da5a403925c46cfc97ad3ea261d90b44cbb0c7706aebc5fa4ac3eca638b475855235265a7cc7102f2cee56fd9a48f60dea736c987be98dbe7277ad86eb96ccbe0d92e7c3cea1bf2f29116fe5b6c21118e614a92c632a7418de1c43c1955f90e63c8d685aee25e8d8565fad0642061dce3a0dbb7c9e32cc18363109f75bebc442fdb989e6aafbe72164af093735441f4d6786f82bc8a553155ce0e490adaeeb52ee2917dd12be50f834600d5492eb0ecac540a8a1f939e03895c75ff66bdd57c3ecf8c0394a608673a02fcf68a1974a01cb9aa49c30491fe283abf45c3bda86e39b02abb523be56379704d114ef6fbcdc4ac0b3c91854aa4b833b83df99df4bdb30d5e470c1c2eb08fa909c51ec4aedc270730dc06c8f049173be4b650d71aeeff0ee391dc791a4a01c0ea461ee624ff17b6ac41e722e0f8960e97647d876b68fe6c5b2eb0acd673b6fe52a94ec909ffbbf12958689fd442f1685f3a66d26f00abddf2c03b6a18bb2eac0eb032573ef9ab56003fe65f5e6f8ef8704cdf4b1dc18633eb2943d8fc214934d099b188c09fce09f7edf16061616c7e074cebb256d70f6888a19c3a32da6b4bbd545029ac0c31290297f18a31200e73b35f34adeebd98cde0c4f053be2921932e86ab5f1b9203a325d9d485dfb8fb8a8481317340060f7a22a9daf02d98dac3e9b249537754513b5fb634da06bf7d0e14dcd12a28cb0169e9be6e93fc9824efa5077134910d0efc4265e18ace39753a5cf59d69a2ee3e82604edd5e99bd50b91ab8740f2fce6e8bf0a76bc4d436abdd62cd8a1bd0f6c9203c154e6c425975f7d9c996c7a7cdf862b9479d018ddf2828c23de6ba09d4688cc2cd1156e42913cd0e1b97ca30fea1c3c92a6460fdf7dc73e4bf120eadf63abfe937ef74a60f0a5d5db95976dfb59122aedecd9871e5e129b9efedf066b3f8db936216930675f0cf260ce2736d619483c93e41b10c856de1eb9428378e5b8dbc6b5fbd5e07b7844b11d2ffe558e34e059e9edcaa69405358cf3643914b405c4c66594b19c6dc3a585212523abeadfe1c1761529c59ac48e66ad098b774fc7a5d809e768f26b7af394eaf548888e5029fcb365dd59e5ff6c0cab5885fc5c5730814dd561fa1daa71fab6f9acc03df45277b74702e22d2a5a79dc270b98c812077f690c73887f2d4e8c9d67a4e7d096a3d61572754e2dd5a84ec5831c56cf9ec1d80c8e4e74d377bf97d6240430f155d47b896e04cc132e461763177a8f673c3e761d2229db45136b9507af420a590653bd59681dbab4105ef6fd867f90ba9319d20b6f1d66e7ebcd6d9225854427039db4764080890b78b041c13e54d7c48eda345a96da008b9a985bc0e901fce179ee56ed5e7eab259d389505ec852234360e4a897831572183062cee7338fe60da0581aaf97bf789d575e750aa77fa200fd57bd56accd5ac255822a9c95c79f7b303e6c1fd1106b790150517cd0cfc972799fb47877800009b02357688f30fce60c4458a498b2d23d95bfa2158465c2405cbccb63a52f3b6c0830632ef00734a6cf6d2ad3107c41b331315a4e8f14cf83d4f0888d7df503af0ac77b55fb152bee2c22ab9c4a24b6dd1e8eb3d22491053d2614a07029c1d6b19eb59912be902aea742c2d50d1bdbdae12a2b9d62da7533000d4ee0aefc97315420d50d87ca1616a2084e5cb565453faddfe398f20b3ed02db10fa13597554c177942ca30259abc5240cbac8e2182d6f51f271c17a02790d5f3636a723d6ad6ec63d849f5ebf5aee279c3d1a898fc1c096aff5dc86e9887288e286adf636fad286c38e2e0883bfe833f44ce78cde28ad6518882ee1b99e57fefff3652768143743283bae84e1bfa32fa5202094b4c0b4db3e79fcfcf54c5cd200b332ff6596e87c50b7a92edf1c3a88b1f67e2824b91c1c55c89437888938364a76563f15eab2329a7397114512b84f3b0d0d72652fd6ec380e07672028da5873f9d3ee7629d8fcef4042f64ffe3fbeb6a569c901917161819f7867c74d2bc3614a482c91b37dbad06d2e4682f4c7d9d870197e5087bb72d740aa0d47d925fed63a9493bdd6af677c169ba1da6abeaf0f1a980f571a1a87b5716bf85272991d03d42e8fc152d3438029e8073526b80140e10be58d725ffa825e329b67cb4eaa5a9e8445829d8f118b94335f3abcb699845dfce3d93cefc6ec1f41b4257e7fba9f1e57e785cb44d01cabd3bde9017892aa67a804ba7df89ae20928196cb259822a783a8d2348a00cb1d46f21bd103c65f6c6cc5590e0c22e54c67476e94856199b2de6e6e4d916219968baf7ed5564452d87cb46921e0e4827d55fcb0fe785ee8b3a08311b6a95fd60232ccd9e7debecd076af8c5488ccf55062cc37b934ea51ee309fe8b536013bf39cee5c59372831192c4dc9d7b84268c6aecb523547f3c97a5fd430e493a205aa13f43750e79546066c6cd8197dd76b4941b84d5a5752c85d5333d658a80655f9c73fe0623dab02ff8980aa44436da9456307d6af8f22bc891e587b9cbb617d08b55df1e226ba322b1f3777225d49caa2728cd514a6457b6425323fede7d8091ca23c98e3984a93c653c6821e669b0c74e694b57492a12faee21323000b79f25dac4f40af997049ee752f937a63edf06fa6a9b8fb601c7c00bdd955fdd4869956d8671fc209c6d838afbbd28287de45334920de95fe2eb023ed6e1ca2ef9413572fd8ff2ba94e32253ed85dda4332495b398f8441df2a3d94d1eccfbfbc338f6e4292f8d24c6f79da6146d5747ff384147e5beb16e6b0996f65f875986ecadae13b6d1a041a1c6d7bfe0d3a1e8de9f6869e558ce9c9d7d1ed24a45154b74d32282c5c3f044e38799e8e5fae1d15e3664129137cae1de1df40b5c990243ba642d364e0bd5b0a4e1b241206d16edc0b939e375551d05a67c98ae0b92c3033622a2b54fafe793584a6ff4b08dca35f23c6c55621d348191fd23cd11414fd794a32372759511962ac1b5e879263f54206ffeb4a580911dca8e8532195f48e0e8740b6575e28419e5912a60d2cd80fbc30eb9cca9d1c2bcc748b7d3c294e64eba9c684c564504e5beb68ba626d6963a35aa245af9ff11ab646ebbb50ef0e9cc9cc7801590ee190532fb5a5045d9453da56074db4cd089ffeac135115f38b41d157b6b5283f5da74dae8d67184fa73d9fdedaa066224da7cb314a0289cd192eec623ace66035dc2855b8050853719c18bfee8f79d5a5bce228974ecb34ecfffa49bce796616b37554281953f76e122087efb0c9d87b054881b8a7af670ed7d9af4682e97d5f83791132ea64721822a5d83bb853261b891910f11c6ebc84e2e668a4e3e83ca3c837a2d1c766683fc54ed4c1ca29602e6b8b1bbc12d63576650d231453dbdccd1d8f0ce5f3ef791d3cf19d83f7f79f9f1740eae9c4463e166d9fbae37ce4d7a4c6bafe0dbf1e17a597b2ca5d3289c93c37995570130718a95cb13223d94980de567d0f18b5c72aa5c80e163e2ecb2a8d30d9442d9fc765214f897ae2826af03762190d7e93030e271802f04299cce6e964d794aff8254da012777093d3664a297d97a86979d619fcf246c23a06c51d9e2a71910e5f3ff5748dad8a04c6e9ee1e7988337cf90dae016527c6df922f0a2e734837315a335fa133fa519a28fa18fe0e59ac67c4260bac05aa3e048515ecaed981432d13fe6ee244dc48a1668269b878a95098860da031ab03eb96f4c4d4aca5b35396f50d0ded49eaead13b8a0baa1f3abfe6f63c9f12f6dcd604a6b7f4cdad15a8030a3380c3864521bf09da915aca5e543d6cd30beba481da9f896ad8e20368cc0d098a93408e5d746f5e99467a277d6566d07424f9fabca928ad7c6372a74182a344788122b744054c5a0198ff8fc9227016e8a49b3a50d33e2ed383825e28a8f796e3484db69c999d512d1ca4c1a0b625c7e02d422aab067fa97c6cb9461c6c2f5c6db662cba3d4366c68d433e268c76081ae64a3a0f34b76e7ac43e7ac7ea9404e459b925af356874647bde6c6305a6d2fabdbd6d106440dab231e34e85c9e6fad9edda26a3cb147f32d629776eb75605043bacdf54f6d16a42a11744b45ded0019625255100941a0c9074583ad103b04391634290beee59c5175e01fe011ce925671ca086ccc0008610694ff6003b0606cb27e6afb84f2fe800c35344b079f27ae85eb13da7094745808bc8a6be5a3b4b364659ea3297b2e38beba4f886d5d73975e110c3447d2a1c9bec4163f884f561233e1abb21a1ad8b3c2030463496e5cf47b3d4ef946b273cfd73d623b8ac4067195bce44bfc1325357ee7ed22d6140d1a9dd9d52e4c35151efa7c62b82a2d498080844cc34cda5b37a454b5e0ae02070d050e8ed1fcbcdbec2944639039467e5c0e94b4731e8fe03513b7ce4bb80ff0b69a8506470804aba7ed3f3e73a28c1837fd4511194264d89217d49c39c1f69575ec0c3b7c14bfc3478ede15d3439421a6f3d0121af0962b0165149fc147ddbc726243870cfeff2c8c78847779f235171f059cc93ff8c98a25c1e2e77db9304350a4303e507bcbd42494cedd809b59d6498a023bb9e77de8df7a247cf710d739deee6e3ea9f34b7766ff61889bc9eeaa6c0012e2698f296222c90e7169b2da39c9715b2a1d67fab9dc25a29c1a7a35735fc5a59159ae640e6ee7d90990ba31b13ebc8e974c709b0986f37ad33698ce541d522da1244471b4596b1bd4505885716ef8c5b90b4d572e10f773d7138c44f57fe056bbddcf670d3f792e68def15e17c3519ac97459b157e142379f591e98a48e95ca3cd1d9204f6bcb7a5f3ebd8cbf442116d716eb810afc61f43cf9beb1b78b066d80cc27684b5412276ff65e7f39bddcc0dc2b8c8846ea9f97133e646b2c47229c0e4d9f280070160154d973c56867a559f450cbcfbbaef080b2779190429362146adfc14a14f3e15b7f1d8c9ffadc7543403662374bc99d77a28689470a95479455af7c27298ce62630928500dbe6b393b0c86ce22b70fbc9d61e431520a69a6b590982eb76b58e708cb83a666a4ccd3edbb3398de326de5041950354709f6d5975394ba3b135c663c98446b6941453b4d58455d64039819fd6d5937586346bff082c9ba86dc4dbda6ec6904bf5bd9b08ca4e7344cf8428cead5c2610a6a33079a98a19b2e88354a339558e2f40e6494a551fc99bfc8e78199de3b99843693eca96413c1873478f66d6f4508f8cb651f46e1eeeda285c8fec62c955afb925a0e3d211c7bfc1b59939555f9efd51d9ba7d4366eb206a234f433bbb9efc53ffa50d1deac21892ec10c2f5fda562da7394b577cad91ee82f19c79c752cb5f352df0aea3819f23625b2543819a5c4c6274ee6d204b3380bb94b5b8ae69ae264563d33280c979a1e6ef04dfe6de2eefe90e4be3ed3785537712f237d3ceebdbb36187ee2bd9c06860207a5c9cf32116c3be8cbc57eae87654ed833c00d0287b7386bacf8632cc0fb42408254ef0d3e1eea34f6e1eb736eba8a527372151a8ac69b5c68fc93c8142cc09903d62f59577b0af5b102b9daa81d9a13ff09f67c13f700c363256d88112a2cde2a14653f2bc6ab62cc199a9df3c27aaad2d96acaf05ebfcfb896fa39249737ab50f665696b67c3b176c83f78a6e6eb65de06b9e284dead7ee8421677f3cd45b918f559232555eadad6527251d3d9fb9ec87eeb9ccf5c62a867234d8baa70aea81d6b9d3310ceb510abaf14171eeb3ef29afbd3a7a8f9fc37c3fdd8ac648aecc70fe0336a94be3735667e990b3dc0268cffa6d6539719a19351fcfe2273dce208fd472b157466e835777f582350bb22477ad488a9e1e694cfd8884a8a7e148558dc365099612c1fa0c7dc421aa5458fd474f71c1872167c16c13ea947efbdc340aaafb3098decfac5faa9beeaeda7d63aee072183dde1bc2f7dcc8c9ade47f61de4621a708f2bc8ad40402643e7ee198ccf0740655ff71bd7d28b42051a3c04f07a4d4c9dbfe8a74e3df078efe7033db21019d10412a33b0bb608b5f0a1810e94bfc3e154bf60e903a6cccb8a7b13f9b36b984902e79e76273626cd23034fd06e4707a8852422265acbe4a13eaddda844b3429703bf2f62a72da40ea0171db12d556122e314c05d67a3beed2c59a52bd390115418b7f2ee68df34dbeec0ada4287ff250380c411ccab3f75de783a8df4627564a2758d2f04827e02670e40defd474d8663af14a775b51fc114550a085b3d29dcde07bfaeede77ccc9c587246827e0586c7667a63b5e9929aa8322ec8d84e25fe2ca3b0b02396699c682371a8b3390f534657d6d182c40ba730365f3c75d4d7b5e782f336484f7eb55ae3bbdfbc4c236a8126aea5a96b0bba40f1dc5e8a33f4743183aac7ace7eedba2818b83aeece750fda5ae5d1925234a9fe7128c24b2e12e2546976de5df673923bbc07de60b716d1fb1696b2b68f663bf0c6345cd3b4b95b434abe85f3c42a6a760831057e05ea214cfbaee4cc733cbb7a42c54569189ef592c174645a5a5e287bdda5107c9ba89c6bba8101ae929c020b0080e644fa6f459315b24a0ae601de823df69c2d215695c6f35824f976ee53ade0cdc8838473aae18322773a98c9f7bd2d47a4ba61e484d5ec94f605d7de059b90084530a131e53240eb7965499bfba9b2f704b221659943d0c4cda3ab7b133ede7f4a17e018532b502dfdb3a3d4a85ad2e53e1258a19b480b9bc01d0090af82e540fb2866058fc0298f28dfc1ad02884df157b8ad4d291632c751591e6243162d5efcf0536669c6c9eac7d6f1c41a9ba446feae1545c4e3c6b8de4435b3230e65833b4072a002d48db3d916c17898cd36a8865fbc172007ab04d5a9b6a8467da00fe0ecde42f54f9fc08cbb9fd064402dde353e237116747be16e63b91088d70f2457755eea3937d86193c81c5611f0d970b4f9909660945d2b676e3cc2169d46e76583807e3153724a57761478b043da7de73e5979629f3779bd5f399b18bf0f4aedbd15942b9e9691e64de06e4f5db807add585c8801d0b4c6c3424d83f02f084d96ef197a8a37bb61da765c137d3a97a2cd20395c55414bbdfe9337d81c0dfcc989758f4b7718a9a53a07a8cee438255c2eb71ab68558cec49b2fb7959cbe113594c82990d7bb7ce0c22067292c29b388c0c0ea57b572141b889d773c0513c81a60d5b048f949bfea1af4b7d9fefe40a6bb794781bd67d952bb7a7299d6da5037e5184f6eafd28bead3e01da006459682e2def9f95208610a63a8fb4fb790ea9780a1ce035f24f425269a50d4ba40f44892b34c16522ff26035fb643d3876f460674b068b8adf7f3bec7ebc9749280fa4770d354bd35cdd5aa6acb268f4fcf9b2d8a2a5fdd6fca3bfd5920dcb23f92179ffb0e4b5fd6c47fb1f2e994d8c6f53306c446319dff4094adf685cce6f8fb922cf0135543082fad16279116eab63c1bff06e630071bd670c1af83d6bd1571ff3b96a63440d80f67e2d53d0d2f8eed74ac6abf2f76c11cee2adfec1506c0392e41aae10cfbb9627ed71b495964d441a64f662cbafe47f6a45a4b14a5de3299ef57b2bd87f2b7bb3140e66b5ef817d2866d4cdf64b0b65e0e18c2cf852206992279f47be1c7fabcc031f4095f6ff14d70a01e8f8a85e02cf2c92f2d2c1149ff1e55b1df967871719a53058a7d9d76b13436dcb7285a4fca59a8c0ace26237509c33175d175b877bb4bd72e6cb325d5ffaac354aeade6140610aa0d64b29137c820fb2c79612eee23c5e8fa0b0066735fe123474662f033669c2c7c688424b228c36944f0211ac3d3e45c498cfce2c915368cf206496a8c306a34df5ee9a754236cbdf04b4241f539670fa9d7fcd384dc27f3d6bdaab0332df4923a24babf02485ca6cb5034f3e22963eaf27f470a424510f4b47273bb7f15c5441a065a6aef71a55340d3360d95311f7ba7c80f92f3fef65d3cacb9b3462d0b569aea3e44a4266130512fa1daad76fbfa6c86479ef8e44146bf374221fafea804cf9942652d3f4099efea623966985157b5f7deea37b4bf5c6e062720f0114b4b842ca2e2f8300275dd1d84edc020a839ccd457a3e39abf9f2551a2384689632ec7ba850d6af8371d36989ca2b409945025b76deb53cbd99e0139178d2d7f092780ef4be3eb4b60fc975860427226518dcea9ac6c9502f93db768bf7a6a4a5dce37a484ba7cc7366c186d6a185d29858fb8fb7703575c083b46c43bde8664ec9917eae0570a4e4e7a926617c17ab151360fd82a0f601619542104aaccfe01cb76a9974a3f96569b9ae69cf364d551e9746bbaf157c75fb3c544caee3f036d031e0d15bcfb323120ab5a33a8126a48c50d766f887c059eca560b2a20fe33bd005f2fbbcc38bb945a78250d5e8742522dbd9a516eec56bc00975ab81f3c3cc7850d8a9e06ad769fa9c93a6cd3744b6715e09c76d77e340924d2a9317e252af1cee8fa251113bab5afd4f022014897b3408269b1fa3b2fabf8ef7005deb13979997d9f7482b1bbd98213e86c9469bef61221a1639fd1aeb9ca92d70225770c563f1c8571cc353de38e318766835545ab18795f998eb60b25dc07bb29dafade4121ff0f19a2ac0e92dc6c4bc6c3c7153cafa85fa3cde94440e0ea0d1094ab554e132c5dc62491403046183ba716b2982aad0ee6f62717f7c4027fe93a89dc8ea60f9c4db48bffcfc3c325c03cdbb2b7ce8aabb8a5efd9c9755fcac7c2dc9d40fd155e2af869a2ce4cb2bf39b19eaeb2f116923293ae8a1ffa0613ba6177444c6334845c1f56c42f1bee546bb33379d51fe9bbd9e9685e2d374ba48e6adc6d8521e4482c622ffec15e0e7fdff871d16a0d6ebd99bc4b784f0a8e5a2d168b4063503c29de273aafc51017828172aeeb3694bf0c62a8d5c7dd7cd06b2b3c71480d255b3e141c52b4eb9238f8b10b8ec016054812a269af54e7747dbf75dc346254dec1bd9e4977af651ad46602bc1d0fdd6c39f167dd04e3dfb9548542c7f0f2dee1c21c83da9fd3b76c2bf834e0971ba5db7c1325fb2605224e287a05af7e61ff6a52e0ea00ed907dafb7cb063351beda95b5e96840bf38e5eb74487c914e7eb3c35120961ddf29cc6e30cccd029149a89e580d785e9ad0bc75dcf174779f9382e6e8f1e27aa355589f1e711d967bf480419121816183bc48f1470273a8b9227ed7572e315418221b643b60da0e497dbce90a21fe6d2c8679cb255c784356e2e2d6710cf9f85b2c53e8f2d17123a8cbec440a6bc79c1d1f70a083e47e671874e8f24b25be388678c3cc177707d7f586e2b6bfe4ecece74815f82d337faf23c04370cec9f492cc1fb92dd320a1bd11855f2b59edd366d85a0513a88051e2b1d21c1c68c5c34cd95225f7dcee24c88b318779bb8f526c22437fd434cbfe04e0eb9ebb0da991a4fdda04f38d59a46159589efd522e261d41a6eab65d9ee977e016033bb576d9933f6cce94c942ba1210c5514cd1a0d960179fd9b04feca9e5c72bc6699a18d225ac90ca554e3977d41a91b2fbbe3de561ff065fa105e97d5371e4da391352a81e23db99210fe9e45957eeffda5d78cd5b7706e65eece5737f380bd7afb364ebd2e2ac2118a3e137be9f8b6f2fe898d7bb63a4b8a5720fcd9e7eef5cba64bde69cc31db298a3cc465d115a80aa2f88070979a0b0a4d41e2fd77ca7440b9085541a81892605d9f0a635b78b4db9b91f9cb6fac9c733d2bfab6a240debd8f6b8308b68e7184587d9ba2b2fe59155de2719fad51e16cf6c11184e7c9aedee6ba09f534dcdd9aca8b88306ba973bce5a7426f2a553d635fafc6a5284b3391ebd8a8435219c24a4e295d93a6a54a4286ca408c0641233bcaf0422e95a670b445b50482fe6b2770ae401f61a06575338e695d3f209c6343f9307cf9a228783007b8bd133d40800d93119a00b9a850449a1379a0fc26a9efab3ddfe8e8c9dce899a07c9aba2f8f7f332821a9d409b7ccc9f762f22e9eb02546f5445911913c23f630a7f6d1e7d83033e0ca257e7c98f0caba8f82a5c985fdaeecd647640a6ef05bcc8177e8a8d83a27887118407951ebd61979edad9c36275c70f82834535d44b1487a5cd86bb1bec770e1f24eeec59144a3cfbed6737c3da9edb18a6e2049d9c38e9390be61def06f87dd6ddc87becc5968bcd9016d56908800ba75589cb3be6197cf524fefa96a091e929bc82a733842854d3a58cf8eb52777a6c26f2377267a3714b886f64e8d6ca2540bdaeb4b583f574a0e32d4c05917a744abff9ed86f6cb0466f3467185ec126680fd444101b3dfa7df6a421afcf74ae56bdbe76aa03e22cc21bac7f27dd6a6d28bb75f465fbbd6fcf7c3c975c504ca2690fda3ed925958627ed4452fbdc1781e33bb02a6c3c601756cc8a8f3904f1ad74770090ac6e28b092756da99d0135a984f107224b23e54076b57e1d8b07368ffc44cde8580c6731385128a5dbb512eeb2337ef78a66c22db4895d5d4dc66a6ea171d87d51d5ffa54d5f1db885691c31d473c9744b1e826fddc1dad100b8283644cef19fd794979013560c808f000d1a537aebfd433557491459b5438aab4aa75714782b12760415b8ca169da8c7122bb9de804bef2276054e99ab049d7d30ad4455c7253ec340238406e370bf67cb4bedc9eaf347fc1441c1c6d8523058a3433258ded5f613a5a107d242f4cb1eb5f196544c6b14d16ed6fc3ccf5b49f44b8964e8db31617f3850504eebe2c847803d2c87f04eaee7b00d4131024504ab0da5dc6908888bef27b4dc69a695b43f74c2b253e7379c533de52cfc963af69a4dedb874544962c645fa306d891c3158702a430d4a1123d54bde7b4283fb77709b842f839912cb2311250c6c30ab6f22b8102bb1dc936649ac9de4dc4ab102aa0205fcca14d694d7c0f0f0a6e70c3631b068658183b53e9fc3aab4b8d1398c5f6b3028c668b05db25fcd6a449c2a1cb48a881ade0595dccb6fbf521db8bd13c84096e4f2dea67345e57d78a50e3968caf08ccaae9e05818d1ddc899067ff595c0e7dc693d89122753306e384eddae5d9a635c6e715f274ef1ebfd8be9b52b14370f7a0eb986bd81070ab0b127e215543500465ec9b3e90a88cd74dd3d2a44521f8fd4182b02df21bbe52d9d294c6d0eacf10d5a04d853ad285b0e9e5dd9a9b4ab865180f51cc16eefcd23c5a818a86430164916bb6c8d05594ff94cc37dd0c10888a5c8ced70ad4f35c8313c9c7d8e3d9cd84778223275aec397330a2d25943f209d4d88ea858b1a109c7fb43c2ef0cadf3555afba43b3cf5515c12aeca2c87cd169b94c492c7721d840d71f56a52ab9805d36a38698829df1ddc6b8268d853b51c4ea7bfec95ed15a294bb7eafba74acb923f42200db5ccf818ec457989d3f9fa2f970aad9ed02ae85d25d5c3ef15db5c3ec0dce6a71b0aac677bb7ae9c936d0bfe8e47f3dd98e6102e76dc348fb6b76a56878fc3f7da53dded5fcfaa99244d1173ca4b5d795a213cddf5c21ee18e0042848557112975e3ba8b137764bb01b1d4184e7327cc0d4fb1c88043f8276dbd2b353c1de922d61c73429a69ea3ea5d2bd3376abcb6e4e0620a9bc3745c4096c9b1191a806dc24de77d4b2c8a75539d9f9d5d325f25379194872fef1adae2314c1ecdd19fcbbfb4debde7f7323eaa8326782655fdbc97b2de3f25b369daded83be6259a57da99f59058a88f79c3f71747d076ce0e6c28f6da26b2d11cefe25cea1b99fddc63abaa2b8cfcb6461d2b36d543c51b3e34b6d53a2a2bb5b4efbb53480786561ee698a257d8df1ff45eae97435563c8b38f319e3c6cd617a484ba6e38a853811e38a65882d9a1a4b0ab7826cd56f9ed718ae09e7727eefbc1456490ec78f5a8bd7a46734328e33bce75fc821f70761f1b456b09d903ca12b6f38e6c702e553dae86796ccb8f58a720ab4f05a7382ee8d495a709d15a430ca20d6f63989470eadbdfa280b9ca50e47a58630e52c248e8f2e49bf4746c61068e3016d21290609f040f2f34dc23268e1a06abe8ba63226004bc7a5dc7c7c448444c107b217d517acf5ba61867022d58ee7cedfbfbfdbe0ab57b28978ab14031e876def6ace6b255a254b6aa71b0067fba30829336a17702f89f837d5344c79f04866de10625939f7b6497a0ba572c1008dada15ee170684a3d355dabe296dcb97dce0b905d27459d6614003055a440f7a9e3e8f907a3eb92f6b33c0444ec897b0b6dd965cf462564008e3403c0355c8c471419b378286f5a03b76ee61dee6deea99d19d63074a574e097082bf45840c42a2640c921f1e6d6b27353bd874857de30d6454a883f703c4b6d724544b126e00110e26137053e1feae308a363d6b74f81bb98f4f210a587c838be81624d796fa8c1dd3132078d3fd0c194d3c39b04eecc430f21a21ddaf4fd2a38f132bf5ea262e0aacb7c8efc89cabe3454f01e4836d86748a2a38aa314f869750580effc1169fd44d7ac81b805d2b2b83c913604f8309b4bd8ebccd51ea82736541d2d19e0f83a0ed5399546f1acdfac8f77d357b26ffc86767a97181f34e4fcfc35460ab55d8d182e4370b2b4bbe4ce594212dc3ff1fbc8257e6c09d22acb267c7c3c7e9356e1bc740090d34d0183eadd2f7a7b55e7e8e8761fdef9d9160966a9a24677088cd5b94f0de3626c2614c8de635473157da964cc6e0619c0399709e109122d40d0f911f99dd9fd8f14e690bdc6e799eb03d7312f8a575c759d67924a986c55cf6844cb006541dbfd325f83cb606d4355e6abe59fa5e09dd01c9caeb680f55364677f1c61eeb29c180368f379516777e08139ba41c37e5761496d24d060814c66deab6dc78be1ca9ad141e64ec30657d82c2369c009ceed378d046cf3282ee579c6ebbff245d7883e101f8c4382584648d61c5dc458b26f5afdc7ffef35acf96a825c4fad48ddee4483b14af442f17d11b152a4aac640820795b1e13144078a822318628543916d6ba9d503ba6df5602590cf0d7ac1d4b9d8fe69e4707838e77416f408ecb69671761a924385ba90372286cfc3260d0043b2ec5f1fc7e2fe443c8f8ace6571d0ef19330d2a82447f24df1ca7aa36578034bbf84287502640e45899f4c2333eaa4448a948830c8771839beaf2311b132ad2b1743f90f4e71144ce1d356809b65c63e983b05da710fb2ce5863a2ca8328249570268dc210c23477a11bb78cb114d0dac5a512b50ba6b2aaf1703359c47056830ccea1bbc3257f821dfe197f3a4d05069b7ec9573360b4401ded8c452d51d69cc6882db2e30ac60c03ba01a722e89c4c947ef03b2ccdbcb28a2fdfd97fd6342f4d66d2550fbf20ea9e2f52dcfcc730074b2299047122da7cf98b4ba10ed1ca9a224f4f6b9b8591e9e332ce5d3935fb02721f0aca8f2803ed55d8e633473bc9456bb5ecbf989d7f3e7e20d07fb686a577657fed8d8ec552d9c40c27aff8d320a02d46b3ef0573473d5afd93b3b32c13df5db0dc501d8b94a967ae953770b790a86feb9c0bd3cff6bc344216e4a3bebe0b875deeaa3dc414758ef04d09bec2eede5fca53034ddf7e8456ad4ad97dd886cb7b8d6f2b42f5466a9b1d698b241d3e213fc2c23951ab77c6ed638c327561369018dd7a4cdaab6952712961991d444852525cd5937623b2a4c75a6820164cb0deff56c22fb0c5a05ee04ee78fbe4539f17032b446cdd3512cea3a9a85a3b7fcfd818fac8fad47c33e018816c8db1e152ef21ee71bb04816d6133b8f7e4acf32c9bbde08bb57353b43d0c4fb134500527943096c4f10a860c3db48b07d48ea8f0930c867c3eb22cf6d53281cacf07c7a12dca2af970fc643f85bb5ef18d44d4ab711336af986323e622c2ea6350fcdbcce7f23c61ee4429cb9724a7185c85f5335a2fb61bbd794a27e2290629d74595fd737e9fc64c7a880a030c1ed46326c8b56fdc8ff6ed2bf8de22886d38d096da5de67a2ea58b11ad24be2c7158819e4dbf8dc89b68288dfd7667c6eee99bfa8d45b99f9e465f760bacf3f881fe73787a162c1336638b56725d4a29cfa8f4d930d1f273eb69245caecf6666d72522388a7bc5fae6573597b0d6a7e3dfc70fc6eaa98a575a891843b0958c979c1ff9e8872c2a799f3aa2fefbf01e7e6f921f7ed9c357919a62665b9838415b81495c0042edb15039f81d1fcb4982c4330d10856201d32ecc481dbfbe2881486e33a8b20d067f1e1351edf56e480a8a9eeccb7a901998a88b72d3a48e1bb89d7416257a555c1f022fae0559e2305b886f9ab936085d9270f6b278d96f092f7415707e381f90660066f263454fc3674932ae0cd822eeb764319cc13e1b7e8272a8e0e68d7aaa071577bf3809ec8f3b3f14a355ba52c57d8b5c325bd622c3c07b7f6a8369b5a4cfec84f6821210275e3bcaea85137721cd999afa34ff4f193ba7a05cb4bc542d534fefc7cbdab8aba6c125824f415ca2f653a05ec00721d74efc839ebd3df1a0051d0bb53eec103bd971433f99539a7bd51faea420d936635ea448d18c2b186d839cd47bfa83d518f31c2c8bf70fc534f66ca1ede79d2ae8ec9fb78a13ec59fbc3a346d1e014b5bae62b87203f5108cfa58a9c7220996e6ea17d390e13385e21e843b095682700d59428e9cc5c239fde5243e3b62a26672c179c24ffeaa8e3d1b897dee4a934a43df9aa0889f1d46b7b2bf7d146e79f3065ea6c570bdb9b0c78bfd9c7aa866ccbf6c82ef1451a0bd22f17d85c2bbc551961e4c64a83d232132df3ed8be63eb27cdfa460869f1cce8d2e1829e6d25d4c600ded7459484ce013183221ff5cdb13be058abd1989425c18f31f1f4dba80006236c849dc7395414ec2ae466ceb94c72e321e97ff77098e306d89fa720d02267398243b220dc9a8f33b6200f5b68e826594f6ebf380e09c672728f94c1a0014b39947d710cb3f8d4b549e7f331902e19cf34d10e694ff400d2b7eda9d341beead4508de150ef9f649f177dbe3d6ff5ebfa97dad6e6e2f992b1bf425fd1fcae312759de59bc742161f8a501a2810ea5f9d22f8649f810e93ce4b0320a2b9f19bd57abe4e6780572d020d9f1dd332f7bd914d77b6ff2717d1256efc5ee79207bcd6ec3f04f9ee65c086073312d017d0424c2625923ac7748670b10d0632402a37510986ffa3b8e5a5d6a932541ebf1461ae61ee43a1dda0f947846fd7a20d49cd5dcace5c75e876389a8566d778b03c954f3495389a618be277b56408a16ce2b7c89eac4913dac0b88adbc9d7bcdb9abf9ee5cfef90988116aaaacd64636617d54d6ace17735ba8935eabdd8e4f11c4a8025c69e33aeacc11addcf3356e653713b986bc2f7febe68d27f880ad052b4acdb008e4322b1c9c68fefb157123a76bebbd167c80dc1751f0c6d3dee7041fd09633ec8a35220f55e2528a56618716cbd147754e5ab2df5f2bb1d2f11d03227d632d48c52eaedebe870d1be64721286334b902e0e52bb8acabb2a98ecbe00ac2dd56478cb7cc350ebfbd008e1d0941b0a575b8566c334bbd1f8fc453d738f299322101f8b84321eeab81df45648ff819ad0d944df7773788cd9d2005fcb12bccfccfa9ccdbf7aeddc19a70528f9d7db1db2f18d236f88405eef7093945c1eaffdbe32ad2206730602e5aa474f67a5b9d1d5c956e58ce4532de2bf2ce5e356063de8179329f41120992d0db74999c403fb4eeb95968f7bde475f308e4acaabe4d09defc923fe80c5525365bf1414159a4dd53e9261e65e68d803b35975105bdec5bb70701c02aa9f1b37e2da71163f8200c0361f28e292342133d5f52cdc710a8522c431c8733738a7b3cf7bf8281e56df307c4e710e708542d7a24e5f5b512ad642c38d925ec4e24bdd9a7220df1748abe72f81d299afa8bf67d93c3e917a76d5312eefed5213ffbb13951c653274e5f40e83be2a3c80b96f13a9845ced1d07e8366156a7c54a344e84ec5b33baaeee5036882af339282477e7db6dd20825c86d9879cf2744f1bace3a15e413c7625f3ce26d5625a880fd5d5c4d81ab5e56dbce10c583e92d9b27f0438353d64ed5a9d83cd0d382c00d205c3a6c0d59ea6b9b031cc91f56f0391e91a53d6f84be316c68445ac054043ca98da0a650db083e625fc31229f259b20117d4c98004c27062e8f827cf252a93fafbeb699ba657711c21ed789261aef42afad5c0bd4041ea5a36c062662fd2d9499e881e1e44a75d422c9a6839bfdcf4b439ec8036f00abd966afa00fb0b9dbd12b2b4150527314c13dc91c57ed4e7cb778744808d1512548b29d915b35bfbc402f5149b7d621676b6acc7bf377a63c5fb5c5299156b6c113f7d3b864229291d78a82c43fe7d648565f49314084417556812d36ec0f020bcd3b05ea7f922bcf4172db00c476790381100c96e0f21ca23d0d115ee1e896e541c36da2d9f5e9514a825d4c496be0aa523366b723a489c0c78c2f56e25d1c144804aa4c8e6fa8cba5ca9e56387b7824cde2e3ca50da3bb22728677eb26409634e478fed1df51482fafef8fefa86ef58f84b00b1d3d1feeb89fd36d0abbfde46f22b581c59c59566748f525289c6245ad522ea7f4f3f197c5e277804f11612ab82496830b8393c9b87fda5d97d629f3b637df1e227dcba7afe022eb90331715e0a704bf0270f9eb5eca57a45cead723d7868b58f05f823e236fdd4acddb82a0874ac6bb0642390c112eace4b450c68af5b3a899f1a38c6cd6cb9825308ac41247ae63fe72715045cdbc07f07681caab93a5e6cb40d4110f2212f720d94c3cf60d493ca9a9b0d55320a69164e6ea4d327e4b13cb8ed6578287cdec51d385b963ab3b91a95ca9d71a00e0a7ce11fa1e50601feae502abe601afe5c9f4970ba01406f6dbaa0b764af6fab1bef3274a09f2d44fabff15f9e14ce93f023df5868eb5d9eeade6b15dfee65262ada2f",
    isRememberEnabled: true,
    rememberDurationInDays: 7,
    staticryptSaltUniqueVariableName: "9c68654ed0906c24a5c025e97c184e05",
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
