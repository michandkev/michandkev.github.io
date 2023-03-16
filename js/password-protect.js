var cryptoEngine =
  ((function () {
    const exports = {};

    /**
     * Salt and encrypt a msg with a password.
     * Inspired by https://github.com/adonespitogo
     */
    function encrypt(msg, hashedPassphrase) {
      var iv = CryptoJS.lib.WordArray.random(128 / 8);

      var encrypted = CryptoJS.AES.encrypt(msg, hashedPassphrase, {
        iv: iv,
        padding: CryptoJS.pad.Pkcs7,
        mode: CryptoJS.mode.CBC,
      });

      // iv will be hex 16 in length (32 characters)
      // we prepend it to the ciphertext for use in decryption
      return iv.toString() + encrypted.toString();
    }
    exports.encrypt = encrypt;

    /**
     * Decrypt a salted msg using a password.
     * Inspired by https://github.com/adonespitogo
     *
     * @param {string} encryptedMsg
     * @param {string} hashedPassphrase
     * @returns {string}
     */
    function decrypt(encryptedMsg, hashedPassphrase) {
      var iv = CryptoJS.enc.Hex.parse(encryptedMsg.substr(0, 32));
      var encrypted = encryptedMsg.substring(32);

      return CryptoJS.AES.decrypt(encrypted, hashedPassphrase, {
        iv: iv,
        padding: CryptoJS.pad.Pkcs7,
        mode: CryptoJS.mode.CBC,
      }).toString(CryptoJS.enc.Utf8);
    }
    exports.decrypt = decrypt;

    /**
     * Salt and hash the passphrase so it can be stored in localStorage without opening a password reuse vulnerability.
     *
     * @param {string} passphrase
     * @param {string} salt
     * @returns string
     */
    function hashPassphrase(passphrase, salt) {
      // we hash the passphrase in two steps: first 1k iterations, then we add iterations. This is because we used to use 1k,
      // so for backwards compatibility with remember-me/autodecrypt links, we need to support going from that to more
      // iterations
      var hashedPassphrase = hashLegacyRound(passphrase, salt);

      return hashSecondRound(hashedPassphrase, salt);
    }
    exports.hashPassphrase = hashPassphrase;

    /**
     * This hashes the passphrase with 1k iterations. This is a low number, we need this function to support backwards
     * compatibility.
     *
     * @param {string} passphrase
     * @param {string} salt
     * @returns {string}
     */
    function hashLegacyRound(passphrase, salt) {
      return CryptoJS.PBKDF2(passphrase, salt, {
        keySize: 256 / 32,
        iterations: 1000,
      }).toString();
    }
    exports.hashLegacyRound = hashLegacyRound;

    /**
     * Add a second round of iterations. This is because we used to use 1k, so for backwards compatibility with
     * remember-me/autodecrypt links, we need to support going from that to more iterations.
     *
     * @param hashedPassphrase
     * @param salt
     * @returns {string}
     */
    function hashSecondRound(hashedPassphrase, salt) {
      return CryptoJS.PBKDF2(hashedPassphrase, salt, {
        keySize: 256 / 32,
        iterations: 14000,
        hasher: CryptoJS.algo.SHA256,
      }).toString();
    }
    exports.hashSecondRound = hashSecondRound;

    function generateRandomSalt() {
      return CryptoJS.lib.WordArray.random(128 / 8).toString();
    }
    exports.generateRandomSalt = generateRandomSalt;

    function getRandomAlphanum() {
      var possibleCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

      var byteArray;
      var parsedInt;

      // Keep generating new random bytes until we get a value that falls
      // within a range that can be evenly divided by possibleCharacters.length
      do {
        byteArray = CryptoJS.lib.WordArray.random(1);
        // extract the lowest byte to get an int from 0 to 255 (probably unnecessary, since we're only generating 1 byte)
        parsedInt = byteArray.words[0] & 0xff;
      } while (parsedInt >= 256 - (256 % possibleCharacters.length));

      // Take the modulo of the parsed integer to get a random number between 0 and totalLength - 1
      var randomIndex = parsedInt % possibleCharacters.length;

      return possibleCharacters[randomIndex];
    }

    /**
     * Generate a random string of a given length.
     *
     * @param {int} length
     * @returns {string}
     */
    function generateRandomString(length) {
      var randomString = '';

      for (var i = 0; i < length; i++) {
        randomString += getRandomAlphanum();
      }

      return randomString;
    }
    exports.generateRandomString = generateRandomString;

    function signMessage(hashedPassphrase, message) {
      return CryptoJS.HmacSHA256(
        message,
        CryptoJS.SHA256(hashedPassphrase).toString()
      ).toString();
    }
    exports.signMessage = signMessage;

    return exports;
  })())

var codec =
  ((function () {
    const exports = {};
    /**
   * Initialize the codec with the provided cryptoEngine - this return functions to encode and decode messages.
   *
   * @param cryptoEngine - the engine to use for encryption / decryption
   */
    function init(cryptoEngine) {
      // TODO: remove on next major version bump. This is a hack to make the salt available in all functions here in a
      //  backward compatible way (not requiring to  change the password_template).
      const backwardCompatibleSalt = '##SALT##';

      const exports = {};

      /**
       * Top-level function for encoding a message.
       * Includes password hashing, encryption, and signing.
       *
       * @param {string} msg
       * @param {string} password
       * @param {string} salt
       * @param {boolean} isLegacy - whether to use the legacy hashing algorithm (1k iterations) or not
       *
       * @returns {string} The encoded text
       */
      function encode(msg, password, salt, isLegacy = false) {
        // TODO: remove in the next major version bump. This is to not break backwards compatibility with the old way of hashing
        const hashedPassphrase = isLegacy
          ? cryptoEngine.hashLegacyRound(password, salt)
          : cryptoEngine.hashPassphrase(password, salt);
        const encrypted = cryptoEngine.encrypt(msg, hashedPassphrase);
        // we use the hashed password in the HMAC because this is effectively what will be used a password (so we can store
        // it in localStorage safely, we don't use the clear text password)
        const hmac = cryptoEngine.signMessage(hashedPassphrase, encrypted);

        return hmac + encrypted;
      }
      exports.encode = encode;

      /**
       * Top-level function for decoding a message.
       * Includes signature check and decryption.
       *
       * @param {string} signedMsg
       * @param {string} hashedPassphrase
       * @param {string} backwardCompatibleHashedPassword
       *
       * @returns {Object} {success: true, decoded: string} | {success: false, message: string}
       */
      function decode(signedMsg, hashedPassphrase, backwardCompatibleHashedPassword = '') {
        const encryptedHMAC = signedMsg.substring(0, 64);
        const encryptedMsg = signedMsg.substring(64);
        const decryptedHMAC = cryptoEngine.signMessage(hashedPassphrase, encryptedMsg);

        if (decryptedHMAC !== encryptedHMAC) {
          // TODO: remove in next major version bump. This is to not break backwards compatibility with the old 1k
          //  iterations in PBKDF2 - if the key we try isn't working, it might be because it's a remember-me/autodecrypt
          //  link key, generated with 1k iterations. Try again with the updated iteration count.
          if (!backwardCompatibleHashedPassword) {
            return decode(
              signedMsg,
              cryptoEngine.hashSecondRound(hashedPassphrase, backwardCompatibleSalt),
              hashedPassphrase
            );
          }

          return { success: false, message: "Signature mismatch" };
        }

        // TODO: remove in next major version bump. If we're trying to double hash for backward compatibility reasons,
        //  and the attempt is successful, we check if we should update the stored password in localStorage. This avoids
        //  having to compute the upgrade each time.
        if (backwardCompatibleHashedPassword) {
          if (window && window.localStorage) {
            const storedPassword = window.localStorage.getItem('staticrypt_passphrase');

            // check the stored password is actually the backward compatible one, so we don't save the new one and trigger
            // the "remember-me" by mistake, leaking the password
            if (storedPassword === backwardCompatibleHashedPassword) {
              window.localStorage.setItem('staticrypt_passphrase', hashedPassphrase);
            }
          }
        }

        return {
          success: true,
          decoded: cryptoEngine.decrypt(encryptedMsg, hashedPassphrase),
        };
      }
      exports.decode = decode;

      return exports;
    }
    exports.init = init;

    return exports;
  })())

var decode = codec.init(cryptoEngine).decode;

jQuery.get('/js/encrypted-index.txt', function (data) {
  var encryptedMsg = data,
    salt = 'b145d327c3e24cec347fdd089475334c',
    labelError = '',
    isRememberEnabled = true,
    rememberDurationInDays = 0; // 0 means forever

  // constants
  var rememberPassphraseKey = 'staticrypt_passphrase',
    rememberExpirationKey = 'staticrypt_expiration';

  /**
   * Decrypt our encrypted page, replace the whole HTML.
   *
   * @param  hashedPassphrase
   * @returns 
   */
  function decryptAndReplaceHtml(hashedPassphrase) {
    var result = decode(encryptedMsg, hashedPassphrase);
    if (!result.success) {
      return false;
    }
    var plainHTML = result.decoded;

    document.write(plainHTML);
    document.close();
    return true;
  }

  /**
   * Clear localstorage from staticrypt related values
   */
  function clearLocalStorage() {
    localStorage.removeItem(rememberPassphraseKey);
    localStorage.removeItem(rememberExpirationKey);
  }

  /**
   * To be called on load: check if we want to try to decrypt and replace the HTML with the decrypted content, and
   * try to do it if needed.
   *
   * @returns  true if we derypted and replaced the whole page, false otherwise
   */
  function decryptOnLoadFromRememberMe() {
    if (!isRememberEnabled) {
      return false;
    }

    // show the remember me checkbox
    document.getElementById('staticrypt-remember-label').classList.remove('hidden');

    // if we are login out, clear the storage and terminate
    var queryParams = new URLSearchParams(window.location.search);

    if (queryParams.has("staticrypt_logout")) {
      clearLocalStorage();
      return false;
    }

    // if there is expiration configured, check if we're not beyond the expiration
    if (rememberDurationInDays && rememberDurationInDays > 0) {
      var expiration = localStorage.getItem(rememberExpirationKey),
        isExpired = expiration && new Date().getTime() > parseInt(expiration);

      if (isExpired) {
        clearLocalStorage();
        return false;
      }
    }

    var hashedPassphrase = localStorage.getItem(rememberPassphraseKey);

    if (hashedPassphrase) {
      // try to decrypt
      var isDecryptionSuccessful = decryptAndReplaceHtml(hashedPassphrase);

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

  function decryptOnLoadFromQueryParam() {
    var queryParams = new URLSearchParams(window.location.search);
    var hashedPassphrase = queryParams.get("staticrypt_pwd");

    if (hashedPassphrase) {
      return decryptAndReplaceHtml(hashedPassphrase);
    }

    return false;
  }

  // try to automatically decrypt on load if there is a saved password
  window.onload = function () {
    var hasDecrypted = decryptOnLoadFromQueryParam();

    if (!hasDecrypted) {
      hasDecrypted = decryptOnLoadFromRememberMe();
    }

    // if we didn't decrypt anything, show the password prompt. Otherwise the content has already been replaced, no
    // need to do anything
    if (!hasDecrypted) {
      document.getElementById("staticrypt_loading").classList.add("hidden");
      document.getElementById("staticrypt_content").classList.remove("hidden");
      document.getElementById("staticrypt-password").focus();
    }
  }

  // handle password form submission
  document.getElementById('staticrypt-form').addEventListener('submit', function (e) {
    e.preventDefault();

    var passphrase = document.getElementById('staticrypt-password').value,
      shouldRememberPassphrase = document.getElementById('staticrypt-remember').checked;

    // decrypt and replace the whole page
    var hashedPassphrase = cryptoEngine.hashPassphrase(passphrase, salt);
    var isDecryptionSuccessful = decryptAndReplaceHtml(hashedPassphrase);

    if (isDecryptionSuccessful) {
      // remember the hashedPassphrase and set its expiration if necessary
      if (isRememberEnabled && shouldRememberPassphrase) {
        window.localStorage.setItem(rememberPassphraseKey, hashedPassphrase);

        // set the expiration if the duration isn't 0 (meaning no expiration)
        if (rememberDurationInDays > 0) {
          window.localStorage.setItem(
            rememberExpirationKey,
            (new Date().getTime() + rememberDurationInDays * 24 * 60 * 60 * 1000).toString()
          );
        }
      }
    } else {
      alert(labelError);
    }
  });
});
