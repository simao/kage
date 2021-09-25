package kage

import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kage.errors.EncryptionException
import kage.errors.IncorrectCipherTextException

public object Primitives {
  private const val ENCRYPTION_ALGO = "ChaCha20-Poly1305"
  private const val KEY_ALGO = "ChaCha20"
  private const val NONCE_LENGTH = 12 // 96 bits, 12 bytes
  private const val TAG_LENGTH = 16

  public fun aeadEncrypt(key: ByteArray, plainText: ByteArray): ByteArray {
    val cipher = Cipher.getInstance(ENCRYPTION_ALGO)
    // Initialize parameter spec with empty byte array
    val parameterSpec = IvParameterSpec(ByteArray(NONCE_LENGTH))
    // Create secretKey from byte array
    val secretKey = SecretKeySpec(key, KEY_ALGO)

    cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec)
    return cipher.doFinal(plainText)
      ?: throw EncryptionException("Failed to encrypt data, returned ByteArray was null")
  }

  public fun aeadDecrypt(key: ByteArray, size: Int, cipherText: ByteArray): ByteArray {
    val cipher = Cipher.getInstance(ENCRYPTION_ALGO)
    // Initialize parameter spec with empty byte array
    val parameterSpec = IvParameterSpec(ByteArray(NONCE_LENGTH))
    // Create secretKey from byte array
    val secretKey = SecretKeySpec(key, KEY_ALGO)

    if (cipherText.size != size + TAG_LENGTH)
      throw IncorrectCipherTextException("Encrypted value has unexpected length")

    cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec)
    return cipher.doFinal(cipherText)
      ?: throw EncryptionException("Failed to decrypt data, returned ByteArray was null")
  }
}
