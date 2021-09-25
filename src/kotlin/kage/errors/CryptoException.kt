package kage.errors

public sealed class CryptoException
@JvmOverloads
constructor(
  message: String? = null,
  cause: Throwable? = null,
) : Exception(message, cause)

public class EncryptionException
@JvmOverloads
constructor(
  message: String? = null,
  cause: Throwable? = null,
) : CryptoException(message, cause)

public class DecryptionException
@JvmOverloads
constructor(
  message: String? = null,
  cause: Throwable? = null,
) : ParseException(message, cause)

public class IncorrectCipherTextException
@JvmOverloads
constructor(
  message: String? = null,
  cause: Throwable? = null,
) : ParseException(message, cause)
