/**
 * Copyright 2021 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage.kage.test.utils

import kotlin.test.*

/**
 * Splits the [ByteArray] around the first instance of [byte], returning the bytes before and after
 * [byte]. If [byte] cannot be found in the [ByteArray], returns `Pair(this, null, false)`.
 */
fun ByteArray.split(byte: Byte): Triple<ByteArray, ByteArray?, Boolean> {
  val splitByte = firstOrNull { b -> b == byte } ?: return Triple(this, null, false)
  val splitIndex = indexOf(splitByte)
  return Triple(copyOfRange(0, splitIndex), copyOfRange(splitIndex + 1, size), true)
}

/** Shorthand for [ByteArray.split] that takes in a [Char] to simplify usages. */
fun ByteArray.split(char: Char) = split(char.code.toByte())

class BytesTest {
  @Test
  fun splitNewline() {
    val testString =
      """
      Line 1
      Line 2
      """
        .trimIndent()
    val (line, rest, found) = check(testString, '\n')
    assertTrue(found)
    assertEquals("Line 1", line.decodeToString())
    assertEquals("Line 2", rest?.decodeToString())
  }

  @Test
  fun splitNotFound() {
    val testString = "Line 1"
    val (line, rest, found) = check(testString, '|')
    assertFalse(found)
    assertEquals(testString, line.decodeToString())
    assertNull(rest)
  }

  private fun check(
    testString: String,
    split: Char,
  ) = testString.encodeToByteArray().split(split)
}
