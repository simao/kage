/**
 * Copyright 2021 The kage Authors. All rights reserved. Use of this source code is governed by
 * either an Apache 2.0 or MIT license at your discretion, that can be found in the LICENSE-APACHE
 * or LICENSE-MIT files respectively.
 */
package kage

import kage.format.AgeStanza

/*
 * From the age docs:
 * An Identity is passed to Decrypt to unwrap an opaque file key from a
 * recipient stanza. It can be for example a secret key like X25519Identity, a
 * plugin, or a custom implementation.
 *
 * Unwrap must return an error wrapping IncorrectIdentityError if none of the
 * recipient stanzas match the identity, any other error will be considered
 * fatal.
 *
 * https://github.com/FiloSottile/age/blob/ab3707c085f2c1fdfd767a2ed718423e3925f4c4/age.go#L59-L72
 */
public interface Identity {
  public fun unwrap(stanzas: List<AgeStanza>): ByteArray
}
