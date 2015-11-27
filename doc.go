/*
Package qp implements 9P2000 as well as some extensions. Regarding the name,
it's "9P", but lowercase. See what I did there?

9P is a file protocol originally designed for Plan9 and later Inferno (in
which it is called Styx). In Plan9, all file-related syscalls send 9P message
to the 9P server responsible for the file, without any exceptions. FUSE is
heavily inspired by this concept, although considerably larger and more
complicated in its implementation. Also, 9P is meant to also work as a network
based protocol, with the only transport requirement being delivery and order
guarantees.

9P, since it was designed for Plan9, use strings for most things where a UNIX
would use a numeric identifier, such as UIDs and errors. In order to simplify
compatibility with such numeric system, the 9P2000.u extension ("Unix")
provides some unix compatibility. Do note that error codes are platform
specific, and user IDs machine specific, making interaction with foreign
systems difficult. Strings, on the other hand, are portable, and can be
converted back and forth between local numeric representations and string
representation at the endpoints. The 9P2000.L extension ("Linux") tries even
harder at tying 9P to the platform, and is what is used by qemu/kvm virtfs.
9P2000.E (Erlang) adds restorable sessions, as well as shorthands for attach,
walk, open, read/write, clunk.

See the various message types for information about their usage. Message types
for extensions have "DotX" appended to their name, where X is the name of the
extension.

Full decoding and encoding of messages happen through the Protocol interface.
A Protocol implementation is available for each extension, with the default
implementation being NineP2000. This abstraction is in place due to overlap
between message types constants in the various extensions.

For more details about the specific protocols and extensions, see the protocol
definitions. */
package qp
