/*
Package qp implements 9P2000 as well as some extensions. Regarding the name,
it's "9P", but lowercase. See what I did there?

9P is a file protocol originally designed for Plan9 and later Inferno (in
which it is called Styx). In Plan9, all file-related syscalls send 9P messages
to a 9P server responsible for the file of interest, without any exceptions.
FUSE and puffs are heavily inspired by this concept, although considerably
larger and more complicated in their implementation. 9P is also meant to work
over any transport that provides delivery and order guarantees (e.g. TCP),
whereas FUSE is only meant for local use.

The protocol implements file access functionality, as well as authentication
measures, by exposing a special authentication file that can be used to read
and write an authentication protocol to. 9P does not define this protocol.

Full decoding and encoding of messages happen through the Protocol interface.
A Protocol implementation is available for each extension, with the default
implementation being NineP2000. This abstraction is in place due to overlap
between message types constants in the various extensions.

For more details about the specific protocols and extensions, see the protocol
definitions. For message usage and information, See the various message type
definition. Message types for extensions have "DotX" appended to their name,
where X is the name of the extension. */
package qp
