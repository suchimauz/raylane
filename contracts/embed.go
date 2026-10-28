package contracts

// Compiled capability-profile authority (T012). This directory embeds the ONE
// authored profile file; there is no duplicated copy, no operator profile
// path, no digest registry and no revalidation machinery. authhttp composes
// the node authority from ProfileBytes exactly once at startup.

import _ "embed"

//go:embed capability-profile.json
var profileJSON []byte

// ProfileBytes returns a COPY of the compiled capability-profile bytes. The
// caller may mutate the result freely; the compiled bytes are never exposed.
func ProfileBytes() []byte {
	out := make([]byte, len(profileJSON))
	copy(out, profileJSON)
	return out
}
